"""Schema-migration regression tests.

The migration ladder is forward-only and additive: v2 -> v3 added the
nullable ``tokens.raw`` column; v3 -> v4 added the nullable
``tokens.security_features`` column and backfills it from
``jwt_payload_json``. These tests build a DB that *looks* like the older
version (downgrade meta + drop the new column), then run an append
ingest and verify:

  1. ``meta.schema_version`` ends at the current SCHEMA_VERSION.
  2. The new columns are present.
  3. Existing rows are not lost or corrupted.
  4. The backfill of ``security_features`` from JWT payloads actually fired
     (when ``jwt_payload_json`` carries CAE / PoP / step-up markers).
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import time

import pytest

import tats as btt


def _ns(**overrides):
    base = dict(
        input=None, output=None,
        enrich=False, enrich_cache_dir=None, no_enrich_cache=False,
        no_serve_hint=True, append=False, source_tag=None,
        no_progress=True, redact_claims=None, store_tokens=False,
        verbose=0, quiet=True,
    )
    base.update(overrides)
    base["func"] = btt.cmd_ingest
    return argparse.Namespace(**base)


def _cols(conn: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def _downgrade_to_v2(db_path):
    """Strip the v3 + v4 columns and reset the meta version to '2'."""
    with sqlite3.connect(db_path) as c:
        # SQLite 3.35+ supports DROP COLUMN.
        cols = _cols(c, "tokens")
        if "security_features" in cols:
            c.execute("ALTER TABLE tokens DROP COLUMN security_features")
        if "raw" in cols:
            c.execute("ALTER TABLE tokens DROP COLUMN raw")
        c.execute("UPDATE meta SET value='2' WHERE key='schema_version'")
        c.commit()


def _downgrade_to_v3(db_path):
    """Strip just the v4 column and reset meta to '3'."""
    with sqlite3.connect(db_path) as c:
        cols = _cols(c, "tokens")
        if "security_features" in cols:
            c.execute("ALTER TABLE tokens DROP COLUMN security_features")
        c.execute("UPDATE meta SET value='3' WHERE key='schema_version'")
        c.commit()


def test_v2_db_upgrades_through_to_current(burp_fixture_xml_copy,
                                           empty_db_path):
    # Build a fresh DB, count its rows, then forcibly downgrade to v2.
    btt.cmd_ingest(_ns(input=str(burp_fixture_xml_copy),
                       output=str(empty_db_path)))
    with sqlite3.connect(empty_db_path) as c:
        before_tokens = c.execute("SELECT COUNT(*) FROM tokens").fetchone()[0]
        before_events = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    _downgrade_to_v2(empty_db_path)

    # Reopening for an append should run the full migration ladder.
    btt.cmd_ingest(_ns(input=str(burp_fixture_xml_copy),
                       output=str(empty_db_path),
                       append=True, source_tag="post-migrate"))

    with sqlite3.connect(empty_db_path) as c:
        sv = c.execute(
            "SELECT value FROM meta WHERE key='schema_version'").fetchone()[0]
        cols = _cols(c, "tokens")
        post_tokens = c.execute("SELECT COUNT(*) FROM tokens").fetchone()[0]
        post_events = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    assert sv == btt.SCHEMA_VERSION
    assert "raw" in cols, "v2 -> v3 step did not add tokens.raw"
    assert "security_features" in cols, \
        "v3 -> v4 step did not add tokens.security_features"
    # Token set should be unchanged (UPSERT on the same fps); events double.
    assert post_tokens == before_tokens
    assert post_events == before_events * 2


def test_v3_db_upgrades_to_current(burp_fixture_xml_copy, empty_db_path):
    btt.cmd_ingest(_ns(input=str(burp_fixture_xml_copy),
                       output=str(empty_db_path)))
    _downgrade_to_v3(empty_db_path)

    btt.cmd_ingest(_ns(input=str(burp_fixture_xml_copy),
                       output=str(empty_db_path),
                       append=True, source_tag="post-migrate"))

    with sqlite3.connect(empty_db_path) as c:
        sv = c.execute(
            "SELECT value FROM meta WHERE key='schema_version'").fetchone()[0]
        cols = _cols(c, "tokens")
    assert sv == btt.SCHEMA_VERSION
    assert "security_features" in cols


def test_v3_to_v4_backfills_security_features(tmp_path,
                                              burp_fixture_xml_copy):
    """When v3 -> v4 runs, rows whose ``jwt_payload_json`` already has
    CAE / PoP / acr / amr markers must be back-filled with a populated
    ``security_features`` blob — researchers shouldn't have to re-ingest
    every old DB to get the new card to light up."""
    db = tmp_path / "v3.db"
    btt.cmd_ingest(_ns(input=str(burp_fixture_xml_copy), output=str(db)))

    # Inject a payload with CAE+PoP into one of the existing tokens so we
    # have something to back-fill against.
    fake_payload = {
        "iss": "https://sts.windows.net/x/",
        "aud": "https://graph.microsoft.com",
        "tid": "11111111-1111-1111-1111-111111111111",
        "xms_cc": ["CP1"],
        "cnf": {"kid": "shared-key-1"},
        "acr": "1",
        "amr": ["pwd", "mfa"],
        "exp": int(time.time()) + 3600,
    }
    with sqlite3.connect(db) as c:
        fp = c.execute(
            "SELECT fp FROM tokens WHERE jwt_payload_json IS NOT NULL LIMIT 1"
        ).fetchone()[0]
        c.execute("UPDATE tokens SET jwt_payload_json=? WHERE fp=?",
                  (json.dumps(fake_payload), fp))
        c.commit()

    _downgrade_to_v3(db)

    btt.cmd_ingest(_ns(input=str(burp_fixture_xml_copy),
                       output=str(db),
                       append=True, source_tag="post-migrate"))

    with sqlite3.connect(db) as c:
        c.row_factory = sqlite3.Row
        row = c.execute(
            "SELECT security_features FROM tokens WHERE fp=?", (fp,)
        ).fetchone()
    assert row is not None
    assert row["security_features"], \
        "v3 -> v4 backfill did not populate security_features for an " \
        "existing JWT with CAE / PoP / acr markers"
    feats = json.loads(row["security_features"])
    assert feats.get("cae") is True
    assert feats.get("pop") is True
    assert feats.get("pop_kid") == "shared-key-1"


def test_migration_refuses_unknown_future_version(burp_fixture_xml_copy,
                                                  empty_db_path):
    """A DB stamped with a schema_version newer than this build knows
    about should bail out cleanly rather than silently upserting into a
    shape it doesn't understand."""
    btt.cmd_ingest(_ns(input=str(burp_fixture_xml_copy),
                       output=str(empty_db_path)))
    with sqlite3.connect(empty_db_path) as c:
        c.execute("UPDATE meta SET value='999' WHERE key='schema_version'")
        c.commit()
    with pytest.raises(SystemExit):
        btt.cmd_ingest(_ns(input=str(burp_fixture_xml_copy),
                           output=str(empty_db_path),
                           append=True))
