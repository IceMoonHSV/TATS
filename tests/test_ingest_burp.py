"""End-to-end ingest tests against the Burp XML fixture.

These tests exercise the whole ingest pipeline: XML parsing, token /
event / exchange extraction, FOCI / BroCI detection, ESTSAUTH cookie
classification, and the SQLite write path. They do not need network
access (no enrichment) and run in well under a second.
"""
from __future__ import annotations

import sqlite3

import pytest

import tats as btt


# Argparse Namespace builder so we can call cmd_ingest without going
# through the CLI parser.
def _ns(**overrides):
    import argparse
    base = dict(
        input=None, output=None,
        enrich=False, enrich_cache_dir=None, no_enrich_cache=False,
        no_serve_hint=True, append=False, source_tag=None,
        no_progress=True, redact_claims=None,
        verbose=0, quiet=True,
    )
    base.update(overrides)
    base["func"] = btt.cmd_ingest
    return argparse.Namespace(**base)


@pytest.fixture
def ingested_db(burp_fixture_xml_copy, empty_db_path):
    """Run a full Burp-XML ingest into a tmp DB and return the path."""
    rc = btt.cmd_ingest(_ns(
        input=str(burp_fixture_xml_copy),
        output=str(empty_db_path),
    ))
    assert rc == 0
    assert empty_db_path.is_file()
    return empty_db_path


def _conn(path):
    c = sqlite3.connect(str(path))
    c.row_factory = sqlite3.Row
    return c


# ---- Schema and meta ------------------------------------------------------

def test_schema_version_is_current(ingested_db):
    with _conn(ingested_db) as c:
        sv = c.execute(
            "SELECT value FROM meta WHERE key='schema_version'").fetchone()[0]
    assert sv == btt.SCHEMA_VERSION


def test_meta_carries_last_modified(ingested_db):
    with _conn(ingested_db) as c:
        lm = c.execute(
            "SELECT value FROM meta WHERE key='last_modified'").fetchone()[0]
    assert lm and lm.endswith("Z")  # ISO 8601 UTC


# ---- Counts (regression: fixture currently produces 11/19/3) -------------

def test_fixture_token_event_exchange_counts(ingested_db):
    with _conn(ingested_db) as c:
        counts = {
            "tokens":   c.execute("SELECT COUNT(*) FROM tokens").fetchone()[0],
            "events":   c.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "exchgs":   c.execute("SELECT COUNT(*) FROM exchanges").fetchone()[0],
        }
    assert counts == {"tokens": 11, "events": 19, "exchgs": 3}


def test_token_types_match_expected_distribution(ingested_db):
    with _conn(ingested_db) as c:
        rows = dict(
            (r["type"], r["c"])
            for r in c.execute(
                "SELECT type, COUNT(*) AS c FROM tokens GROUP BY type"))
    # 5 access (3 from idp.example, 1 each from MS Teams/AzCLI/ADIbizaUX),
    # 5 refresh, 1 id.
    assert rows.get("access") == 5
    assert rows.get("refresh") == 5
    assert rows.get("id") == 1


# ---- Microsoft-specific detection ----------------------------------------

def test_foci_exchange_is_flagged(ingested_db):
    with _conn(ingested_db) as c:
        n = c.execute(
            "SELECT COUNT(*) FROM exchanges WHERE foci_family IS NOT NULL"
        ).fetchone()[0]
    assert n >= 1


def test_broci_exchange_carries_broker_and_nested(ingested_db):
    with _conn(ingested_db) as c:
        row = c.execute(
            "SELECT broci_broker_id, broci_nested_id, broci_evidence "
            "FROM exchanges WHERE broci_broker_id IS NOT NULL"
        ).fetchone()
    assert row is not None
    assert row["broci_broker_id"]
    assert row["broci_nested_id"]
    assert "brk_client_id" in (row["broci_evidence"] or "")


def test_source_tag_default_is_burp_filename(ingested_db, burp_fixture_xml_copy):
    with _conn(ingested_db) as c:
        tag = c.execute(
            "SELECT DISTINCT source_tag FROM tokens").fetchone()[0]
    assert tag == f"burp:{burp_fixture_xml_copy.name}"


# ---- Append mode ---------------------------------------------------------

def test_append_doubles_events_and_keeps_token_count_fixed(ingested_db,
                                                           burp_fixture_xml_copy):
    rc = btt.cmd_ingest(_ns(
        input=str(burp_fixture_xml_copy),
        output=str(ingested_db),
        append=True,
        source_tag="second-pass",
    ))
    assert rc == 0
    with _conn(ingested_db) as c:
        n_tokens = c.execute("SELECT COUNT(*) FROM tokens").fetchone()[0]
        n_events = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        tags = set(
            r["source_tag"] for r in
            c.execute("SELECT source_tag FROM tokens"))
    assert n_tokens == 11
    assert n_events == 38   # 19 + 19
    # source_tag accumulated as comma-separated list on every UPSERT'd row
    joined = next(iter(tags))
    assert "second-pass" in joined
    assert joined.startswith("burp:")


def test_append_seq_offsets_past_existing_max(ingested_db,
                                              burp_fixture_xml_copy):
    with _conn(ingested_db) as c:
        before_max = c.execute("SELECT MAX(seq) FROM events").fetchone()[0]
    btt.cmd_ingest(_ns(
        input=str(burp_fixture_xml_copy),
        output=str(ingested_db),
        append=True,
    ))
    with _conn(ingested_db) as c:
        new_min = c.execute(
            "SELECT MIN(seq) FROM events WHERE id > ("
            "SELECT MAX(id)-1 FROM events) - 18"
        ).fetchone()[0]
        # The new batch's smallest seq should sit past the old max.
        max_now = c.execute("SELECT MAX(seq) FROM events").fetchone()[0]
    assert max_now > before_max
    assert new_min is not None
