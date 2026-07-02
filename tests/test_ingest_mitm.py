"""End-to-end mitmproxy flow ingest, including WebSocket frame extraction.

Skipped automatically when ``mitmproxy`` is not installed (the package is
optional). When it *is* installed, these run against the bundled
``examples/fixture.mitm`` fixture which contains an HTTP token-issuance
flow plus a WebSocket session that carries a token in JSON.
"""
from __future__ import annotations

import argparse
import sqlite3

import pytest

import tats as btt


def _ns(**overrides):
    base = dict(
        input=None, output=None,
        enrich=False, enrich_cache_dir=None, no_enrich_cache=False,
        no_serve_hint=True, append=False, source_tag=None,
        no_progress=True, redact_claims=None,
        verbose=0, quiet=True,
    )
    base.update(overrides)
    base["func"] = btt.cmd_mitm
    return argparse.Namespace(**base)


def _conn(path):
    c = sqlite3.connect(str(path))
    c.row_factory = sqlite3.Row
    return c


@pytest.fixture
def mitm_db(mitm_fixture, empty_db_path):
    rc = btt.cmd_mitm(_ns(input=str(mitm_fixture), output=str(empty_db_path)))
    assert rc == 0
    assert empty_db_path.is_file()
    return empty_db_path


def test_websocket_frame_event_recorded(mitm_db):
    with _conn(mitm_db) as c:
        rows = c.execute(
            "SELECT fp, host, role, source, ws_session_id "
            "FROM events WHERE role LIKE 'ws-frame-%'"
        ).fetchall()
    assert rows, "expected at least one WebSocket frame event"
    ev = rows[0]
    assert ev["role"] in ("ws-frame-sent", "ws-frame-received")
    assert ev["source"].startswith("ws[")
    assert ev["ws_session_id"]   # frames are grouped by connection


def test_token_extracted_from_websocket_frame(mitm_db):
    with _conn(mitm_db) as c:
        # The WS frame carries a JWT under access_token; that token's only
        # observation should be a ws-frame-* event.
        rows = c.execute("""
            SELECT t.fp, t.type, t.sub_type, e.role
            FROM tokens t JOIN events e ON e.fp = t.fp
            WHERE e.role LIKE 'ws-frame-%'
        """).fetchall()
    fps = {r["fp"] for r in rows}
    assert fps, "expected at least one token sourced from a WS frame"
    # And the token type should be access (the frame's body had access_token=...)
    types = {r["type"] for r in rows}
    assert types == {"access"}


def test_default_source_tag_is_mitm_filename(mitm_db, mitm_fixture):
    with _conn(mitm_db) as c:
        tags = {r["source_tag"]
                for r in c.execute("SELECT DISTINCT source_tag FROM tokens")}
    assert any(t == f"mitm:{mitm_fixture.name}" for t in tags)


def test_http_and_ws_tokens_coexist(mitm_db):
    with _conn(mitm_db) as c:
        n = c.execute("SELECT COUNT(*) FROM tokens").fetchone()[0]
    # 3 from the HTTP token-endpoint response + 1 from the WS frame.
    assert n == 4
