#!/usr/bin/env python3
# Token Analysis and Tracking System (TATS) — track OAuth2 / JWT tokens
# across captured traffic.
# Copyright (C) 2026  TATS contributors.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
TATS — Token Analysis and Tracking System.

Track OAuth2 / JWT tokens across captured traffic from multiple sources
(Burp XML exports, mitmproxy flow files, live Chrome via DevTools
Protocol) with extra support for Microsoft Entra ID flows (FOCI,
BroCI / NAA).

Subcommands:

    tats ingest <burp_items.xml> -o tokens.db [--enrich] [--store-tokens]

        Parse a Burp "Save items" XML export and write the extracted
        tokens, events, and exchanges to a SQLite database.

    tats mitm <flow.mitm> -o tokens.db [--enrich] [--store-tokens]

        Parse a mitmproxy flow file (HTTP + WebSocket frames).

    tats cdp -o tokens.db [--enrich] [--launch-chrome] [--store-tokens]

        Live-attach to a running Chrome / Edge instance via the DevTools
        Protocol and stream HTTP and WebSocket traffic in real time.
        Tracks every existing tab AND every tab opened during the run.

    tats serve tokens.db [--host 127.0.0.1] [--port 8765]

        Serve an interactive web UI for the database on localhost. The UI
        provides a filterable / sortable token inventory, expandable JWT
        details, replay-ready exports (raw / Bearer / curl / JSON /
        roadtools token cache), command previews, and Mermaid graph +
        sequence diagrams that can be highlighted or isolated to a single
        token's flow.

PRIVACY
    The database stores SHA-256 fingerprints (first 12 hex chars) and a
    12-char prefix of every observed token by default; full token strings
    are only written when ``--store-tokens`` is passed. JWT *claims*
    (header + payload) are stored verbatim and exposed via the web UI —
    treat the generated database as sensitive whenever JWTs were observed.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time as _time
import urllib.error
import urllib.parse as _urlparse
import urllib.request
import webbrowser
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterable, Optional

__version__ = "2.0.0"
__title__ = "Token Analysis and Tracking System"
__acronym__ = "TATS"


# ---------------------------------------------------------------------------
# Banner art
# ---------------------------------------------------------------------------
#
# A flail. Printed once at the top of the ``--version`` output. Kept
# here as a module-level constant so it can be reused (banner
# subcommand, future "about" panel, etc.) without duplicating the art.

FLAIL_ASCII = r"""
                                                                                                                                                        
 **********     **     **********  ********
/////**///     ****   /////**///  **////// 
    /**       **//**      /**    /**       
    /**      **  //**     /**    /*********
    /**     **********    /**    ////////**
    /**    /**//////**    /**           /**
    /**    /**     /**    /**     ******** 
    //     //      //     //     ////////                                                                                                                                                    
                                                                                                                                                        
                                                                                                                                                   
"""


def banner_text() -> str:
    """Return the flail + project name + version, suitable for stderr or
    the ``--version`` action."""
    return (
        FLAIL_ASCII
        + f"   {__title__} ({__acronym__}) {__version__}\n"
        + "   track OAuth2 / JWT tokens across captured traffic\n"
    )


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
#
# The tool writes two distinct things to stderr:
#   1. *User-facing errors* — multi-line messages explaining what went wrong
#      and how to fix it. Those are formatted as plain text via print() so
#      they're not affected by --quiet and don't carry log decorations the
#      user has to ignore.
#   2. *Log lines* — progress, warnings about non-fatal failures (cache miss,
#      enrichment fetch failed, CDP handler raised, …). Those go through the
#      logging module so --verbose / --quiet can dial the volume.
#
# All loggers under the ``btt`` namespace inherit the configuration set up
# by ``setup_logging()``.

log = logging.getLogger("tats")
_log_enrich = logging.getLogger("tats.enrich")
_log_ingest = logging.getLogger("tats.ingest")
_log_serve = logging.getLogger("tats.serve")
_log_cdp = logging.getLogger("tats.cdp")


class _Progress:
    """Tiny stdlib-only progress indicator.

    Renders ``label N/M (P%) | rate`` (or ``label N | rate`` when the
    total is unknown) on a single carriage-return line. Throttled to at
    most one repaint every 100 ms. Auto-disables on non-TTY streams or
    when explicitly suppressed; in those cases all methods are no-ops so
    callers don't need to special-case anything.
    """

    def __init__(self, total: Optional[int] = None, *, label: str = "",
                 stream=sys.stderr, disable: bool = False) -> None:
        self.total = total
        self.label = label
        self.stream = stream
        self.n = 0
        self._last_paint = 0.0
        self._start = _time.time()
        # Honour --no-progress / --quiet, and skip on non-TTY (CI logs,
        # piped output) where carriage returns just create noise.
        self.disable = disable or not getattr(stream, "isatty", lambda: False)()

    def update(self, n: int = 1) -> None:
        if self.disable:
            self.n += n
            return
        self.n += n
        now = _time.time()
        # Throttle repaints, but always paint the final tick so the user
        # sees the completion line.
        if now - self._last_paint < 0.1 and self.n != self.total:
            return
        self._last_paint = now
        elapsed = now - self._start
        rate = (self.n / elapsed) if elapsed > 0 else 0.0
        if self.total:
            pct = (self.n / self.total) * 100 if self.total else 0
            msg = f"{self.label} {self.n}/{self.total} ({pct:5.1f}%) | {rate:6.0f}/s"
        else:
            msg = f"{self.label} {self.n} | {rate:6.0f}/s"
        # Clear the rest of the line in case a previous paint was longer.
        self.stream.write("\r" + msg + " " * 4)
        self.stream.flush()

    def close(self) -> None:
        if self.disable:
            return
        self.stream.write("\n")
        self.stream.flush()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def setup_logging(verbose: int = 0, quiet: bool = False) -> None:
    """Configure the ``btt`` logger tree.

    ``verbose`` is the count of ``-v`` flags seen on the command line.
    ``quiet`` overrides ``verbose`` and clamps the level to WARNING.
    """
    if quiet:
        level = logging.WARNING
    elif verbose >= 2:
        level = logging.DEBUG
    elif verbose == 1:
        level = logging.INFO
    else:
        level = logging.INFO
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
        datefmt="%H:%M:%S",
    ))
    root = logging.getLogger("tats")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    # Don't bubble to the global root logger — keeps third-party libraries
    # from echoing our messages a second time.
    root.propagate = False

# ---------------------------------------------------------------------------
# Patterns and hint tables
# ---------------------------------------------------------------------------

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]*")
GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
BROCI_REDIRECT_RE = re.compile(
    r"^brk-(?P<broker>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})://", re.IGNORECASE,
)

BODY_KEY_TO_TYPE = {
    "access_token": "access",
    "refresh_token": "refresh",
    "id_token": "id",
}

COOKIE_HINTS = [
    ("refresh", "refresh"),
    ("id_token", "id"),
    ("idtoken", "id"),
    ("access", "access"),
    ("bearer", "access"),
    ("jwt", "access"),
    ("session", "access"),
    ("auth", "access"),
]

# Microsoft Entra ID session cookies. These behave like refresh tokens —
# long-lived, never sent in ``Authorization: Bearer``, but used by the
# browser on silent-auth requests to login.microsoftonline.com to mint new
# access tokens. The "auth" substring in their names would otherwise have
# COOKIE_HINTS misclassify them as access tokens, so they get an exact-name
# allow-list that takes precedence over the substring rules.
MS_SESSION_COOKIE_NAMES = {
    "estsauth", "estsauthpersistent", "estsauthlight",
    "signinstatecookie",
}

TOKEN_ENDPOINT_HINTS = (
    "/token", "/oauth/token", "/oauth2/token", "/oauth2/v2.0/token",
    "/connect/token", "/auth/refresh", "/refresh", "/signin",
    "/login/token", "/common/oauth2/",
)

INVENTORY_JWT_CLAIMS = (
    "iss", "aud", "appid", "azp", "client_id", "tid", "oid", "sub",
    "scp", "scope", "roles", "amr", "acrs", "idtyp", "tenant_region_scope",
    "brk_brokerid", "brk_clientid", "foci", "exp",
)

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def sha_fp(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:12]


def b64url_json(segment: str) -> Optional[dict]:
    try:
        padded = segment + "=" * (-len(segment) % 4)
        return json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except Exception:
        return None


def parse_jwt(token: str) -> Optional[dict]:
    parts = token.split(".")
    if len(parts) < 2:
        return None
    header = b64url_json(parts[0])
    payload = b64url_json(parts[1])
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return {"header": header, "payload": payload}


def is_tokenish(value: str) -> bool:
    if not value or len(value) < 16:
        return False
    if JWT_RE.fullmatch(value):
        return True
    return bool(re.fullmatch(r"[A-Za-z0-9_\-\.~+/=]{20,}", value))


def cookie_type_hint(name: str) -> Optional[str]:
    low = name.lower()
    if low in MS_SESSION_COOKIE_NAMES:
        return "refresh"
    for needle, tt in COOKIE_HINTS:
        if needle in low:
            return tt
    return None


def is_token_endpoint(path: str) -> bool:
    p = path.lower().split("?", 1)[0]
    return any(h in p for h in TOKEN_ENDPOINT_HINTS)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class Event:
    seq: int
    time: str
    host: str
    method: str
    path: str
    status: Optional[int]
    direction: str
    role: str
    source: str
    fp: str
    token_type: str
    grant_type: Optional[str] = None
    client_id: Optional[str] = None
    broci_broker_id: Optional[str] = None
    ws_session_id: Optional[str] = None
    source_tag: Optional[str] = None


@dataclass
class Token:
    fp: str
    sample: str
    token_type: str
    sub_type: str
    first_seen_time: str
    last_seen_time: str
    issuer_host: Optional[str] = None
    jwt_header: Optional[dict] = None
    jwt_payload: Optional[dict] = None
    foci_family: Optional[str] = None
    events: list = field(default_factory=list)
    app_info: Optional[dict] = None
    resource_info: Optional[dict] = None
    # Full token string. Always populated in-memory. Only persisted to
    # the DB when the user passed --store-tokens.
    raw: Optional[str] = None


@dataclass
class Exchange:
    seq: int
    time: str
    host: str
    path: str
    grant_type: Optional[str]
    input_fps: list[str]
    output_fps: list[str]
    client_id: Optional[str] = None
    foci_family: Optional[str] = None
    broci: Optional[dict] = None
    source_tag: Optional[str] = None


# ---------------------------------------------------------------------------
# Burp XML parsing
# ---------------------------------------------------------------------------


def _decoded_text(elem: Optional[ET.Element]) -> str:
    if elem is None or elem.text is None:
        return ""
    if (elem.attrib.get("base64") or "false").lower() == "true":
        try:
            return base64.b64decode(elem.text).decode("utf-8", errors="replace")
        except Exception:
            return ""
    return elem.text


def split_http(blob: str) -> tuple[list[str], str]:
    if not blob:
        return [], ""
    sep = "\r\n\r\n" if "\r\n\r\n" in blob else "\n\n"
    parts = blob.split(sep, 1)
    head = parts[0].splitlines()
    body = parts[1] if len(parts) > 1 else ""
    return head, body


def header_value(headers: list[str], name: str) -> Optional[str]:
    target = name.lower()
    for line in headers[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        if k.strip().lower() == target:
            return v.strip()
    return None


def all_header_values(headers: list[str], name: str) -> list[str]:
    target = name.lower()
    out = []
    for line in headers[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        if k.strip().lower() == target:
            out.append(v.strip())
    return out


def _walk_json_for_tokens(node, path: str = "") -> Iterable[tuple[str, str, str]]:
    if isinstance(node, dict):
        for k, v in node.items():
            sub = f"{path}.{k}" if path else k
            if k in BODY_KEY_TO_TYPE and isinstance(v, str) and is_tokenish(v):
                yield v, BODY_KEY_TO_TYPE[k], f"body_json[{k}]"
            else:
                yield from _walk_json_for_tokens(v, sub)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            yield from _walk_json_for_tokens(item, f"{path}[{i}]")
    elif isinstance(node, str) and JWT_RE.fullmatch(node):
        yield node, "unknown", f"body_json_jwt[{path or 'root'}]"


def _extract_from_body(body: str) -> Iterable[tuple[str, str, str]]:
    if not body:
        return
    stripped = body.lstrip()
    if not stripped:
        return
    if stripped[:1] in "{[":
        try:
            yield from _walk_json_for_tokens(json.loads(stripped))
            return
        except Exception:
            pass
    if "=" in stripped and "\n" not in stripped[:200]:
        try:
            parsed = _urlparse.parse_qs(stripped, keep_blank_values=True)
        except Exception:
            parsed = {}
        for k, values in parsed.items():
            for v in values:
                if k in BODY_KEY_TO_TYPE and is_tokenish(v):
                    yield v, BODY_KEY_TO_TYPE[k], "body_form"
    for m in JWT_RE.finditer(stripped):
        yield m.group(0), "unknown", "body_raw_jwt"


def extract_request_tokens(headers: list[str], body: str,
                           full_url_path: str) -> Iterable[tuple[str, str, str]]:
    qs_idx = full_url_path.find("?")
    if qs_idx != -1:
        try:
            for k, values in _urlparse.parse_qs(
                full_url_path[qs_idx + 1:], keep_blank_values=True,
            ).items():
                for v in values:
                    if k in BODY_KEY_TO_TYPE and is_tokenish(v):
                        yield v, BODY_KEY_TO_TYPE[k], f"query[{k}]"
        except Exception:
            pass

    auth = header_value(headers, "authorization")
    if auth:
        m = re.match(r"(?i)bearer\s+(\S+)", auth)
        if m and is_tokenish(m.group(1)):
            yield m.group(1), "access", "authorization_bearer"

    cookie = header_value(headers, "cookie")
    if cookie:
        for part in cookie.split(";"):
            part = part.strip()
            if "=" not in part:
                continue
            name, value = part.split("=", 1)
            if is_tokenish(value):
                tt = cookie_type_hint(name) or "unknown"
                yield value, tt, f"cookie[{name.strip()}]"

    yield from _extract_from_body(body)


def extract_response_tokens(headers: list[str], body: str
                            ) -> Iterable[tuple[str, str, str]]:
    for sc in all_header_values(headers, "set-cookie"):
        name_eq = sc.split(";", 1)[0]
        if "=" not in name_eq:
            continue
        name, value = name_eq.split("=", 1)
        if is_tokenish(value):
            tt = cookie_type_hint(name) or "unknown"
            yield value, tt, f"set-cookie[{name.strip()}]"
    yield from _extract_from_body(body)


def parse_body_params(body: str) -> dict[str, str]:
    if not body:
        return {}
    stripped = body.lstrip()
    if not stripped:
        return {}
    if stripped[:1] == "{":
        try:
            parsed = json.loads(stripped)
        except Exception:
            return {}
        if not isinstance(parsed, dict):
            return {}
        out: dict[str, str] = {}
        for k, v in parsed.items():
            if isinstance(v, (str, int, float, bool)):
                out[k] = str(v)
            elif isinstance(v, list) and v and isinstance(v[0], (str, int, float, bool)):
                out[k] = str(v[0])
        return out
    if "=" in stripped and "\n" not in stripped[:200]:
        try:
            parsed = _urlparse.parse_qs(stripped, keep_blank_values=True)
        except Exception:
            return {}
        return {k: (vs[0] if vs else "") for k, vs in parsed.items()}
    return {}


def parse_response_json(body: str) -> Optional[dict]:
    if not body:
        return None
    stripped = body.lstrip()
    if not stripped or stripped[:1] != "{":
        return None
    try:
        parsed = json.loads(stripped)
    except Exception:
        return None
    return parsed if isinstance(parsed, dict) else None


def detect_broci(req_params: dict[str, str]) -> Optional[dict]:
    if not req_params:
        return None
    brk_client_id = req_params.get("brk_client_id")
    brk_redirect_uri = req_params.get("brk_redirect_uri")
    nested_client_id = req_params.get("client_id")
    redirect_uri = req_params.get("redirect_uri", "")

    broker_id = None
    evidence: list[str] = []
    if brk_client_id:
        broker_id = brk_client_id
        evidence.append("brk_client_id")
    if brk_redirect_uri:
        evidence.append("brk_redirect_uri")
    m = BROCI_REDIRECT_RE.match(redirect_uri)
    if m:
        broker_id = broker_id or m.group("broker")
        evidence.append("brk-<guid>://redirect_uri")

    if not evidence:
        return None
    return {
        "broker_client_id": broker_id,
        "broker_redirect_uri": brk_redirect_uri,
        "nested_client_id": nested_client_id,
        "nested_redirect_uri": redirect_uri or None,
        "evidence": evidence,
    }


def detect_foci(resp: Optional[dict]) -> Optional[str]:
    if not isinstance(resp, dict):
        return None
    v = resp.get("foci")
    if isinstance(v, (str, int)) and str(v).strip():
        return str(v)
    return None


# ---------------------------------------------------------------------------
# Tracker
# ---------------------------------------------------------------------------


class Tracker:
    def __init__(self, source_tag: Optional[str] = None) -> None:
        self.tokens: dict[str, Token] = {}
        self.events: list[Event] = []
        self.exchanges: list[Exchange] = []
        self.hosts: set[str] = set()
        # default tag stamped onto rows when callers don't pass one explicitly
        self.source_tag: Optional[str] = source_tag

    # -- token upsert -----------------------------------------------------

    def _upsert(self, raw: str, token_type: str, time: str) -> Token:
        fp = sha_fp(raw)
        tok = self.tokens.get(fp)
        if tok is None:
            jwt = parse_jwt(raw)
            sample = raw[:12] + ("…" if len(raw) > 12 else "")
            tok = Token(
                fp=fp, sample=sample, token_type=token_type,
                sub_type="jwt" if jwt else "opaque",
                jwt_header=(jwt or {}).get("header") if jwt else None,
                jwt_payload=(jwt or {}).get("payload") if jwt else None,
                first_seen_time=time, last_seen_time=time,
                raw=raw,
            )
            self.tokens[fp] = tok
        else:
            if tok.token_type == "unknown" and token_type != "unknown":
                tok.token_type = token_type
            if time:
                tok.last_seen_time = time
            if tok.raw is None:
                tok.raw = raw
        return tok

    # -- Burp XML adapter -------------------------------------------------

    def ingest_item(self, seq: int, item: ET.Element,
                    source_tag: Optional[str] = None) -> None:
        host = (item.findtext("host") or "").strip()
        port = (item.findtext("port") or "").strip()
        path = (item.findtext("path") or "").strip() or "/"
        method = (item.findtext("method") or "").strip() or "GET"
        time = (item.findtext("time") or "").strip()
        status_text = (item.findtext("status") or "").strip()
        status = int(status_text) if status_text.isdigit() else None

        host_label = host if not port or port in ("80", "443") else f"{host}:{port}"

        req_blob = _decoded_text(item.find("request"))
        resp_blob = _decoded_text(item.find("response"))
        req_headers, req_body = split_http(req_blob)
        resp_headers, resp_body = split_http(resp_blob)

        self._ingest_http_message(
            seq=seq, time=time, host_label=host_label, path=path,
            method=method, status=status,
            req_headers=req_headers, req_body=req_body,
            resp_headers=resp_headers, resp_body=resp_body,
            source_tag=source_tag,
        )

    # -- generic HTTP request/response adapter ---------------------------

    def _ingest_http_message(
        self, *, seq: int, time: str, host_label: str, path: str,
        method: str, status: Optional[int],
        req_headers: list[str], req_body: str,
        resp_headers: list[str], resp_body: str,
        source_tag: Optional[str] = None,
    ) -> None:
        tag = source_tag or self.source_tag
        self.hosts.add(host_label)

        req_params = parse_body_params(req_body)
        resp_json = parse_response_json(resp_body)
        grant = req_params.get("grant_type")
        form_client_id = req_params.get("client_id")
        broci = detect_broci(req_params) if is_token_endpoint(path) else None
        foci_family = detect_foci(resp_json) if is_token_endpoint(path) else None

        request_inputs: list[tuple[str, str, str]] = []
        for raw, tt, source in extract_request_tokens(req_headers, req_body, path):
            request_inputs.append((raw, tt, source))
            tok = self._upsert(raw, tt, time)
            role = "used"
            if source.startswith("body_form") or source.startswith("body_json"):
                role = "exchanged-in" if is_token_endpoint(path) else "presented"
            ev = Event(
                seq=seq, time=time, host=host_label, method=method, path=path,
                status=status, direction="request", role=role, source=source,
                fp=tok.fp, token_type=tok.token_type, grant_type=grant,
                client_id=form_client_id,
                broci_broker_id=(broci or {}).get("broker_client_id"),
                source_tag=tag,
            )
            tok.events.append(ev)
            self.events.append(ev)

        response_outputs: list[tuple[str, str, str]] = []
        for raw, tt, source in extract_response_tokens(resp_headers, resp_body):
            response_outputs.append((raw, tt, source))
            tok = self._upsert(raw, tt, time)
            role = "issued" if is_token_endpoint(path) else "returned"
            if role == "issued" and tok.issuer_host is None:
                tok.issuer_host = host_label
            if foci_family and tok.token_type == "refresh" and not tok.foci_family:
                tok.foci_family = foci_family
            ev = Event(
                seq=seq, time=time, host=host_label, method=method, path=path,
                status=status, direction="response", role=role, source=source,
                fp=tok.fp, token_type=tok.token_type, grant_type=grant,
                client_id=form_client_id,
                broci_broker_id=(broci or {}).get("broker_client_id"),
                source_tag=tag,
            )
            tok.events.append(ev)
            self.events.append(ev)

        if request_inputs and response_outputs and is_token_endpoint(path):
            in_fps = sorted({sha_fp(r) for r, _, _ in request_inputs})
            out_fps = sorted({sha_fp(r) for r, _, _ in response_outputs})
            self.exchanges.append(Exchange(
                seq=seq, time=time, host=host_label, path=path,
                grant_type=grant, input_fps=in_fps, output_fps=out_fps,
                client_id=form_client_id, foci_family=foci_family, broci=broci,
                source_tag=tag,
            ))

    # -- WebSocket frame adapter -----------------------------------------

    def ingest_ws_frame(
        self, *, seq: int, time: str, host_label: str, path: str,
        direction: str, payload: str,
        ws_session_id: Optional[str] = None,
        source_tag: Optional[str] = None,
    ) -> None:
        """Scan one WebSocket frame for OAuth/JWT tokens.

        ``direction`` is ``"sent"`` (client -> server) or ``"received"``
        (server -> client). Frame payload should be UTF-8 text; binary
        frames whose bytes don't decode to text are ignored. Tokens found
        in the payload generate events with role ``ws-frame-sent`` or
        ``ws-frame-received`` so the dashboard's timeline can pick them
        up alongside HTTP events.
        """
        if direction not in ("sent", "received"):
            raise ValueError("direction must be 'sent' or 'received'")
        if not payload:
            return
        tag = source_tag or self.source_tag
        self.hosts.add(host_label)
        role = "ws-frame-sent" if direction == "sent" else "ws-frame-received"
        # Reuse the same JSON / form / raw-JWT walker the HTTP body path uses.
        for raw, tt, source in _extract_from_body(payload):
            tok = self._upsert(raw, tt, time)
            ev = Event(
                seq=seq, time=time, host=host_label, method="WS",
                path=path, status=None, direction=direction, role=role,
                source=f"ws[{source}]",
                fp=tok.fp, token_type=tok.token_type,
                ws_session_id=ws_session_id, source_tag=tag,
            )
            tok.events.append(ev)
            self.events.append(ev)


# ---------------------------------------------------------------------------
# Enrichment — entrascopes.com
# ---------------------------------------------------------------------------


ENTRASCOPES_BASE = "https://entrascopes.com"
ENTRASCOPES_APPS_URL = f"{ENTRASCOPES_BASE}/firstpartyscopes.json"
ENTRASCOPES_RESOURCES_URL = f"{ENTRASCOPES_BASE}/resources.json"
ENRICH_CACHE_TTL_SECONDS = 7 * 24 * 3600


def default_cache_dir() -> Path:
    # TATS_CACHE is the canonical env var; BURP_TOKEN_TRACKER_CACHE is
    # accepted for one release as a migration nicety from the pre-rename
    # name (no warning — silent fallback).
    env = (os.environ.get("TATS_CACHE")
           or os.environ.get("BURP_TOKEN_TRACKER_CACHE"))
    if env:
        return Path(env).expanduser()
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "tats"
    local = os.environ.get("LOCALAPPDATA")
    if local:
        return Path(local) / "tats" / "cache"
    return Path.home() / ".cache" / "tats"


def entrascopes_app_link(guid: str) -> str:
    return f"{ENTRASCOPES_BASE}/?appId={guid}"


class EntraEnricher:
    def __init__(self, cache_dir: Optional[Path] = None, *,
                 use_cache: bool = True, _log=None) -> None:
        # ``_log`` is accepted-but-ignored for back-compat with older
        # callers; diagnostics now route through the ``tats.enrich``
        # logger configured by ``setup_logging()``.
        del _log
        self.cache_dir = (cache_dir or default_cache_dir()).expanduser()
        self.use_cache = use_cache
        self.log = _log_enrich
        self.apps: dict[str, dict] = {}
        self.resources: dict[str, str] = {}
        self.resource_by_url: dict[str, str] = {}
        self.available = False

    def load(self) -> None:
        apps_raw = self._load_json(
            ENTRASCOPES_APPS_URL, self.cache_dir / "firstpartyscopes.json")
        res_raw = self._load_json(
            ENTRASCOPES_RESOURCES_URL, self.cache_dir / "resources.json")
        if apps_raw is None and res_raw is None:
            return

        apps_container = (apps_raw or {}).get("apps", {}) if isinstance(apps_raw, dict) else {}
        if isinstance(apps_container, dict):
            for guid, info in apps_container.items():
                if isinstance(guid, str) and isinstance(info, dict):
                    self.apps[guid.lower()] = info

        if isinstance(apps_raw, dict):
            ri = apps_raw.get("resourceidentifiers")
            if isinstance(ri, dict):
                for url, guid in ri.items():
                    if isinstance(url, str) and isinstance(guid, str):
                        self.resource_by_url[url.strip().lower()] = guid

        res_items = None
        if isinstance(res_raw, list):
            res_items = res_raw
        elif isinstance(res_raw, dict):
            maybe = res_raw.get("resources")
            if isinstance(maybe, list):
                res_items = maybe
            else:
                for guid, info in res_raw.items():
                    if not isinstance(guid, str):
                        continue
                    if isinstance(info, str):
                        self.resources[guid.lower()] = info
                    elif isinstance(info, dict):
                        self.resources[guid.lower()] = (
                            info.get("displayName") or info.get("name") or guid)
        if res_items:
            for it in res_items:
                if not isinstance(it, dict):
                    continue
                rid = (it.get("resourceId") or it.get("appId") or "").strip()
                name = (it.get("displayName") or it.get("name") or "").strip()
                if rid:
                    self.resources[rid.lower()] = name or rid
                for url_field in ("identifierUri", "identifierUris",
                                  "servicePrincipalNames"):
                    val = it.get(url_field)
                    if isinstance(val, str):
                        self.resource_by_url[val.strip().lower()] = rid
                    elif isinstance(val, list):
                        for u in val:
                            if isinstance(u, str):
                                self.resource_by_url[u.strip().lower()] = rid

        self.available = bool(self.apps or self.resources)
        self.log.info("loaded %d apps, %d resources from entrascopes.com",
                      len(self.apps), len(self.resources))

    def lookup_app(self, guid: Optional[str]) -> Optional[dict]:
        if not guid or not GUID_RE.match(guid.strip()):
            return None
        info = self.apps.get(guid.strip().lower())
        if info is None:
            return None
        redirect_uris = info.get("redirect_uris") or []
        brokerable = any(isinstance(r, str) and r.lower().startswith("brk-")
                         for r in redirect_uris)
        return {
            "guid": guid.strip(),
            "name": info.get("name") or "",
            "foci": bool(info.get("foci")),
            "public_client": bool(info.get("public_client")),
            "brokerable": brokerable,
            "link": entrascopes_app_link(guid.strip()),
        }

    def lookup_resource(self, aud: Optional[str]) -> Optional[dict]:
        if not aud:
            return None
        raw = aud.strip()
        low = raw.lower()
        if GUID_RE.match(raw):
            name = self.resources.get(low)
            if name:
                return {"guid": raw, "name": name, "link": entrascopes_app_link(raw)}
            app = self.apps.get(low)
            if app:
                return {"guid": raw, "name": app.get("name") or raw,
                        "link": entrascopes_app_link(raw)}
            return {"guid": raw, "name": "(unknown)",
                    "link": entrascopes_app_link(raw)}
        guid = (
            self.resource_by_url.get(low)
            or self.resource_by_url.get(low.rstrip("/"))
            or self.resource_by_url.get(low + "/")
            or self.resource_by_url.get(f"api://{low}")
        )
        if guid:
            return {"guid": guid,
                    "name": self.resources.get(guid.lower(), raw),
                    "link": entrascopes_app_link(guid)}
        return None

    def _load_json(self, url: str, cache_path: Path):
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            self.log.warning("cannot create cache dir %s: %s",
                             self.cache_dir, e)
        if self.use_cache and cache_path.is_file():
            try:
                age = _time.time() - cache_path.stat().st_mtime
            except OSError:
                age = ENRICH_CACHE_TTL_SECONDS + 1
            if age <= ENRICH_CACHE_TTL_SECONDS:
                try:
                    return json.loads(cache_path.read_text(encoding="utf-8"))
                except Exception as e:
                    self.log.warning("cache read failed (%s): %s",
                                     cache_path, e)

        data = self._fetch(url)
        if data is None:
            if cache_path.is_file():
                try:
                    self.log.warning("using stale cache for %s",
                                     cache_path.name)
                    return json.loads(cache_path.read_text(encoding="utf-8"))
                except Exception:
                    return None
            return None
        try:
            cache_path.write_text(
                json.dumps(data, separators=(",", ":")), encoding="utf-8")
        except OSError as e:
            self.log.warning("cannot write cache %s: %s", cache_path, e)
        return data

    def _fetch(self, url: str):
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "tats/2.0 (+local research tool)"},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            self.log.warning("fetch failed for %s: %s", url, e)
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception as e:
            self.log.warning("JSON parse failed for %s: %s", url, e)
            return None


def enrich_token(tok: Token, enricher: EntraEnricher) -> None:
    payload = tok.jwt_payload or {}
    app_guid = (payload.get("appid") or payload.get("azp")
                or payload.get("client_id") or None)
    if isinstance(app_guid, str):
        tok.app_info = enricher.lookup_app(app_guid)
    aud = payload.get("aud")
    if isinstance(aud, list) and aud:
        aud = aud[0]
    if isinstance(aud, str):
        tok.resource_info = enricher.lookup_resource(aud)


# ---------------------------------------------------------------------------
# Database — schema, ingestion, query layer
# ---------------------------------------------------------------------------

DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS hosts (
    host TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS tokens (
    fp                TEXT PRIMARY KEY,
    sample            TEXT NOT NULL,
    type              TEXT NOT NULL,
    sub_type          TEXT NOT NULL,
    first_seen        TEXT,
    last_seen         TEXT,
    issuer_host       TEXT,
    foci_family       TEXT,
    jwt_header_json   TEXT,
    jwt_payload_json  TEXT,
    app_guid          TEXT,
    app_name          TEXT,
    app_link          TEXT,
    app_foci          INTEGER,
    app_brokerable    INTEGER,
    resource_guid     TEXT,
    resource_name     TEXT,
    resource_link     TEXT,
    claim_summary     TEXT,
    uses              INTEGER NOT NULL DEFAULT 0,
    user_identity     TEXT,
    exp_unix          INTEGER,
    tenant_id         TEXT,
    scopes_text       TEXT,
    source_tag        TEXT,
    -- Full token string. NULL unless the ingest was run with
    -- --store-tokens. Treat the file as sensitive when this column is
    -- populated — every byte needed to replay is here.
    raw               TEXT,
    -- Compact JSON object describing CAE / PoP / step-up markers on
    -- the JWT. NULL when none fired. See ``derive_security_features``.
    security_features TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    seq             INTEGER NOT NULL,
    time            TEXT,
    host            TEXT,
    method          TEXT,
    path            TEXT,
    status          INTEGER,
    direction       TEXT,
    role            TEXT,
    source          TEXT,
    fp              TEXT NOT NULL,
    token_type      TEXT,
    grant_type      TEXT,
    client_id       TEXT,
    broci_broker_id TEXT,
    ws_session_id   TEXT,
    source_tag      TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_fp  ON events(fp);
CREATE INDEX IF NOT EXISTS idx_events_seq ON events(seq);
CREATE INDEX IF NOT EXISTS idx_events_role ON events(role);

CREATE TABLE IF NOT EXISTS exchanges (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    seq             INTEGER NOT NULL,
    time            TEXT,
    host            TEXT,
    path            TEXT,
    grant_type      TEXT,
    client_id       TEXT,
    foci_family     TEXT,
    broci_broker_id TEXT,
    broci_nested_id TEXT,
    broci_evidence  TEXT,
    source_tag      TEXT
);

CREATE TABLE IF NOT EXISTS exchange_inputs (
    exchange_id INTEGER NOT NULL,
    fp          TEXT NOT NULL,
    PRIMARY KEY (exchange_id, fp)
);
CREATE INDEX IF NOT EXISTS idx_exin_fp ON exchange_inputs(fp);

CREATE TABLE IF NOT EXISTS exchange_outputs (
    exchange_id INTEGER NOT NULL,
    fp          TEXT NOT NULL,
    PRIMARY KEY (exchange_id, fp)
);
CREATE INDEX IF NOT EXISTS idx_exout_fp ON exchange_outputs(fp);

-- Lookup indexes for the dashboard's identity / tenant / sources cards.
-- Without them, those cards trigger a full token scan on every render
-- once token counts cross a few thousand.
CREATE INDEX IF NOT EXISTS idx_tokens_user_identity ON tokens(user_identity);
CREATE INDEX IF NOT EXISTS idx_tokens_tenant_id     ON tokens(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tokens_source_tag    ON tokens(source_tag);
"""


def stringify_claim(v) -> str:
    if v is None:
        return ""
    if isinstance(v, list):
        return ", ".join(stringify_claim(x) for x in v)
    if isinstance(v, dict):
        return json.dumps(v, separators=(",", ":"))
    return str(v)


def claim_summary(payload: Optional[dict]) -> str:
    """Compact, searchable, single-line summary of interesting JWT claims."""
    if not payload:
        return ""
    bits: list[str] = []
    seen: set[str] = set()
    for k in INVENTORY_JWT_CLAIMS:
        if k in payload:
            v = stringify_claim(payload.get(k))
            if v:
                bits.append(f"{k}={v}")
                seen.add(k)
    for k, v in payload.items():
        if k in seen or not isinstance(k, str):
            continue
        if k.startswith("brk_") or k.startswith("foci"):
            s = stringify_claim(v)
            if s:
                bits.append(f"{k}={s}")
    return "; ".join(bits)


# Claims that identify the human user a token was issued to. Order matters:
# we pick the first present, since e.g. ``upn`` is more readable than ``oid``.
USER_IDENTITY_CLAIMS = (
    "upn", "preferred_username", "unique_name", "email", "name",
)

# Default redaction list when the user passes ``--redact-claims`` without an
# explicit comma list. These are the claims that most commonly carry
# personally identifying information in Microsoft Entra tokens.
DEFAULT_REDACT_CLAIMS = (
    "sub", "oid", "upn", "email", "name",
    "unique_name", "preferred_username",
    # mail-style aliases
    "emails", "mail",
    # SAML-ish (sometimes appears in v1 tokens)
    "ipaddr", "given_name", "family_name",
)


def _redact_value(value):
    """Return a stable, content-free placeholder for ``value``.

    Same input always maps to the same output, so the dashboard can still
    *group* tokens by user (everyone with the same redacted upn falls into
    the same bucket) without revealing the user. Lists and nested dicts
    are walked so a list-shaped ``aud`` claim still redacts each entry.
    """
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        # Numbers are rarely PII; keep them so things like ``exp`` keep
        # working. If a deployment puts user IDs as ints, redact ahead of
        # the call (callers can pre-stringify).
        return value
    if isinstance(value, list):
        return [_redact_value(v) for v in value]
    if isinstance(value, dict):
        return {k: _redact_value(v) for k, v in value.items()}
    s = str(value)
    if not s:
        return s
    digest = hashlib.sha256(s.encode("utf-8")).hexdigest()[:8]
    return f"<redacted:{digest}>"


def redact_payload(payload: Optional[dict],
                   fields: Iterable[str]) -> Optional[dict]:
    """Return a copy of ``payload`` with every claim in ``fields``
    replaced by ``_redact_value(...)``. Other claims pass through
    unchanged. Returns the original (None) when ``payload`` is None."""
    if not payload:
        return payload
    field_set = {f.strip().lower() for f in fields if f and f.strip()}
    if not field_set:
        return payload
    out: dict = {}
    for k, v in payload.items():
        if isinstance(k, str) and k.lower() in field_set:
            out[k] = _redact_value(v)
        else:
            out[k] = v
    return out


def parse_redact_arg(raw: Optional[str]) -> Optional[set[str]]:
    """Parse the ``--redact-claims`` CLI value into a set of claim names.

    ``None`` (flag not given)               -> redaction disabled
    ``""`` (flag given without an argument) -> use ``DEFAULT_REDACT_CLAIMS``
    ``"foo,bar"``                            -> {"foo", "bar"}
    """
    if raw is None:
        return None
    if raw == "":
        return set(DEFAULT_REDACT_CLAIMS)
    fields = {f.strip() for f in raw.split(",") if f.strip()}
    return fields or set(DEFAULT_REDACT_CLAIMS)


def apply_redaction(tracker: "Tracker",
                    fields: Optional[set[str]]) -> int:
    """Walk every JWT in the tracker and redact the requested fields in
    place. Returns the count of tokens whose payload was modified."""
    if not fields:
        return 0
    touched = 0
    for tok in tracker.tokens.values():
        if tok.jwt_payload:
            new_payload = redact_payload(tok.jwt_payload, fields)
            if new_payload is not tok.jwt_payload:
                tok.jwt_payload = new_payload
                touched += 1
        if tok.jwt_header:
            tok.jwt_header = redact_payload(tok.jwt_header, fields)
    return touched


def derive_user_identity(payload: Optional[dict]) -> Optional[str]:
    """Return a human-readable user identifier for a JWT, or None.

    Microsoft tokens vary: id_tokens carry ``preferred_username`` and ``name``;
    v1 access tokens carry ``upn`` and ``unique_name``; service-principal
    tokens have no user at all (``idtyp=app``). We fall back to ``sub@iss``
    or ``oid`` if no friendly name is present so callers can still group
    tokens by identity.
    """
    if not payload:
        return None
    idtyp = payload.get("idtyp")
    if isinstance(idtyp, str) and idtyp.lower() == "app":
        return None  # explicitly an app-only token; let caller bucket as such
    for k in USER_IDENTITY_CLAIMS:
        v = payload.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    sub = payload.get("sub")
    iss = payload.get("iss")
    if isinstance(sub, str) and sub.strip():
        if isinstance(iss, str) and iss.strip():
            return f"{sub.strip()} @ {iss.strip()}"
        return sub.strip()
    oid = payload.get("oid")
    if isinstance(oid, str) and oid.strip():
        return oid.strip()
    return None


def derive_exp_unix(payload: Optional[dict]) -> Optional[int]:
    """Return the JWT ``exp`` claim as a Unix timestamp, or None."""
    if not payload:
        return None
    v = payload.get("exp")
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return int(v)
    if isinstance(v, str):
        try:
            return int(float(v))
        except ValueError:
            return None
    return None


def derive_tenant_id(payload: Optional[dict]) -> Optional[str]:
    """Return JWT ``tid`` claim if present (Microsoft Entra tenant id)."""
    if not payload:
        return None
    v = payload.get("tid")
    if isinstance(v, str) and v.strip():
        return v.strip()
    return None


def derive_scopes_text(payload: Optional[dict]) -> Optional[str]:
    """Return concatenated scope/scp/roles claim values, space-separated.

    Microsoft access tokens carry permissions in ``scp`` (delegated, space-
    separated) and ``roles`` (application). Some tokens also carry the
    OIDC ``scope`` claim. This helper normalises them so the dashboard can
    flag privileged scopes regardless of which claim they came from.
    """
    if not payload:
        return None
    bits: list[str] = []
    for key in ("scp", "scope", "roles"):
        v = payload.get(key)
        if isinstance(v, str) and v.strip():
            bits.append(v.strip())
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, str) and item.strip():
                    bits.append(item.strip())
    return " ".join(bits) if bits else None


# Claims that flag Microsoft-specific access-control features. The values
# are short stable strings the dashboard can group / filter on without
# re-parsing the underlying claim each render.
def derive_security_features(payload: Optional[dict]) -> Optional[dict]:
    """Detect Continuous Access Evaluation, proof-of-possession, and
    step-up auth markers on a JWT payload.

    Returns a dict with up to these keys (only ones that fire):

      ``cae``            — True if ``xms_cc`` contains "CP1" (the client
                           told Entra it can handle CAE challenges, so
                           tokens may be revoked mid-lifetime).
      ``pop``            — True if a ``cnf`` (RFC 7800) confirmation
                           claim is present; the token is bound to a
                           caller-held key and Bearer-style replay
                           against the audience will fail.
      ``pop_kid``        — the ``cnf.kid`` thumbprint when present, for
                           correlating tokens that bind to the same key.
      ``pop_pl``         — ``xms_pl``: preferred PoP audience location.
      ``acr``            — ``acr`` claim verbatim (e.g. "1" for plain,
                           "c1" for MFA on some MS endpoints).
      ``acrs``           — list of ``acrs`` ACR values (step-up auth
                           requirements the resource will enforce).
      ``amr``            — list of ``amr`` authentication methods (pwd,
                           mfa, pop, smartcard, …). Already surfaced on
                           the auth-methods card; included here so the
                           security-features view is self-contained.

    Returns ``None`` if nothing fired."""
    if not isinstance(payload, dict):
        return None
    out: dict = {}

    # CAE-capable client. xms_cc is a list per Microsoft's docs, but some
    # tokens carry a single string — accept both shapes.
    xms_cc = payload.get("xms_cc")
    if isinstance(xms_cc, str):
        xms_cc = [xms_cc]
    if isinstance(xms_cc, list) and any(
            isinstance(v, str) and v.strip().upper() == "CP1"
            for v in xms_cc):
        out["cae"] = True

    # Proof-of-possession binding. cnf is an object; even when present
    # without a usable jwk/kid it indicates PoP-style issuance.
    cnf = payload.get("cnf")
    if isinstance(cnf, dict) and cnf:
        out["pop"] = True
        kid = cnf.get("kid") or (cnf.get("jwk") or {}).get("kid") \
            if isinstance(cnf.get("jwk"), dict) else cnf.get("kid")
        if isinstance(kid, str) and kid.strip():
            out["pop_kid"] = kid.strip()

    xms_pl = payload.get("xms_pl")
    if isinstance(xms_pl, str) and xms_pl.strip():
        out["pop_pl"] = xms_pl.strip()

    acr = payload.get("acr")
    if isinstance(acr, str) and acr.strip():
        out["acr"] = acr.strip()

    acrs = payload.get("acrs")
    if isinstance(acrs, str):
        acrs = [acrs]
    if isinstance(acrs, list):
        vals = [v.strip() for v in acrs
                if isinstance(v, str) and v.strip()]
        if vals:
            out["acrs"] = vals

    amr = payload.get("amr")
    if isinstance(amr, str):
        amr = [amr]
    if isinstance(amr, list):
        vals = [v.strip() for v in amr
                if isinstance(v, str) and v.strip()]
        if vals:
            out["amr"] = vals

    return out or None


def security_features_text(payload: Optional[dict]) -> Optional[str]:
    """Serialise ``derive_security_features`` as a compact JSON string
    for the ``tokens.security_features`` column. ``None`` when nothing
    of interest is on the token."""
    feats = derive_security_features(payload)
    if not feats:
        return None
    return json.dumps(feats, separators=(",", ":"), sort_keys=True)


@dataclass(frozen=True)
class TokenFacts:
    """All derived fields about a JWT payload, computed once.

    This is a facade over the individual ``derive_*`` helpers and
    ``claim_summary``. Build it via :func:`derive_token_facts` at ingest
    time and the UPSERT site has a single object instead of six function
    calls — one place to add new derived fields, one place to test, and
    no risk of the call sites drifting out of sync (a previous version
    of the codebase forgot to pass ``security_features`` to the UPSERT
    after the column was added; a single facade eliminates that whole
    class of bug)."""

    user_identity: Optional[str]
    exp_unix: Optional[int]
    tenant_id: Optional[str]
    scopes_text: Optional[str]
    security_features_text: Optional[str]
    claim_summary: str


def derive_token_facts(payload: Optional[dict]) -> TokenFacts:
    """Derive all per-token facts from a JWT payload in one call.

    Returns a ``TokenFacts`` with everything we persist. Sub-helpers
    remain individually callable (and tested) so existing code paths
    that only need one field — e.g. the dashboard's redaction layer —
    don't have to instantiate the whole facade.
    """
    return TokenFacts(
        user_identity=derive_user_identity(payload),
        exp_unix=derive_exp_unix(payload),
        tenant_id=derive_tenant_id(payload),
        scopes_text=derive_scopes_text(payload),
        security_features_text=security_features_text(payload),
        claim_summary=claim_summary(payload),
    )


SCHEMA_VERSION = "4"


def _migrate(conn: sqlite3.Connection, existing: str) -> str:
    """Run forward-only migrations from ``existing`` to SCHEMA_VERSION on
    an open append-mode connection. Returns the version reached. Each
    step is additive (new nullable columns / tables) so older callers
    still work against an upgraded DB if they're forgiving about extra
    columns."""
    if existing == "2":
        # v2 -> v3: optional full-token storage. Adding a nullable column
        # is non-destructive: existing rows keep raw=NULL. PRAGMA
        # table_info returns (cid, name, type, notnull, dflt, pk) tuples.
        cols = {r[1] for r in conn.execute("PRAGMA table_info(tokens)")}
        if "raw" not in cols:
            conn.execute("ALTER TABLE tokens ADD COLUMN raw TEXT")
        conn.execute(
            "UPDATE meta SET value = '3' WHERE key = 'schema_version'")
        existing = "3"
    if existing == "3":
        # v3 -> v4: CAE / PoP / step-up auth detection. Persisted as a
        # compact JSON blob on the tokens row so the dashboard can group
        # / filter without re-parsing every JWT payload on each request.
        cols = {r[1] for r in conn.execute("PRAGMA table_info(tokens)")}
        if "security_features" not in cols:
            conn.execute(
                "ALTER TABLE tokens ADD COLUMN security_features TEXT")
        # Best-effort backfill for already-ingested rows so the new card
        # has data on day one without forcing a re-ingest.
        for row in conn.execute(
                "SELECT fp, jwt_payload_json FROM tokens "
                "WHERE security_features IS NULL "
                "  AND jwt_payload_json IS NOT NULL").fetchall():
            try:
                payload = json.loads(row[1])
            except (TypeError, ValueError):
                continue
            feats = security_features_text(payload)
            if feats:
                conn.execute(
                    "UPDATE tokens SET security_features = ? WHERE fp = ?",
                    (feats, row[0]))
        conn.execute(
            "UPDATE meta SET value = '4' WHERE key = 'schema_version'")
        existing = "4"
    return existing


def _open_db_for_write(db_path: Path, *, append: bool) -> sqlite3.Connection:
    if not append and db_path.exists():
        db_path.unlink()
    conn = sqlite3.connect(str(db_path))
    conn.executescript(DB_SCHEMA)
    conn.execute("PRAGMA foreign_keys = ON")
    if append:
        row = conn.execute(
            "SELECT value FROM meta WHERE key = 'schema_version'"
        ).fetchone()
        existing = row[0] if row else None
        if existing and existing != SCHEMA_VERSION:
            existing = _migrate(conn, existing)
        if existing and existing != SCHEMA_VERSION:
            conn.close()
            raise SystemExit(
                f"error: cannot append to DB with schema_version "
                f"{existing!r} (this build is at {SCHEMA_VERSION!r}). "
                "Re-ingest the original source without --append to rebuild.")
    return conn


def _seq_offset(conn: sqlite3.Connection) -> int:
    """In append mode, callers shift their seq numbers past the highest
    one already in the DB so the activity timeline stays monotonic."""
    row = conn.execute("SELECT COALESCE(MAX(seq), 0) FROM events").fetchone()
    return int(row[0] or 0)


def ingest_to_db(tracker: Tracker, db_path: Path,
                 *, source: str, enricher: Optional[EntraEnricher],
                 append: bool = False,
                 source_tag: Optional[str] = None,
                 store_tokens: bool = False) -> None:
    """Persist a Tracker to SQLite.

    ``append`` keeps an existing DB and merges into it via UPSERT for tokens
    and INSERT for events / exchanges. ``source_tag`` is stamped onto every
    new row (defaults to the tracker's tag, then to ``source``).
    ``store_tokens`` controls whether the full token string is written to
    ``tokens.raw``; off by default, since it makes the database a wholesale
    secret."""
    tag = source_tag or tracker.source_tag or source
    conn = _open_db_for_write(db_path, append=append)
    try:
        seq_offset = _seq_offset(conn) if append else 0

        # uses count per fp from THIS pass only — UPSERT will sum it.
        uses = {fp: 0 for fp in tracker.tokens}
        for ev in tracker.events:
            if ev.role in ("used", "presented", "exchanged-in"):
                uses[ev.fp] = uses.get(ev.fp, 0) + 1

        # ---- tokens (UPSERT) -------------------------------------------
        for fp, t in tracker.tokens.items():
            app = t.app_info or {}
            res = t.resource_info or {}
            # All derived JWT fields in one place — keeps the parameter
            # list below in sync with whatever new derivations get added.
            facts = derive_token_facts(t.jwt_payload)
            conn.execute("""
                INSERT INTO tokens(
                    fp, sample, type, sub_type, first_seen, last_seen,
                    issuer_host, foci_family,
                    jwt_header_json, jwt_payload_json,
                    app_guid, app_name, app_link, app_foci, app_brokerable,
                    resource_guid, resource_name, resource_link,
                    claim_summary, uses, user_identity, exp_unix,
                    tenant_id, scopes_text, source_tag, raw,
                    security_features)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(fp) DO UPDATE SET
                    -- preserve a non-unknown type once we have one
                    type = CASE WHEN type = 'unknown' THEN excluded.type
                                ELSE type END,
                    -- expand the observed lifetime
                    first_seen = CASE
                        WHEN first_seen IS NULL OR first_seen = '' THEN excluded.first_seen
                        WHEN excluded.first_seen IS NULL OR excluded.first_seen = '' THEN first_seen
                        WHEN excluded.first_seen < first_seen THEN excluded.first_seen
                        ELSE first_seen END,
                    last_seen = CASE
                        WHEN last_seen IS NULL OR last_seen = '' THEN excluded.last_seen
                        WHEN excluded.last_seen IS NULL OR excluded.last_seen = '' THEN last_seen
                        WHEN excluded.last_seen > last_seen THEN excluded.last_seen
                        ELSE last_seen END,
                    -- accumulate use count across passes
                    uses = uses + excluded.uses,
                    -- only fill nullable fields that were previously empty
                    issuer_host = COALESCE(issuer_host, excluded.issuer_host),
                    foci_family = COALESCE(foci_family, excluded.foci_family),
                    jwt_header_json = COALESCE(jwt_header_json, excluded.jwt_header_json),
                    jwt_payload_json = COALESCE(jwt_payload_json, excluded.jwt_payload_json),
                    app_guid = COALESCE(app_guid, excluded.app_guid),
                    app_name = COALESCE(app_name, excluded.app_name),
                    app_link = COALESCE(app_link, excluded.app_link),
                    app_foci = COALESCE(app_foci, excluded.app_foci),
                    app_brokerable = COALESCE(app_brokerable, excluded.app_brokerable),
                    resource_guid = COALESCE(resource_guid, excluded.resource_guid),
                    resource_name = COALESCE(resource_name, excluded.resource_name),
                    resource_link = COALESCE(resource_link, excluded.resource_link),
                    claim_summary = COALESCE(NULLIF(claim_summary, ''), excluded.claim_summary),
                    user_identity = COALESCE(user_identity, excluded.user_identity),
                    exp_unix = COALESCE(exp_unix, excluded.exp_unix),
                    tenant_id = COALESCE(tenant_id, excluded.tenant_id),
                    scopes_text = COALESCE(scopes_text, excluded.scopes_text),
                    -- record every distinct source we've seen this token from
                    source_tag = CASE
                        WHEN source_tag IS NULL OR source_tag = '' THEN excluded.source_tag
                        WHEN excluded.source_tag IS NULL OR excluded.source_tag = '' THEN source_tag
                        WHEN instr(',' || source_tag || ',', ',' || excluded.source_tag || ',') > 0 THEN source_tag
                        ELSE source_tag || ',' || excluded.source_tag END,
                    -- only fill raw if it was missing, so a later run
                    -- without --store-tokens can't blank an already-stored
                    -- token (and a later run with --store-tokens can fill
                    -- one that previously came in without).
                    raw = COALESCE(raw, excluded.raw),
                    security_features = COALESCE(
                        security_features, excluded.security_features)
            """, (
                t.fp, t.sample, t.token_type, t.sub_type,
                t.first_seen_time, t.last_seen_time, t.issuer_host,
                t.foci_family,
                json.dumps(t.jwt_header) if t.jwt_header else None,
                json.dumps(t.jwt_payload) if t.jwt_payload else None,
                app.get("guid"), app.get("name"), app.get("link"),
                1 if app.get("foci") else (0 if app else None),
                1 if app.get("brokerable") else (0 if app else None),
                res.get("guid"), res.get("name"), res.get("link"),
                facts.claim_summary,
                uses.get(fp, 0),
                facts.user_identity,
                facts.exp_unix,
                facts.tenant_id,
                facts.scopes_text,
                tag,
                t.raw if store_tokens else None,
                facts.security_features_text,
            ))

        # hosts
        conn.executemany("INSERT OR IGNORE INTO hosts(host) VALUES (?)",
                         [(h,) for h in sorted(tracker.hosts)])

        # events
        conn.executemany("""
            INSERT INTO events(
                seq, time, host, method, path, status, direction, role, source,
                fp, token_type, grant_type, client_id, broci_broker_id,
                ws_session_id, source_tag)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, [
            (e.seq + seq_offset, e.time, e.host, e.method, e.path, e.status,
             e.direction, e.role, e.source, e.fp, e.token_type, e.grant_type,
             e.client_id, e.broci_broker_id, e.ws_session_id,
             e.source_tag or tag)
            for e in tracker.events
        ])

        # exchanges + io
        for x in tracker.exchanges:
            broker = (x.broci or {}).get("broker_client_id")
            nested = (x.broci or {}).get("nested_client_id")
            evidence = ", ".join((x.broci or {}).get("evidence") or [])
            cur = conn.execute("""
                INSERT INTO exchanges(
                    seq, time, host, path, grant_type, client_id, foci_family,
                    broci_broker_id, broci_nested_id, broci_evidence,
                    source_tag)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """, (x.seq + seq_offset, x.time, x.host, x.path, x.grant_type,
                  x.client_id, x.foci_family, broker, nested, evidence,
                  x.source_tag or tag))
            xid = cur.lastrowid
            conn.executemany(
                "INSERT INTO exchange_inputs(exchange_id, fp) VALUES (?, ?)",
                [(xid, fp) for fp in x.input_fps])
            conn.executemany(
                "INSERT INTO exchange_outputs(exchange_id, fp) VALUES (?, ?)",
                [(xid, fp) for fp in x.output_fps])

        # meta — recompute counts from the DB so they reflect cumulative state
        tcount = conn.execute("SELECT COUNT(*) FROM tokens").fetchone()[0]
        ecount = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        xcount = conn.execute("SELECT COUNT(*) FROM exchanges").fetchone()[0]
        hcount = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
        now_iso = _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime())
        existing_source = conn.execute(
            "SELECT value FROM meta WHERE key = 'source'"
        ).fetchone()
        merged_source = source
        if append and existing_source and existing_source[0]:
            if source not in existing_source[0].split(", "):
                merged_source = existing_source[0] + ", " + source
            else:
                merged_source = existing_source[0]
        meta_rows = [
            ("source", merged_source),
            ("generated_at",
             conn.execute("SELECT value FROM meta WHERE key = 'generated_at'")
                 .fetchone()[0] if append and conn.execute(
                "SELECT value FROM meta WHERE key = 'generated_at'"
             ).fetchone() else now_iso),
            ("last_modified", now_iso),
            ("schema_version", SCHEMA_VERSION),
            ("tokens_count", str(tcount)),
            ("events_count", str(ecount)),
            ("exchanges_count", str(xcount)),
            ("hosts_count", str(hcount)),
            ("enrichment_used",
             "1" if (enricher and enricher.available) else "0"),
        ]
        conn.executemany(
            "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", meta_rows)
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Read layer + Mermaid generators
# ---------------------------------------------------------------------------


class Store:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(
            f"file:{self.db_path}?mode=ro", uri=True, check_same_thread=False)
        c.row_factory = sqlite3.Row
        return c

    def meta(self) -> dict:
        with self._conn() as c:
            return {r["key"]: r["value"]
                    for r in c.execute("SELECT key, value FROM meta")}

    def tokens(self) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("""
                SELECT fp, sample, type, sub_type, first_seen, last_seen,
                       issuer_host, foci_family,
                       app_guid, app_name, app_link, app_foci, app_brokerable,
                       resource_guid, resource_name, resource_link,
                       claim_summary, uses, user_identity, exp_unix,
                       tenant_id, scopes_text, source_tag,
                       security_features,
                       jwt_header_json IS NOT NULL AS has_jwt
                FROM tokens
            """).fetchall()
        return [self._token_row(r) for r in rows]

    def host_usage(self) -> list[dict]:
        """Return ``(fp, host, role, count)`` aggregates from events.

        This is the minimum needed to drive the Hosts and audience-mismatch
        cards on the dashboard without sending the full event log.
        """
        with self._conn() as c:
            rows = c.execute("""
                SELECT fp, host, role, COUNT(*) AS n
                FROM events
                GROUP BY fp, host, role
            """).fetchall()
        return [{"fp": r["fp"], "host": r["host"],
                 "role": r["role"], "count": r["n"]} for r in rows]

    def token_detail(self, fp: str) -> Optional[dict]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM tokens WHERE fp = ?", (fp,)).fetchone()
            if row is None:
                return None
            evs = c.execute("""
                SELECT id, seq, time, host, method, path, status, direction,
                       role, source, token_type, grant_type, client_id,
                       broci_broker_id, ws_session_id, source_tag
                FROM events WHERE fp = ? ORDER BY seq, id
            """, (fp,)).fetchall()
            x_in = c.execute("""
                SELECT x.* FROM exchanges x
                JOIN exchange_inputs i ON i.exchange_id = x.id
                WHERE i.fp = ? ORDER BY x.seq
            """, (fp,)).fetchall()
            x_out = c.execute("""
                SELECT x.* FROM exchanges x
                JOIN exchange_outputs o ON o.exchange_id = x.id
                WHERE o.fp = ? ORDER BY x.seq
            """, (fp,)).fetchall()
        out = self._token_row(row)
        out["jwt_header"] = (
            json.loads(row["jwt_header_json"]) if row["jwt_header_json"] else None)
        out["jwt_payload"] = (
            json.loads(row["jwt_payload_json"]) if row["jwt_payload_json"] else None)
        out["events"] = [dict(e) for e in evs]
        out["exchanges_as_input"] = [self._exchange_row(c, e) for e in x_in]
        out["exchanges_as_output"] = [self._exchange_row(c, e) for e in x_out]
        # Optional full token (only present when --store-tokens was used).
        out["raw"] = (
            row["raw"] if "raw" in set(row.keys()) and row["raw"] else None)
        return out

    def exchanges(self) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("""
                SELECT * FROM exchanges ORDER BY seq, id
            """).fetchall()
            return [self._exchange_row(c, r) for r in rows]

    def hosts(self) -> list[str]:
        with self._conn() as c:
            return [r["host"] for r in c.execute(
                "SELECT host FROM hosts ORDER BY host")]

    @staticmethod
    def _token_row(r: sqlite3.Row) -> dict:
        keys = set(r.keys())
        d = {
            "fp": r["fp"], "sample": r["sample"], "type": r["type"],
            "sub_type": r["sub_type"], "first_seen": r["first_seen"],
            "last_seen": r["last_seen"], "issuer_host": r["issuer_host"],
            "foci_family": r["foci_family"],
            "claim_summary": r["claim_summary"], "uses": r["uses"],
            "user_identity": r["user_identity"] if "user_identity" in keys else None,
            "exp_unix": r["exp_unix"] if "exp_unix" in keys else None,
            "tenant_id": r["tenant_id"] if "tenant_id" in keys else None,
            "scopes_text": r["scopes_text"] if "scopes_text" in keys else None,
            "source_tag": r["source_tag"] if "source_tag" in keys else None,
        }
        # Decode the security_features JSON blob into an object so the
        # dashboard doesn't have to parse JSON in every render.
        if "security_features" in keys and r["security_features"]:
            try:
                d["security_features"] = json.loads(r["security_features"])
            except (TypeError, ValueError):
                d["security_features"] = None
        else:
            d["security_features"] = None
        if "has_jwt" in keys:
            d["has_jwt"] = bool(r["has_jwt"])
        else:
            d["has_jwt"] = bool(r["jwt_header_json"])
        if r["app_guid"]:
            d["app"] = {
                "guid": r["app_guid"], "name": r["app_name"],
                "link": r["app_link"], "foci": bool(r["app_foci"]),
                "brokerable": bool(r["app_brokerable"]),
            }
        else:
            d["app"] = None
        if r["resource_guid"]:
            d["resource"] = {
                "guid": r["resource_guid"], "name": r["resource_name"],
                "link": r["resource_link"],
            }
        else:
            d["resource"] = None
        return d

    @staticmethod
    def _exchange_row(c: sqlite3.Connection, r: sqlite3.Row) -> dict:
        xid = r["id"]
        ins = [row["fp"] for row in c.execute(
            "SELECT fp FROM exchange_inputs WHERE exchange_id = ? ORDER BY fp",
            (xid,))]
        outs = [row["fp"] for row in c.execute(
            "SELECT fp FROM exchange_outputs WHERE exchange_id = ? ORDER BY fp",
            (xid,))]
        keys = set(r.keys())
        return {
            "id": xid, "seq": r["seq"], "time": r["time"], "host": r["host"],
            "path": r["path"], "grant_type": r["grant_type"],
            "client_id": r["client_id"], "foci_family": r["foci_family"],
            "broci_broker_id": r["broci_broker_id"],
            "broci_nested_id": r["broci_nested_id"],
            "broci_evidence": r["broci_evidence"] or "",
            "source_tag": r["source_tag"] if "source_tag" in keys else None,
            "input_fps": ins, "output_fps": outs,
        }

    # -- Mermaid --------------------------------------------------------

    def mermaid_graph(self, *, highlight_fps: Optional[set[str]] = None,
                      isolate_fps: Optional[set[str]] = None) -> str:
        highlight_fps = set(highlight_fps or ())
        isolate_fps = set(isolate_fps or ())
        with self._conn() as c:
            tokens = c.execute("""
                SELECT fp, type, sub_type, foci_family, app_name
                FROM tokens
            """).fetchall()
            evs = c.execute("""
                SELECT DISTINCT fp, host, role FROM events
            """).fetchall()
            xs = c.execute("SELECT * FROM exchanges").fetchall()
            xins = {row["exchange_id"]: [] for row in c.execute(
                "SELECT exchange_id, fp FROM exchange_inputs")}
            for row in c.execute(
                "SELECT exchange_id, fp FROM exchange_inputs"):
                xins.setdefault(row["exchange_id"], []).append(row["fp"])
            xouts: dict[int, list[str]] = {}
            for row in c.execute(
                "SELECT exchange_id, fp FROM exchange_outputs"):
                xouts.setdefault(row["exchange_id"], []).append(row["fp"])
            hosts = [r["host"] for r in c.execute(
                "SELECT host FROM hosts ORDER BY host")]

        # Determine which fps + hosts survive isolation
        keep_fps: Optional[set[str]] = None
        keep_hosts: Optional[set[str]] = None
        if isolate_fps:
            keep_fps = set(isolate_fps)
            # Pull in fps connected through exchanges containing an isolated fp
            for x in xs:
                ins = xins.get(x["id"], [])
                outs = xouts.get(x["id"], [])
                if any(fp in isolate_fps for fp in ins + outs):
                    keep_fps.update(ins)
                    keep_fps.update(outs)
            keep_hosts = set()
            for ev in evs:
                if ev["fp"] in keep_fps:
                    keep_hosts.add(ev["host"])

        lines = ["flowchart LR"]
        token_ids: dict[str, str] = {}
        for t in tokens:
            fp = t["fp"]
            if keep_fps is not None and fp not in keep_fps:
                continue
            nid = f"T_{_mermaid_id(fp)}"
            token_ids[fp] = nid
            shape_l, shape_r = (("[(", ")]") if t["type"] == "refresh"
                                else ("([", "])"))
            extras: list[str] = []
            if t["foci_family"]:
                extras.append(f"FOCI:{t['foci_family']}")
            if t["app_name"]:
                extras.append(t["app_name"])
            extra = ("\\n" + " | ".join(extras)) if extras else ""
            label = f"{t['type']}\\n{fp}\\n({t['sub_type']}){extra}"
            lines.append(f"    {nid}{shape_l}\"{label}\"{shape_r}")

        host_ids: dict[str, str] = {}
        for h in hosts:
            if keep_hosts is not None and h not in keep_hosts:
                continue
            hid = f"H_{_mermaid_id(h)}"
            host_ids[h] = hid
            lines.append(f'    {hid}["{h}"]')

        seen_edges: set[tuple[str, str, str]] = set()
        for ev in evs:
            if ev["fp"] not in token_ids:
                continue
            tnode = token_ids[ev["fp"]]
            hnode = host_ids.get(ev["host"])
            if hnode is None:
                continue
            if ev["role"] in ("issued", "returned"):
                key = (hnode, tnode, "i")
                if key in seen_edges:
                    continue
                seen_edges.add(key)
                lines.append(f"    {hnode} -- issues --> {tnode}")
            elif ev["role"] in ("used", "presented", "exchanged-in"):
                verb = {"presented": "presented to",
                        "exchanged-in": "exchanged at"}.get(
                    ev["role"], "used at")
                key = (tnode, hnode, ev["role"])
                if key in seen_edges:
                    continue
                seen_edges.add(key)
                lines.append(f"    {tnode} -- {verb} --> {hnode}")

        for x in xs:
            label_parts = [x["grant_type"] or "exchange"]
            if x["foci_family"]:
                label_parts.append(f"FOCI:{x['foci_family']}")
            if x["broci_broker_id"]:
                label_parts.append("BroCI")
            label = " ".join(label_parts)
            for i in xins.get(x["id"], []):
                for o in xouts.get(x["id"], []):
                    if i == o:
                        continue
                    if i not in token_ids or o not in token_ids:
                        continue
                    lines.append(
                        f"    {token_ids[i]} -. {label} .-> {token_ids[o]}")

        if highlight_fps:
            highlighted_nodes: list[str] = []
            for fp in highlight_fps:
                nid = token_ids.get(fp)
                if nid:
                    highlighted_nodes.append(nid)
            if highlighted_nodes:
                lines.append("    classDef hl fill:#fde68a,stroke:#f59e0b,"
                             "stroke-width:3px,color:#1f2937;")
                lines.append("    class " + ",".join(highlighted_nodes) + " hl;")

        return "\n".join(lines)

    def mermaid_sequence(self, *, fp: Optional[str] = None,
                         highlight_fps: Optional[set[str]] = None,
                         max_events: int = 200) -> str:
        highlight_fps = set(highlight_fps or ())
        with self._conn() as c:
            if fp:
                evs = c.execute("""
                    SELECT seq, time, host, method, path, status, direction,
                           role, source, fp, token_type
                    FROM events WHERE fp = ? ORDER BY seq, id
                """, (fp,)).fetchall()
            else:
                evs = c.execute("""
                    SELECT seq, time, host, method, path, status, direction,
                           role, source, fp, token_type
                    FROM events ORDER BY seq, id
                """).fetchall()
            hosts_present = {e["host"] for e in evs}
            host_order = [r["host"] for r in c.execute(
                "SELECT host FROM hosts ORDER BY host") if r["host"] in hosts_present]

        lines = ["sequenceDiagram", "    participant C as Client"]
        host_actors: dict[str, str] = {}
        for h in host_order:
            aid = _mermaid_id(h)
            host_actors[h] = aid
            lines.append(f'    participant {aid} as {h}')

        shown = 0
        for e in evs:
            actor = host_actors.get(e["host"])
            if actor is None:
                continue
            tag = f"{e['token_type']} {e['fp']}"
            note = ""
            if highlight_fps and e["fp"] in highlight_fps:
                note = " ★"
            short_p = (e["path"] or "")[:48]
            if e["direction"] == "request":
                if e["role"] == "exchanged-in":
                    msg = f"{e['method']} {short_p} [exchange {tag}]{note}"
                elif e["role"] == "used":
                    msg = f"{e['method']} {short_p} [Bearer {tag}]{note}"
                elif e["role"] == "presented":
                    msg = f"{e['method']} {short_p} [{e['source']} {tag}]{note}"
                else:
                    msg = f"{e['method']} {short_p} [{tag}]{note}"
                lines.append(f"    C->>{actor}: {msg}")
            else:
                if e["role"] == "issued":
                    msg = f"{e['status'] or ''} issued {tag}{note}"
                else:
                    msg = f"{e['status'] or ''} {e['role']} {tag}{note}"
                lines.append(f"    {actor}-->>C: {msg}")
            shown += 1
            if shown >= max_events:
                lines.append(f"    note over C: ...truncated after {max_events} events...")
                break
        return "\n".join(lines)


def _mermaid_id(raw: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", raw)[:40] or "n"


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------


def make_handler(store: Store, log=None):
    # ``log`` is kept in the signature for back-compat but ignored —
    # diagnostics go through the ``tats.serve`` logger.
    del log
    serve_log = _log_serve

    class Handler(BaseHTTPRequestHandler):
        server_version = "tats/2.0"

        def log_message(self, fmt, *args):  # quieter than the default
            serve_log.debug(fmt, *args)

        def _send_json(self, payload, status: int = 200) -> None:
            data = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _send_text(self, body: str, content_type: str = "text/html",
                       status: int = 200) -> None:
            data = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", f"{content_type}; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _params(self) -> dict[str, list[str]]:
            qs = self.path.split("?", 1)[1] if "?" in self.path else ""
            return _urlparse.parse_qs(qs, keep_blank_values=True)

        def _path_only(self) -> str:
            return self.path.split("?", 1)[0]

        def do_GET(self):  # noqa: N802
            try:
                p = self._path_only()
                if p == "/" or p == "/index.html":
                    return self._send_text(INDEX_HTML, "text/html")
                if p == "/api/data":
                    return self._send_json({
                        "meta": store.meta(),
                        "hosts": store.hosts(),
                        "tokens": store.tokens(),
                        "exchanges": store.exchanges(),
                        "host_usage": store.host_usage(),
                    })
                if p == "/api/meta":
                    # tiny poll endpoint for live-update detection
                    return self._send_json(store.meta())
                if p.startswith("/api/token/"):
                    fp = p.rsplit("/", 1)[-1]
                    detail = store.token_detail(fp)
                    if detail is None:
                        return self._send_json(
                            {"error": "token not found"}, status=404)
                    return self._send_json(detail)
                if p == "/api/export":
                    # Bulk export of selected tokens for replay or use
                    # with downstream tools (roadtx, jwt.io, curl). Includes
                    # the raw token string when --store-tokens was used.
                    params = self._params()
                    fps = []
                    for v in params.get("fps", []):
                        fps.extend(x for x in v.split(",") if x)
                    if not fps:
                        return self._send_json(
                            {"error": "no fps given"}, status=400)
                    out = []
                    for fp in fps[:200]:  # cap to stop runaway queries
                        d = store.token_detail(fp)
                        if d is not None:
                            out.append(d)
                    return self._send_json({
                        "exported_at": _time.strftime(
                            "%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
                        "count": len(out),
                        "tokens": out,
                    })
                if p == "/api/graph":
                    params = self._params()
                    hl = set(params.get("highlight", []))
                    iso = set(params.get("isolate", []))
                    src = store.mermaid_graph(
                        highlight_fps=hl or None,
                        isolate_fps=iso or None)
                    return self._send_json({"mermaid": src})
                if p == "/api/sequence":
                    params = self._params()
                    fp = (params.get("fp") or [None])[0]
                    hl = set(params.get("highlight", []))
                    try:
                        max_events = int((params.get("max") or ["200"])[0])
                    except ValueError:
                        max_events = 200
                    src = store.mermaid_sequence(
                        fp=fp, highlight_fps=hl or None,
                        max_events=max_events)
                    return self._send_json({"mermaid": src})
                if p == "/healthz":
                    return self._send_text("ok", "text/plain")
                return self._send_text("not found", status=404)
            except Exception as e:  # noqa: BLE001
                serve_log.exception("handler error: %r", e)
                self._send_json({"error": str(e)}, status=500)

    return Handler


def serve(db_path: Path, host: str, port: int, *,
          open_browser: bool = True, log=None) -> None:
    # ``log`` retained for back-compat; routing goes through ``tats.serve``.
    del log
    if not db_path.exists():
        raise SystemExit(
            f"error: database file not found: {db_path}\n"
            f"       working directory: {Path.cwd()}\n"
            "       create one first with one of:\n"
            f"         tats ingest <burp.xml> -o {db_path}\n"
            f"         tats mitm   <flow.mitm> -o {db_path}\n"
            f"         tats cdp                 -o {db_path}")
    store = Store(db_path)
    # Touch the DB once so any schema / permission errors surface before
    # we bind the listening port (otherwise the user sees a confusing
    # success message followed by a 500 on the first browser request).
    try:
        meta = store.meta()
    except sqlite3.DatabaseError as e:
        raise SystemExit(
            f"error: {db_path} is not a valid SQLite database produced by "
            f"this tool: {e}\n"
            "       re-create it with: tats ingest <burp.xml> -o "
            + str(db_path))
    sv = meta.get("schema_version")
    if sv and sv != SCHEMA_VERSION:
        _log_serve.warning(
            "database schema_version is %r but this build expects %r — some "
            "dashboard fields may be empty until you re-ingest.",
            sv, SCHEMA_VERSION)
    handler_cls = make_handler(store)
    httpd = ThreadingHTTPServer((host, port), handler_cls)
    url = f"http://{host}:{port}/"
    _log_serve.info("%s -> %s", db_path, url)
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        _log_serve.info("shutting down")
    finally:
        httpd.server_close()


# ---------------------------------------------------------------------------
# Web UI (single page)
# ---------------------------------------------------------------------------

# The dashboard's HTML / CSS / JS were extracted into separate files
# under ``tats/static/`` so they can be edited with proper LSP /
# linting / formatting support. Loaded once at module import time and
# interpolated into a single string the HTTP handler serves directly —
# no per-request file I/O, no template engine, no extra deps.
_STATIC_DIR = Path(__file__).parent / "static"


def _load_index_html() -> str:
    tpl = (_STATIC_DIR / "index.html").read_text(encoding="utf-8")
    css = (_STATIC_DIR / "style.css").read_text(encoding="utf-8")
    js = (_STATIC_DIR / "app.js").read_text(encoding="utf-8")
    return tpl.replace("{{CSS}}", css).replace("{{JS}}", js)


INDEX_HTML = _load_index_html()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_enricher(args: argparse.Namespace) -> Optional[EntraEnricher]:
    if not getattr(args, "enrich", False):
        return None
    cache = (Path(args.enrich_cache_dir).expanduser()
             if getattr(args, "enrich_cache_dir", None) else None)
    enricher = EntraEnricher(
        cache_dir=cache, use_cache=not args.no_enrich_cache)
    enricher.load()
    return enricher


def _looks_like_burp_project_file(path: Path) -> bool:
    """A binary .burp project file starts with the bytes ``\\x00burp`` (a
    leading NUL plus the magic). The XML export always starts with ``<``."""
    try:
        with path.open("rb") as f:
            head = f.read(8)
    except OSError:
        return False
    return head[:1] == b"\x00" or head[:5] == b"\x00burp" or path.suffix.lower() == ".burp"


def cmd_ingest(args: argparse.Namespace) -> int:
    in_path = Path(args.input).expanduser()
    if not in_path.exists():
        print(f"error: input file not found: {in_path}\n"
              f"       resolved from: {args.input!r}\n"
              f"       working directory: {Path.cwd()}",
              file=sys.stderr)
        return 2
    if _looks_like_burp_project_file(in_path):
        print(f"error: {in_path} looks like a binary Burp project file (.burp), "
              "which is not supported.\n"
              "       in Burp: Proxy > HTTP history > select items > "
              "right-click > Save items\n"
              "       then ingest the resulting XML file.",
              file=sys.stderr)
        return 2
    try:
        tree = ET.parse(str(in_path))
    except ET.ParseError as e:
        print(f"error: could not parse {in_path} as XML: {e}\n"
              "       this tool accepts Burp's 'Save items' XML export.\n"
              "       in Burp: Proxy > HTTP history > select items > "
              "right-click > Save items.",
              file=sys.stderr)
        return 2
    except OSError as e:
        print(f"error: could not read {in_path}: {e}\n"
              f"       check that the file exists and is readable; "
              f"working directory: {Path.cwd()}",
              file=sys.stderr)
        return 2

    items = tree.getroot().findall(".//item")
    if not items:
        root_tag = tree.getroot().tag
        print(f"error: no <item> elements found in {in_path} "
              f"(root element is <{root_tag}>).\n"
              "       this tool needs a Burp 'Save items' XML export "
              "(root element <items>).\n"
              "       in Burp: Proxy > HTTP history > select items > "
              "right-click > Save items.",
              file=sys.stderr)
        return 2

    source_tag = args.source_tag or f"burp:{in_path.name}"
    tracker = Tracker(source_tag=source_tag)
    progress_disabled = args.no_progress or args.quiet
    with _Progress(total=len(items), label=f"ingest {in_path.name}",
                   disable=progress_disabled) as prog:
        for i, item in enumerate(items, start=1):
            tracker.ingest_item(i, item)
            prog.update()

    redact_fields = parse_redact_arg(getattr(args, "redact_claims", None))
    if redact_fields:
        n = apply_redaction(tracker, redact_fields)
        _log_ingest.info("redacted %d JWT claim values across %d tokens",
                         len(redact_fields), n)

    enricher = _build_enricher(args)
    if enricher and enricher.available:
        for tok in tracker.tokens.values():
            enrich_token(tok, enricher)

    db_path = Path(args.output).expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    store_tokens = bool(getattr(args, "store_tokens", False))
    if store_tokens:
        _log_ingest.warning(
            "--store-tokens: full token strings will be written to %s. "
            "Treat the database as a wholesale credential — every byte "
            "needed to replay any captured session is in it.",
            db_path)
    ingest_to_db(tracker, db_path, source=str(in_path),
                 enricher=enricher, append=args.append,
                 source_tag=source_tag,
                 store_tokens=store_tokens)
    print(f"wrote {db_path} (tokens={len(tracker.tokens)}, "
          f"events={len(tracker.events)}, "
          f"exchanges={len(tracker.exchanges)}, "
          f"source={source_tag}, append={args.append}"
          f"{', store_tokens=True' if store_tokens else ''})",
          file=sys.stderr)
    if not args.no_serve_hint:
        print(f"hint: launch the web UI with\n"
              f"    python {Path(sys.argv[0]).name} serve {db_path}",
              file=sys.stderr)
    return 0


def _format_request_headers(method: str, full_path: str,
                            mitm_headers) -> tuple[list[str], str]:
    """Convert mitmproxy headers into the ``[request_line, "k: v", ...]``
    shape our HTTP message helpers expect, and return (headers, path).

    ``full_path`` is the URL's path + query (we keep query params so the
    existing query-string token extractor still works)."""
    lines = [f"{method} {full_path or '/'} HTTP/1.1"]
    for name, value in mitm_headers.items(multi=True):
        lines.append(f"{name}: {value}")
    return lines, full_path or "/"


def _format_response_headers(status_code: Optional[int],
                             mitm_headers) -> list[str]:
    code = status_code if status_code is not None else 0
    lines = [f"HTTP/1.1 {code}"]
    for name, value in mitm_headers.items(multi=True):
        lines.append(f"{name}: {value}")
    return lines


def _decode_body(content: Optional[bytes]) -> str:
    if content is None:
        return ""
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError:
        return content.decode("utf-8", errors="replace")


def cmd_mitm(args: argparse.Namespace) -> int:
    try:
        import mitmproxy.io as mio
        from mitmproxy import http as mhttp
        from mitmproxy.exceptions import FlowReadException
    except ImportError as e:
        print(f"error: the 'mitm' source needs the mitmproxy Python package "
              f"({e}).\n"
              "       install it with:  pip install mitmproxy\n"
              "       (or use a different ingest source — see --help)",
              file=sys.stderr)
        return 2

    in_path = Path(args.input).expanduser()
    if not in_path.exists():
        print(f"error: mitmproxy flow file not found: {in_path}\n"
              f"       resolved from: {args.input!r}\n"
              f"       working directory: {Path.cwd()}\n"
              f"       create one with:  mitmdump -w {in_path.name}",
              file=sys.stderr)
        return 2
    if not in_path.is_file():
        print(f"error: {in_path} exists but is not a regular file.",
              file=sys.stderr)
        return 2

    source_tag = args.source_tag or f"mitm:{in_path.name}"
    tracker = Tracker(source_tag=source_tag)
    seq = 0
    flows_seen = 0
    ws_frames_seen = 0

    progress_disabled = args.no_progress or args.quiet
    prog = _Progress(label=f"mitm {in_path.name}", disable=progress_disabled)
    with in_path.open("rb") as f:
        reader = mio.FlowReader(f)
        try:
            for flow in reader.stream():
                if not isinstance(flow, mhttp.HTTPFlow):
                    continue
                seq += 1
                flows_seen += 1
                prog.update()
                req = flow.request
                resp = flow.response

                host_label = req.pretty_host
                port = req.port
                if port and port not in (80, 443):
                    host_label = f"{host_label}:{port}"

                full_path = req.path or "/"
                req_headers, path = _format_request_headers(
                    req.method, full_path, req.headers)
                req_body = _decode_body(getattr(req, "content", None))

                if resp is not None:
                    resp_headers = _format_response_headers(
                        resp.status_code, resp.headers)
                    resp_body = _decode_body(
                        getattr(resp, "content", None))
                    status = resp.status_code
                else:
                    resp_headers, resp_body, status = [], "", None

                ts = (req.timestamp_start
                      if req.timestamp_start is not None else 0)
                time_str = _time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", _time.gmtime(ts)) if ts else ""

                tracker._ingest_http_message(
                    seq=seq, time=time_str, host_label=host_label,
                    path=path, method=req.method, status=status,
                    req_headers=req_headers, req_body=req_body,
                    resp_headers=resp_headers, resp_body=resp_body,
                    source_tag=source_tag,
                )

                ws = getattr(flow, "websocket", None)
                if ws is not None:
                    # Each frame becomes its own seq slot so the sequence
                    # diagram can place them after the upgrade.
                    ws_session_id = f"mitm:{flow.id}"
                    for msg in ws.messages:
                        if msg.type not in (1, 2):  # TEXT=1, BINARY=2
                            continue
                        try:
                            payload = msg.content.decode("utf-8")
                        except (UnicodeDecodeError, AttributeError):
                            continue
                        seq += 1
                        ws_frames_seen += 1
                        frame_ts = (msg.timestamp
                                    if msg.timestamp is not None else ts)
                        frame_time = _time.strftime(
                            "%Y-%m-%dT%H:%M:%SZ",
                            _time.gmtime(frame_ts)) if frame_ts else ""
                        tracker.ingest_ws_frame(
                            seq=seq, time=frame_time,
                            host_label=host_label, path=path,
                            direction="sent" if msg.from_client else "received",
                            payload=payload,
                            ws_session_id=ws_session_id,
                            source_tag=source_tag,
                        )
        except FlowReadException as e:
            print(f"error: {in_path} is not a valid mitmproxy flow file: "
                  f"{e}\n"
                  "       this subcommand expects a .mitm file produced by "
                  "mitmproxy / mitmdump / mitmweb.\n"
                  "       (HAR files, pcap files, and Burp XML are NOT this "
                  "format.)",
                  file=sys.stderr)
            return 2
        except OSError as e:
            print(f"error: I/O error reading {in_path}: {e}\n"
                  f"       working directory: {Path.cwd()}",
                  file=sys.stderr)
            return 2
        except Exception as e:  # noqa: BLE001 — unexpected mitmproxy bug
            print(f"error: unexpected failure while reading {in_path}: "
                  f"{type(e).__name__}: {e}\n"
                  "       this is likely a bug — please file an issue with "
                  "the traceback below.\n",
                  file=sys.stderr)
            import traceback
            traceback.print_exc()
            prog.close()
            return 2
    prog.close()

    if flows_seen == 0:
        print(f"warning: no HTTP flows found in {in_path}", file=sys.stderr)

    redact_fields = parse_redact_arg(getattr(args, "redact_claims", None))
    if redact_fields:
        n = apply_redaction(tracker, redact_fields)
        _log_ingest.info("redacted %d JWT claim values across %d tokens",
                         len(redact_fields), n)

    enricher = _build_enricher(args)
    if enricher and enricher.available:
        for tok in tracker.tokens.values():
            enrich_token(tok, enricher)

    db_path = Path(args.output).expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    store_tokens = bool(getattr(args, "store_tokens", False))
    if store_tokens:
        _log_ingest.warning(
            "--store-tokens: full token strings will be written to %s.",
            db_path)
    ingest_to_db(tracker, db_path, source=str(in_path),
                 enricher=enricher, append=args.append,
                 source_tag=source_tag,
                 store_tokens=store_tokens)
    print(f"wrote {db_path} (flows={flows_seen}, ws_frames={ws_frames_seen}, "
          f"tokens={len(tracker.tokens)}, events={len(tracker.events)}, "
          f"exchanges={len(tracker.exchanges)}, "
          f"source={source_tag}, append={args.append}"
          f"{', store_tokens=True' if store_tokens else ''})",
          file=sys.stderr)
    if not args.no_serve_hint:
        print(f"hint: launch the web UI with\n"
              f"    python {Path(sys.argv[0]).name} serve {db_path}",
              file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# CDP attach (live capture from Chrome / Edge via DevTools Protocol)
# ---------------------------------------------------------------------------


import socket
import struct


class _WSClient:
    """Minimal RFC 6455 WebSocket client. ``ws://`` only — CDP listens on
    plain HTTP/WS on localhost so we never need TLS."""

    def __init__(self, host: str, port: int, path: str,
                 timeout: float = 10.0) -> None:
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(None)
        self._buf = b""
        self._do_handshake(host, port, path)

    def _do_handshake(self, host: str, port: int, path: str) -> None:
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        self.sock.sendall(req.encode("ascii"))
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("WS handshake closed before reply")
            buf += chunk
        first_line = buf.split(b"\r\n", 1)[0]
        if b"101" not in first_line:
            raise ConnectionError(
                f"WS handshake failed: {first_line.decode('ascii', 'replace')}")
        end = buf.index(b"\r\n\r\n") + 4
        self._buf = buf[end:]

    def _read_n(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("WS connection closed")
            self._buf += chunk
        out = self._buf[:n]
        self._buf = self._buf[n:]
        return out

    def recv_message(self) -> tuple[int, bytes]:
        """Return ``(opcode, defragmented_payload)`` for the next message."""
        msg = bytearray()
        first_op: Optional[int] = None
        while True:
            hdr = self._read_n(2)
            b0, b1 = hdr[0], hdr[1]
            fin = bool(b0 & 0x80)
            op = b0 & 0x0F
            masked = bool(b1 & 0x80)
            length = b1 & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._read_n(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._read_n(8))[0]
            mask = self._read_n(4) if masked else None
            payload = self._read_n(length) if length else b""
            if mask:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            if first_op is None and op != 0:
                first_op = op
            msg.extend(payload)
            if fin:
                break
        return (first_op or 0), bytes(msg)

    def send(self, data, opcode: int = 1) -> None:
        if isinstance(data, str):
            data = data.encode("utf-8")
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        n = len(data)
        hdr = bytes([0x80 | opcode])
        if n < 126:
            hdr += bytes([0x80 | n])
        elif n < 65536:
            hdr += bytes([0x80 | 126]) + struct.pack("!H", n)
        else:
            hdr += bytes([0x80 | 127]) + struct.pack("!Q", n)
        self.sock.sendall(hdr + mask + masked)

    def close(self) -> None:
        try:
            self.send(b"", opcode=8)
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


class CDPClient:
    """Connect to a Chrome / Edge instance launched with
    ``--remote-debugging-port=<port>`` and ingest its Network events into a
    Tracker. Captures HTTP request / response pairs (with bodies) and
    WebSocket frame payloads in both directions.

    By default attaches at the *browser* level and uses the flat-protocol
    session multiplexer (``Target.setAutoAttach`` with ``flatten=true``) so
    every existing tab AND every tab the user opens during the run is
    tracked over one WebSocket. Pass ``target_id`` to fall back to the
    legacy single-target attach (one tab only, dies when the tab closes).
    """

    def __init__(self, tracker: Tracker, *, host: str, port: int,
                 target_id: Optional[str], source_tag: str,
                 log=None) -> None:
        # ``log`` accepted for back-compat; diagnostics route through
        # the ``tats.cdp`` logger.
        del log
        self.tracker = tracker
        self.host = host
        self.port = port
        self.target_id = target_id
        self.source_tag = source_tag
        self.log = _log_cdp
        self.ws: Optional[_WSClient] = None
        self.next_id = 1
        self.event_queue: list[dict] = []
        # Per-session state, keyed by CDP sessionId. The legacy
        # single-target path stores its state under the key ``None``
        # because per-target WebSockets don't carry sessionId on events.
        self.sessions: dict[Optional[str], dict] = {}
        self._seq_counter = 0
        self.attached_target: Optional[dict] = None

    # -- attach + RPC -----------------------------------------------------

    def list_targets(self) -> list[dict]:
        url = f"http://{self.host}:{self.port}/json/list"
        with urllib.request.urlopen(url, timeout=5) as resp:
            return json.loads(resp.read())

    def _new_session_state(self, target_info: dict) -> dict:
        return {
            "target_id": target_info.get("targetId") or target_info.get("id"),
            "url": target_info.get("url", ""),
            "title": target_info.get("title", ""),
            "type": target_info.get("type", "page"),
            "http_pending": {},
            "ws_sessions": {},
        }

    def attach(self) -> None:
        if self.target_id:
            self._attach_single_target()
        else:
            self._attach_browser_level()

    def _attach_single_target(self) -> None:
        """Legacy per-tab attach: connect to one target's WebSocket and
        ride that connection. Closes when the tab closes."""
        targets = self.list_targets()
        chosen = next(
            (t for t in targets if t.get("id") == self.target_id), None)
        if chosen is None:
            raise SystemExit(
                f"target {self.target_id!r} not found in /json/list")
        ws_url = chosen.get("webSocketDebuggerUrl")
        if not ws_url:
            raise SystemExit(
                f"target {chosen.get('id')!r} has no webSocketDebuggerUrl "
                "(another debugger may already be attached).")
        parsed = _urlparse.urlparse(ws_url)
        self.ws = _WSClient(parsed.hostname or "127.0.0.1",
                            parsed.port or self.port, parsed.path)
        self.attached_target = chosen
        self.sessions[None] = self._new_session_state(chosen)
        self.log.info("attached to %s (%s)",
                      chosen.get("title") or "?", chosen.get("url") or "?")
        self.call("Network.enable")

    def _attach_browser_level(self) -> None:
        """Connect to the browser-level WebSocket and auto-attach to every
        existing and future page target with the flat protocol."""
        url = f"http://{self.host}:{self.port}/json/version"
        with urllib.request.urlopen(url, timeout=5) as resp:
            info = json.loads(resp.read())
        ws_url = info.get("webSocketDebuggerUrl")
        if not ws_url:
            raise SystemExit(
                f"no browser-level webSocketDebuggerUrl at {url} — Chrome "
                "may be too old for multi-tab tracking. Pass --target <id> "
                "from /json/list to attach to a single tab instead.")
        parsed = _urlparse.urlparse(ws_url)
        self.ws = _WSClient(parsed.hostname or "127.0.0.1",
                            parsed.port or self.port, parsed.path)
        self.log.info("attached to %s at browser level "
                      "(tracking all current and future tabs)",
                      info.get("Browser") or "Chrome")
        # Discover events fire for every new target; on_target_created
        # then attaches anything setAutoAttach missed. Belt and braces.
        self.call("Target.setDiscoverTargets", {"discover": True})
        # Primary path: future top-level targets get auto-attached as flat
        # sessions, so all events for every tab arrive on this single
        # socket carrying a sessionId.
        self.call("Target.setAutoAttach", {
            "autoAttach": True,
            "waitForDebuggerOnStart": False,
            "flatten": True,
        })
        # Manually attach to every existing page target. Each call fires a
        # Target.attachedToTarget event that on_target_attached handles.
        targets = self.call("Target.getTargets")
        for t in targets.get("targetInfos", []) or []:
            if t.get("type") != "page":
                continue
            tid = t.get("targetId")
            if not tid:
                continue
            try:
                self.call("Target.attachToTarget",
                          {"targetId": tid, "flatten": True})
            except RuntimeError as e:
                self.log.warning(
                    "attachToTarget(%s) failed: %s", tid, e)

    def call(self, method: str, params: Optional[dict] = None,
             timeout: float = 15.0, *,
             sid: Optional[str] = None) -> dict:
        """Send a CDP command and wait for its response.

        If ``sid`` is set the command is routed to that flat session;
        otherwise it goes to the root (browser- or single-target-level)
        connection. Events that arrive while we're waiting are buffered
        on ``event_queue`` so ``run_forever`` can dispatch them later.
        """
        cid = self.next_id
        self.next_id += 1
        msg: dict = {"id": cid, "method": method, "params": params or {}}
        if sid:
            msg["sessionId"] = sid
        assert self.ws is not None
        self.ws.send(json.dumps(msg))
        deadline = _time.time() + timeout
        while _time.time() < deadline:
            op, data = self.ws.recv_message()
            if op == 8:
                raise ConnectionError("CDP closed during call")
            if op != 1:
                continue
            obj = json.loads(data.decode("utf-8"))
            if obj.get("id") == cid:
                if "error" in obj:
                    raise RuntimeError(
                        f"CDP {method} error: {obj['error']}")
                return obj.get("result", {}) or {}
            if "method" in obj:
                self.event_queue.append(obj)
        raise TimeoutError(f"CDP {method} timed out")

    def next_event(self) -> Optional[dict]:
        if self.event_queue:
            return self.event_queue.pop(0)
        assert self.ws is not None
        while True:
            op, data = self.ws.recv_message()
            if op == 8:
                return None
            if op != 1:
                continue
            obj = json.loads(data.decode("utf-8"))
            if "method" in obj:
                return obj
            # response to a command we didn't await — drop
            continue

    # -- internal helpers -------------------------------------------------

    def _seq(self) -> int:
        self._seq_counter += 1
        return self._seq_counter

    @staticmethod
    def _fmt_time(ts: Optional[float]) -> str:
        if not ts:
            return ""
        # CDP timestamps are monotonic seconds since process start, not unix.
        # We keep them as-is but stamp wall-clock at ingest time.
        return _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime())

    @staticmethod
    def _split_url(url: str) -> tuple[str, str]:
        parsed = _urlparse.urlparse(url)
        host = parsed.hostname or "?"
        if parsed.port and parsed.port not in (80, 443):
            host = f"{host}:{parsed.port}"
        path = parsed.path or "/"
        if parsed.query:
            path = path + "?" + parsed.query
        return host, path

    @staticmethod
    def _headers_to_lines(start_line: str, headers: dict) -> list[str]:
        out = [start_line]
        for k, v in (headers or {}).items():
            if isinstance(v, list):
                for vv in v:
                    out.append(f"{k}: {vv}")
            else:
                out.append(f"{k}: {v}")
        return out

    # -- Target / session lifecycle handlers -----------------------------

    def _page_session_count(self) -> int:
        return sum(1 for s in self.sessions.values()
                   if s.get("type") == "page")

    def on_target_created(self, params: dict, sid: Optional[str]) -> None:
        """Fallback for setAutoAttach: if Chrome didn't auto-attach the new
        target for some reason (older builds, weird flags), grab it
        explicitly. Idempotent — Chrome will return an error if the target
        is already attached, which we swallow at debug level."""
        del sid
        info = params.get("targetInfo") or {}
        if info.get("type") != "page":
            return
        tid = info.get("targetId")
        if not tid:
            return
        # Skip if we already have a session for this target (auto-attach
        # most likely beat us to it).
        if any(s.get("target_id") == tid for s in self.sessions.values()):
            return
        try:
            self.call("Target.attachToTarget",
                      {"targetId": tid, "flatten": True})
        except RuntimeError as e:
            self.log.debug("targetCreated -> attachToTarget(%s): %s", tid, e)

    def on_target_attached(self, params: dict, sid: Optional[str]) -> None:
        # ``sid`` here is the parent session that observed the attach (None
        # at browser level). The new child session id is in params.
        del sid
        new_sid = params.get("sessionId")
        info = params.get("targetInfo") or {}
        if not new_sid or info.get("type") not in ("page", "iframe"):
            return
        self.sessions[new_sid] = self._new_session_state(info)
        self.log.info("tab attached: %s (%s) — now tracking %d tab(s)",
                      info.get("title") or "?",
                      info.get("url") or "?",
                      self._page_session_count())
        try:
            self.call("Network.enable", sid=new_sid)
        except (RuntimeError, ConnectionError, TimeoutError) as e:
            self.log.warning("Network.enable failed for session %s: %s",
                             new_sid[:8], e)

    def on_target_detached(self, params: dict, sid: Optional[str]) -> None:
        del sid
        gone = params.get("sessionId")
        st = self.sessions.pop(gone, None) if gone else None
        if st:
            self.log.info("tab detached: %s — still tracking %d tab(s)",
                          st.get("url") or "?",
                          self._page_session_count())

    # -- HTTP event handlers ---------------------------------------------

    def on_request(self, params: dict, sid: Optional[str]) -> None:
        rid = params.get("requestId")
        st = self.sessions.get(sid)
        if st is None or not rid:
            return
        req = params.get("request", {}) or {}
        st["http_pending"][rid] = {
            "method": req.get("method", "GET"),
            "url": req.get("url", ""),
            "req_headers": req.get("headers", {}) or {},
            "req_body": req.get("postData", "") or "",
            "ts": params.get("timestamp", 0),
        }

    def on_response(self, params: dict, sid: Optional[str]) -> None:
        rid = params.get("requestId")
        st = self.sessions.get(sid)
        if st is None or not rid:
            return
        pending = st["http_pending"].get(rid)
        if pending is None:
            return
        resp = params.get("response", {}) or {}
        pending["status"] = resp.get("status")
        pending["resp_headers"] = resp.get("headers", {}) or {}
        pending["mime"] = resp.get("mimeType", "")

    def on_loaded(self, params: dict, sid: Optional[str]) -> None:
        rid = params.get("requestId")
        st = self.sessions.get(sid)
        if st is None or not rid:
            return
        pending = st["http_pending"].pop(rid, None)
        if pending is None or "status" not in pending:
            return
        body = ""
        try:
            body_resp = self.call(
                "Network.getResponseBody", {"requestId": rid},
                timeout=5, sid=sid)
            body = body_resp.get("body", "") or ""
            if body_resp.get("base64Encoded"):
                try:
                    body = base64.b64decode(body).decode(
                        "utf-8", errors="replace")
                except Exception:
                    body = ""
        except RuntimeError as e:
            # -32001 "Session with given id not found" is the close-during-
            # fetch race: Network.loadingFinished arrives just before
            # Target.detachedFromTarget, so by the time we ask for the body
            # Chrome has already torn the session down. The request /
            # response itself is still useful — ingest it without the body.
            msg = str(e)
            if "-32001" in msg or "Session with given id not found" in msg:
                self.log.debug(
                    "getResponseBody: tab closed before fetch (rid=%s)", rid)
            else:
                self.log.warning("getResponseBody failed for %s: %s", rid, e)
        except (ConnectionError, TimeoutError, OSError) as e:
            self.log.warning("getResponseBody failed for %s: %s", rid, e)

        host_label, path = self._split_url(pending["url"])
        req_headers = self._headers_to_lines(
            f"{pending['method']} {path} HTTP/1.1", pending["req_headers"])
        resp_headers = self._headers_to_lines(
            f"HTTP/1.1 {pending['status'] or 0}", pending["resp_headers"])
        self.tracker._ingest_http_message(
            seq=self._seq(), time=self._fmt_time(pending["ts"]),
            host_label=host_label, path=path,
            method=pending["method"], status=pending["status"],
            req_headers=req_headers, req_body=pending["req_body"] or "",
            resp_headers=resp_headers, resp_body=body,
            source_tag=self.source_tag,
        )

    def on_loading_failed(self, params: dict, sid: Optional[str]) -> None:
        rid = params.get("requestId")
        st = self.sessions.get(sid)
        if st is None or not rid:
            return
        st["http_pending"].pop(rid, None)

    # -- WebSocket event handlers ----------------------------------------

    def on_ws_created(self, params: dict, sid: Optional[str]) -> None:
        rid = params.get("requestId")
        st = self.sessions.get(sid)
        if st is None or not rid:
            return
        url = params.get("url", "")
        host_label, path = self._split_url(url)
        st["ws_sessions"][rid] = {
            "url": url, "host_label": host_label, "path": path,
            "ws_session_id": f"cdp:{rid}",
        }

    def on_ws_handshake_response(self, params: dict,
                                 sid: Optional[str]) -> None:
        rid = params.get("requestId")
        st = self.sessions.get(sid)
        sess = st["ws_sessions"].get(rid) if (st and rid) else None
        if sess is None:
            return
        # Synthesize an HTTP "upgrade" event so the dashboard sees the
        # handshake (and any tokens it carried).
        resp = params.get("response", {}) or {}
        host_label, path = sess["host_label"], sess["path"]
        req_headers = self._headers_to_lines(
            f"GET {path} HTTP/1.1",
            params.get("request", {}).get("headers", {}) or {})
        resp_headers = self._headers_to_lines(
            f"HTTP/1.1 {resp.get('status') or 101}",
            resp.get("headers", {}) or {})
        self.tracker._ingest_http_message(
            seq=self._seq(), time=self._fmt_time(params.get("timestamp", 0)),
            host_label=host_label, path=path,
            method="GET", status=resp.get("status"),
            req_headers=req_headers, req_body="",
            resp_headers=resp_headers, resp_body="",
            source_tag=self.source_tag,
        )

    def _on_ws_frame(self, direction: str, params: dict,
                     sid: Optional[str]) -> None:
        rid = params.get("requestId")
        st = self.sessions.get(sid)
        sess = st["ws_sessions"].get(rid) if (st and rid) else None
        if sess is None:
            return
        resp = params.get("response", {}) or {}
        opcode = resp.get("opcode")
        if opcode not in (1, 2):  # ignore control frames
            return
        payload = resp.get("payloadData", "") or ""
        if opcode == 2:
            # binary — CDP sends it base64-encoded
            try:
                payload = base64.b64decode(payload).decode(
                    "utf-8", errors="replace")
            except Exception:
                return
        self.tracker.ingest_ws_frame(
            seq=self._seq(), time=self._fmt_time(params.get("timestamp", 0)),
            host_label=sess["host_label"], path=sess["path"],
            direction=direction, payload=payload,
            ws_session_id=sess["ws_session_id"],
            source_tag=self.source_tag,
        )

    def on_ws_frame_sent(self, params: dict, sid: Optional[str]) -> None:
        self._on_ws_frame("sent", params, sid)

    def on_ws_frame_received(self, params: dict,
                             sid: Optional[str]) -> None:
        self._on_ws_frame("received", params, sid)

    def on_ws_closed(self, params: dict, sid: Optional[str]) -> None:
        rid = params.get("requestId")
        st = self.sessions.get(sid)
        if st is None or not rid:
            return
        st["ws_sessions"].pop(rid, None)

    # -- main loop -------------------------------------------------------

    HANDLERS = {
        "Target.targetCreated": "on_target_created",
        "Target.attachedToTarget": "on_target_attached",
        "Target.detachedFromTarget": "on_target_detached",
        "Network.requestWillBeSent": "on_request",
        "Network.responseReceived": "on_response",
        "Network.loadingFinished": "on_loaded",
        "Network.loadingFailed": "on_loading_failed",
        "Network.webSocketCreated": "on_ws_created",
        "Network.webSocketHandshakeResponseReceived": "on_ws_handshake_response",
        "Network.webSocketFrameSent": "on_ws_frame_sent",
        "Network.webSocketFrameReceived": "on_ws_frame_received",
        "Network.webSocketClosed": "on_ws_closed",
    }

    def run_forever(self, *, on_batch=None,
                    flush_event_count: int = 25) -> None:
        """Pump CDP events. Calls ``on_batch`` after every
        ``flush_event_count`` events so callers can persist the tracker."""
        n = 0
        while True:
            try:
                ev = self.next_event()
            except (ConnectionError, OSError) as e:
                self.log.info("connection lost: %s", e)
                if on_batch:
                    on_batch()
                return
            if ev is None:
                if on_batch:
                    on_batch()
                return
            method = ev.get("method")
            sid = ev.get("sessionId")
            params = ev.get("params", {}) or {}
            handler_name = self.HANDLERS.get(method)
            if handler_name:
                try:
                    getattr(self, handler_name)(params, sid)
                except Exception as e:
                    self.log.warning("handler %s raised: %s", method, e)
                n += 1
                if n >= flush_event_count and on_batch:
                    on_batch()
                    n = 0


def find_chrome() -> Optional[str]:
    """Locate a Chromium-family browser binary on this machine.

    Returns the first match from a platform-appropriate candidate list,
    or None if nothing was found.
    """
    candidates: list[Path] = []
    if sys.platform == "win32":
        for env_var in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
            base = os.environ.get(env_var)
            if not base:
                continue
            candidates += [
                Path(base) / "Google/Chrome/Application/chrome.exe",
                Path(base) / "Microsoft/Edge/Application/msedge.exe",
                Path(base) / "Chromium/Application/chrome.exe",
            ]
    elif sys.platform == "darwin":
        candidates = [
            Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            Path("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
            Path("/Applications/Chromium.app/Contents/MacOS/Chromium"),
            Path("/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"),
        ]
    else:
        # POSIX-ish fallback: look in PATH for the common names.
        for name in ("google-chrome", "google-chrome-stable",
                     "chromium", "chromium-browser", "microsoft-edge",
                     "brave-browser"):
            path = shutil.which(name)
            if path:
                return path

    for p in candidates:
        if p.is_file():
            return str(p)
    return None


def launch_chrome(executable: str, port: int, *,
                  user_data_dir: Optional[Path] = None,
                  extra_args: Optional[list[str]] = None
                  ) -> tuple[subprocess.Popen, Path]:
    """Spawn ``executable`` with ``--remote-debugging-port=<port>`` and a
    fresh user-data-dir. Returns ``(process, profile_dir)``; the caller is
    responsible for terminating the process and (optionally) deleting the
    profile dir on shutdown.
    """
    if user_data_dir is None:
        user_data_dir = Path(tempfile.mkdtemp(prefix="btt-cdp-profile-"))
    cmd = [
        executable,
        f"--remote-debugging-port={port}",
        f"--user-data-dir={user_data_dir}",
        "--no-first-run",
        "--no-default-browser-check",
        # Stop Chrome from holding stdout/stderr open after we exit.
        "--disable-features=Translate",
    ]
    if extra_args:
        cmd.extend(extra_args)
    # Use DETACHED_PROCESS on Windows so Ctrl-C in our terminal doesn't
    # also kill the browser before we get to flush.
    creationflags = 0
    if sys.platform == "win32":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=creationflags,
    )
    return proc, user_data_dir


def wait_for_cdp_endpoint(host: str, port: int, *,
                          timeout: float = 15.0) -> bool:
    """Poll ``GET /json/version`` until it succeeds or ``timeout`` runs
    out. Returns True if the endpoint responded."""
    deadline = _time.time() + timeout
    url = f"http://{host}:{port}/json/version"
    while _time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, OSError):
            pass
        _time.sleep(0.3)
    return False


def cmd_cdp(args: argparse.Namespace) -> int:
    """Live-attach to a running Chrome/Edge instance and stream Network
    events into the database. Press Ctrl-C to stop."""
    db_path = Path(args.output).expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    source_tag = args.source_tag or f"cdp:{args.host}:{args.port}"
    tracker = Tracker(source_tag=source_tag)

    # --launch-chrome [PATH] — auto-detect or use the explicit path.
    chrome_proc: Optional[subprocess.Popen] = None
    chrome_profile: Optional[Path] = None
    chrome_arg = getattr(args, "launch_chrome", None)
    if chrome_arg is not None:
        executable: Optional[str]
        if chrome_arg in ("", "auto"):
            executable = find_chrome()
            if not executable:
                print("error: --launch-chrome requested but no Chrome / Edge "
                      "/ Chromium / Brave executable was found on this "
                      "machine.\n"
                      "       pass an explicit path:\n"
                      "         --launch-chrome /path/to/chrome",
                      file=sys.stderr)
                return 2
        else:
            executable = chrome_arg
            if not Path(executable).is_file():
                print(f"error: --launch-chrome path not found: {executable}",
                      file=sys.stderr)
                return 2
        try:
            chrome_proc, chrome_profile = launch_chrome(executable, args.port)
        except OSError as e:
            print(f"error: failed to launch {executable}: {e}",
                  file=sys.stderr)
            return 2
        _log_cdp.info("launched %s (pid %d) with profile %s",
                      Path(executable).name, chrome_proc.pid, chrome_profile)
        if not wait_for_cdp_endpoint(args.host, args.port, timeout=15):
            print("error: launched Chrome but its DevTools endpoint at "
                  f"{args.host}:{args.port} never came up within 15 s.\n"
                  "       check the Chrome window: did it crash, prompt for "
                  "an account picker, or refuse the flag because another "
                  "Chrome was already using the same user-data-dir?",
                  file=sys.stderr)
            chrome_proc.terminate()
            return 2

    enricher = _build_enricher(args)

    cdp = CDPClient(tracker, host=args.host, port=args.port,
                    target_id=args.target, source_tag=source_tag)
    try:
        cdp.attach()
    except urllib.error.URLError as e:
        print(f"error: cannot reach Chrome's DevTools endpoint at "
              f"{args.host}:{args.port} ({e}).\n"
              "       likely causes:\n"
              "         - Chrome isn't running, or wasn't started with "
              "--remote-debugging-port\n"
              "         - the running Chrome is using a different "
              "user-data-dir\n"
              "         - the port number doesn't match Chrome's flag\n"
              "       quick check:\n"
              f"         curl http://{args.host}:{args.port}/json/version\n"
              "       to start Chrome cleanly:\n"
              f'         chrome --remote-debugging-port={args.port} '
              "--user-data-dir=/tmp/cdp-profile",
              file=sys.stderr)
        return 2
    except SystemExit:
        # CDPClient.attach() raises SystemExit with its own diagnostic
        # (no targets, target id not found, no webSocketDebuggerUrl, …).
        # Let it propagate so the user sees that exact message.
        raise
    except (ConnectionError, OSError) as e:
        print(f"error: CDP WebSocket attach failed: "
              f"{type(e).__name__}: {e}\n"
              "       Chrome accepted the HTTP request but the WebSocket "
              "upgrade failed.\n"
              "       likely causes:\n"
              "         - another debugger (DevTools window?) is already "
              "attached to this target — close it and retry\n"
              "         - the target was closed between /json/list and the "
              "WebSocket connect\n"
              "         - a firewall is dropping the upgrade",
              file=sys.stderr)
        return 2

    is_first_flush = not args.append and not db_path.exists()
    flush_state = {"first": is_first_flush, "tokens": 0,
                   "events": 0, "exchanges": 0}
    redact_fields = parse_redact_arg(getattr(args, "redact_claims", None))
    store_tokens = bool(getattr(args, "store_tokens", False))
    if store_tokens:
        _log_cdp.warning(
            "--store-tokens: full token strings will be written to %s on "
            "every flush.", db_path)

    def flush() -> None:
        if (not tracker.tokens and not tracker.events
                and not tracker.exchanges and not tracker.hosts):
            return
        if redact_fields:
            apply_redaction(tracker, redact_fields)
        if enricher and enricher.available:
            for tok in tracker.tokens.values():
                if tok.app_info is None and tok.resource_info is None:
                    enrich_token(tok, enricher)
        ingest_to_db(
            tracker, db_path,
            source=f"cdp://{args.host}:{args.port}",
            enricher=enricher,
            append=not flush_state["first"] or args.append,
            source_tag=source_tag,
            store_tokens=store_tokens,
        )
        flush_state["first"] = False
        flush_state["tokens"] += len(tracker.tokens)
        flush_state["events"] += len(tracker.events)
        flush_state["exchanges"] += len(tracker.exchanges)
        # Reset the in-memory buffer; the DB has the cumulative state.
        tracker.tokens.clear()
        tracker.events.clear()
        tracker.exchanges.clear()
        tracker.hosts.clear()
        _log_cdp.info("flushed batch (cumulative: tokens+=%d, events+=%d, "
                      "exchanges+=%d)",
                      flush_state["tokens"], flush_state["events"],
                      flush_state["exchanges"])

    _log_cdp.info("writing to %s; press Ctrl-C to stop", db_path)
    if not args.no_serve_hint:
        _log_cdp.info("in another terminal: python %s serve %s",
                      Path(sys.argv[0]).name, db_path)

    try:
        cdp.run_forever(on_batch=flush, flush_event_count=args.flush_every)
    except KeyboardInterrupt:
        _log_cdp.info("stopping (Ctrl-C)")
    finally:
        flush()
        if cdp.ws:
            cdp.ws.close()
        if chrome_proc is not None:
            _log_cdp.info("terminating launched browser (pid %d)",
                          chrome_proc.pid)
            try:
                chrome_proc.terminate()
                chrome_proc.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError):
                chrome_proc.kill()
        if chrome_profile is not None:
            try:
                shutil.rmtree(chrome_profile, ignore_errors=True)
            except OSError as e:
                _log_cdp.warning("could not clean profile %s: %s",
                                 chrome_profile, e)
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    db_path = Path(args.db).expanduser()
    serve(db_path, args.host, args.port,
          open_browser=not args.no_browser)
    return 0


MAIN_EPILOG = """\
typical workflows
-----------------

  Ingest a Burp Suite XML export and open the dashboard:
    %(prog)s ingest engagement.xml -o tokens.db --enrich
    %(prog)s serve tokens.db

  Combine a Burp capture and a mitmproxy flow file in one DB:
    %(prog)s ingest engagement.xml -o tokens.db --enrich
    %(prog)s mitm chat-session.mitm -o tokens.db --enrich --append
    %(prog)s serve tokens.db

  Live capture from Chrome / Edge (sees TLS-decrypted HTTP and WebSocket
  frames without a proxy CA):
    chrome --remote-debugging-port=9222 --user-data-dir=/tmp/cdp-profile
    %(prog)s cdp -o tokens.db --enrich   # in another terminal
    %(prog)s serve tokens.db             # in a third

Run any subcommand with -h for its full options. See README.md for the
complete dashboard / detection feature list.
"""


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__.splitlines()[1],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=MAIN_EPILOG)
    p.add_argument("--version", action="version",
                   version=banner_text())
    verbosity = p.add_mutually_exclusive_group()
    verbosity.add_argument("-v", "--verbose", action="count", default=0,
                           help="Increase log volume. -v adds INFO, -vv "
                                "adds DEBUG. Without -v / -q the default "
                                "is INFO (status messages only).")
    verbosity.add_argument("-q", "--quiet", action="store_true",
                           help="Suppress INFO log lines; only WARNINGs "
                                "and ERRORs reach stderr. User-facing "
                                "error messages still print regardless.")
    sub = p.add_subparsers(dest="cmd", required=True,
                           metavar="{ingest,mitm,cdp,serve}")

    # ---- ingest ----------------------------------------------------------

    INGEST_EPILOG = """\
examples
--------
  # fresh DB with Microsoft enrichment
  %(prog)s burp.xml -o tokens.db --enrich

  # add a second Burp export to an existing DB without losing the first
  %(prog)s day2.xml -o tokens.db --append --source-tag burp:day2

  # offline run (no entrascopes.com fetch)
  %(prog)s burp.xml -o tokens.db

input format
------------
This subcommand reads Burp Suite's "Save items" XML export only. To
produce one, in Burp: Proxy > HTTP history > select items > right-click
> Save items.

Binary .burp project files are NOT supported (proprietary, unstable
across versions).
"""
    p_in = sub.add_parser(
        "ingest",
        help="parse a Burp XML export into a SQLite database",
        description="Parse a Burp Suite \"Save items\" XML export and write "
                    "the extracted tokens, events, and exchanges to a SQLite "
                    "database.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=INGEST_EPILOG)
    p_in.add_argument("input",
                      help="Path to a Burp 'Save items' XML export.")
    p_in.add_argument("-o", "--output", default="tokens.db",
                      help="Path of the SQLite database to write. Overwritten "
                           "if it already exists, unless --append is used. "
                           "Parent directories are created if needed. "
                           "Default: tokens.db")
    p_in.add_argument("--enrich", action="store_true",
                      help="Resolve Microsoft app and resource GUIDs against "
                           "https://entrascopes.com/ and store friendly names "
                           "and clickable links in the database. Makes one "
                           "outbound HTTP request on first run; results are "
                           "cached for 7 days. Skip if outbound HTTP is "
                           "disallowed in your environment.")
    p_in.add_argument("--enrich-cache-dir", default=None,
                      help="Directory for the entrascopes.com JSON cache. "
                           "Defaults (in order): $TATS_CACHE, "
                           "$XDG_CACHE_HOME/tats, "
                           "%%LOCALAPPDATA%%/tats/cache, "
                           "~/.cache/tats. The legacy "
                           "$BURP_TOKEN_TRACKER_CACHE env var is still "
                           "honored as a one-release migration nicety.")
    p_in.add_argument("--no-enrich-cache", action="store_true",
                      help="Always re-fetch entrascopes.com data even if a "
                           "fresh cache exists. Useful right after the "
                           "upstream dataset is updated.")
    p_in.add_argument("--no-serve-hint", action="store_true",
                      help="Suppress the 'launch the web UI with…' hint "
                           "printed after a successful ingest.")
    p_in.add_argument("--append", action="store_true",
                      help="Merge into an existing DB instead of overwriting "
                           "it. Tokens are upserted (uses count and observed "
                           "lifetime accumulate; source_tag becomes a "
                           "comma-separated list of every pass that's seen "
                           "the row); events and exchanges are appended with "
                           "seq numbers offset past the existing max. Refuses "
                           "to merge across schema versions.")
    p_in.add_argument("--source-tag", default=None,
                      help="Label written to every row produced by this run. "
                           "Default: 'burp:<filename>'. Surfaces in the "
                           "dashboard's Sources card and is searchable via "
                           "the Tokens-tab free-text filter.")
    p_in.add_argument("--no-progress", action="store_true",
                      help="Disable the carriage-return progress indicator. "
                           "Auto-disabled on non-TTY stderr (CI logs, "
                           "redirected output).")
    p_in.add_argument("--redact-claims", nargs="?", const="", default=None,
                      metavar="CLAIM,CLAIM,...",
                      help="Replace listed JWT claim values with stable "
                           "<redacted:XXXXXXXX> tokens before writing them to "
                           "the database. Use without an argument to redact "
                           "the default set (sub, oid, upn, email, name, "
                           "unique_name, preferred_username, emails, mail, "
                           "ipaddr, given_name, family_name). The redaction "
                           "is content-stable: same value always maps to the "
                           "same placeholder, so dashboard grouping still "
                           "works.")
    p_in.add_argument("--store-tokens", action="store_true",
                      help="Persist the full raw token string to the DB so "
                           "the dashboard can offer copy / download / "
                           "replay-as-curl actions, ship roadtools-format "
                           "token caches (.roadtools_auth), pre-fill "
                           "roadtx / curl / Python / PowerShell command "
                           "previews, and /api/export can ship tokens to "
                           "downstream tools. Off by default — enabling it "
                           "turns the database into a wholesale credential. "
                           "Note: --redact-claims only redacts the decoded "
                           "claim view; raw tokens are stored verbatim.")
    p_in.set_defaults(func=cmd_ingest)

    # ---- mitm ------------------------------------------------------------

    MITM_EPILOG = """\
examples
--------
  # ingest a mitmproxy session that includes WebSocket frames
  %(prog)s session.mitm -o tokens.db --enrich

  # add it to an existing Burp-derived DB
  %(prog)s session.mitm -o tokens.db --append

requires
--------
The mitmproxy Python package: pip install mitmproxy

what gets captured
------------------
HTTP request/response (with bodies) and every WebSocket text/binary frame
inside flow.websocket.messages. Tokens found in frames generate events
with role ws-frame-sent / ws-frame-received and a ws_session_id that
groups all frames within one WebSocket connection.
"""
    p_mt = sub.add_parser(
        "mitm",
        help="parse a mitmproxy flow file (.mitm) into a SQLite database — "
             "captures HTTP and WebSocket frame payloads",
        description="Parse a mitmproxy '.mitm' flow file. Unlike Burp's XML "
                    "export, mitmproxy flow files preserve every WebSocket "
                    "frame payload, so this is the only file-based path that "
                    "captures tokens flowing through chat/signalling/etc.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=MITM_EPILOG)
    p_mt.add_argument("input",
                      help="Path to a mitmproxy '.mitm' flow file.")
    p_mt.add_argument("-o", "--output", default="tokens.db",
                      help="Path of the SQLite database to write. Same "
                           "semantics as 'ingest -o'. Default: tokens.db")
    p_mt.add_argument("--enrich", action="store_true",
                      help="Resolve Microsoft app and resource GUIDs against "
                           "https://entrascopes.com/. See 'ingest --help' for "
                           "cache details.")
    p_mt.add_argument("--enrich-cache-dir", default=None,
                      help="Directory for the entrascopes.com JSON cache "
                           "(see 'ingest --help' for default lookup order).")
    p_mt.add_argument("--no-enrich-cache", action="store_true",
                      help="Always re-fetch entrascopes.com data.")
    p_mt.add_argument("--no-serve-hint", action="store_true",
                      help="Suppress the post-ingest hint.")
    p_mt.add_argument("--append", action="store_true",
                      help="Merge into an existing DB. UPSERT for tokens, "
                           "INSERT for events/exchanges. See 'ingest --help'.")
    p_mt.add_argument("--source-tag", default=None,
                      help="Label for every row produced by this run "
                           "(default: 'mitm:<filename>').")
    p_mt.add_argument("--no-progress", action="store_true",
                      help="Disable the carriage-return progress indicator.")
    p_mt.add_argument("--redact-claims", nargs="?", const="", default=None,
                      metavar="CLAIM,CLAIM,...",
                      help="Redact listed JWT claim values at write time. "
                           "See 'ingest --help' for the default claim list.")
    p_mt.add_argument("--store-tokens", action="store_true",
                      help="Persist full raw token strings to the DB. See "
                           "'ingest --help' for the privacy implications.")
    p_mt.set_defaults(func=cmd_mitm)

    # ---- cdp -------------------------------------------------------------

    CDP_EPILOG = """\
preparing the browser
---------------------
Launch Chrome / Edge with a fresh user-data-dir so it doesn't reuse a
running profile (which would refuse the debug flag):

  Windows: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" \\
             --remote-debugging-port=9222 \\
             --user-data-dir="%%TEMP%%\\cdp-profile"

  macOS:   "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \\
             --remote-debugging-port=9222 \\
             --user-data-dir=/tmp/cdp-profile

  Linux:   google-chrome --remote-debugging-port=9222 \\
             --user-data-dir=/tmp/cdp-profile

Then list available targets (only needed if you want a single tab):
  curl http://127.0.0.1:9222/json/list

multi-tab tracking
------------------
By default this attaches at the *browser* level and tracks every tab that
exists when it starts AND every tab opened during the run (including
tabs spawned by window.open or Ctrl-click). All tabs share one
WebSocket via the CDP flat-protocol session multiplexer. Pass
``--target <id>`` to fall back to single-tab mode (the connection then
dies when that tab closes).

examples
--------
  # default: track every tab in the running Chrome instance
  %(prog)s -o tokens.db --enrich

  # pin to a specific tab (from /json/list) — single-tab mode
  %(prog)s -o tokens.db --target 4F2B1234ABCDEF...

  # snappier UI updates (default flushes every 25 events)
  %(prog)s -o tokens.db --flush-every 5

stopping
--------
Press Ctrl-C. The in-flight buffer is flushed to the DB before exit.
"""
    p_cd = sub.add_parser(
        "cdp",
        help="live-attach to Chrome / Edge via DevTools Protocol and stream "
             "HTTP + WebSocket traffic into the database in real time",
        description="Connect to a running Chrome/Edge instance via the "
                    "DevTools Protocol and stream HTTP requests/responses "
                    "(with bodies) and every WebSocket frame into the "
                    "database. By default tracks every existing tab AND "
                    "every tab opened during the run via browser-level "
                    "auto-attach. The dashboard's 5-second poll picks up "
                    "new tokens within seconds of the browser making the "
                    "request — no proxy CA needed.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=CDP_EPILOG)
    p_cd.add_argument("-o", "--output", default="tokens.db",
                      help="Path of the SQLite database to write to. Created "
                           "if missing; appended to if it already exists. "
                           "Default: tokens.db")
    p_cd.add_argument("--host", default="127.0.0.1",
                      help="Host where Chrome's --remote-debugging-port is "
                           "listening. Default: 127.0.0.1")
    p_cd.add_argument("--port", type=int, default=9222,
                      help="Chrome's --remote-debugging-port. Default: 9222.")
    p_cd.add_argument("--target", default=None,
                      help="Pin to a single target id (from /json/list) "
                           "instead of tracking every tab. The attach "
                           "ends when that tab closes. Default: track all "
                           "current and future tabs via browser-level "
                           "auto-attach.")
    p_cd.add_argument("--launch-chrome", nargs="?", const="auto", default=None,
                      metavar="PATH",
                      help="Launch Chrome / Edge / Chromium / Brave with "
                           "--remote-debugging-port and a fresh "
                           "user-data-dir, wait for the DevTools endpoint "
                           "to come up, then attach. Without an argument the "
                           "browser is auto-detected; pass an explicit "
                           "executable path to override. The launched "
                           "browser is terminated when this command exits, "
                           "and the temporary profile dir is deleted.")
    p_cd.add_argument("--flush-every", type=int, default=25,
                      help="Flush the in-memory buffer to the DB after this "
                           "many CDP events. Lower values reduce dashboard "
                           "latency at the cost of more DB writes. "
                           "Default: 25.")
    p_cd.add_argument("--enrich", action="store_true",
                      help="Resolve Microsoft app/resource GUIDs against "
                           "https://entrascopes.com/ on each flush.")
    p_cd.add_argument("--enrich-cache-dir", default=None,
                      help="Directory for the entrascopes.com JSON cache.")
    p_cd.add_argument("--no-enrich-cache", action="store_true",
                      help="Always re-fetch entrascopes.com data.")
    p_cd.add_argument("--no-serve-hint", action="store_true",
                      help="Suppress the 'in another terminal: serve…' hint.")
    p_cd.add_argument("--append", action="store_true",
                      help="Force append mode even if the DB doesn't exist. "
                           "Default: append if the file exists, replace "
                           "otherwise.")
    p_cd.add_argument("--source-tag", default=None,
                      help="Label for every row produced "
                           "(default: 'cdp:<host>:<port>').")
    p_cd.add_argument("--redact-claims", nargs="?", const="", default=None,
                      metavar="CLAIM,CLAIM,...",
                      help="Redact listed JWT claim values on each flush. "
                           "See 'ingest --help' for the default claim list.")
    p_cd.add_argument("--store-tokens", action="store_true",
                      help="Persist full raw token strings to the DB on "
                           "every flush. See 'ingest --help' for the "
                           "privacy implications.")
    p_cd.set_defaults(func=cmd_cdp)

    # ---- serve -----------------------------------------------------------

    SERVE_EPILOG = """\
examples
--------
  # default: localhost:8765, auto-opens a browser tab
  %(prog)s tokens.db

  # bind to a different port without auto-launching the browser
  %(prog)s tokens.db --port 9000 --no-browser

  # (trusted network only — no authentication)
  %(prog)s tokens.db --host 0.0.0.0

what's served
-------------
GET  /              the single-page dashboard
GET  /api/data      meta + hosts + tokens + exchanges + host_usage (full)
GET  /api/meta      tiny meta-only endpoint for the live-update poll
GET  /api/token/<fp>  token detail with full JWT, events, exchanges
GET  /api/graph     mermaid flowchart source (?highlight, ?isolate)
GET  /api/sequence  mermaid sequence source (?fp, ?highlight, ?max)
GET  /healthz       liveness probe

The server is read-only; running it alongside an in-flight 'cdp' or
'mitm' ingest is safe and is how live updates work.

security
--------
There is no authentication. Decoded JWT claim contents (oid, sub, upn,
email, tid, scope lists, etc.) are exposed to anyone who can reach the
bind address. Keep --host on 127.0.0.1 unless another auth layer
fronts the server.
"""
    p_sv = sub.add_parser(
        "serve",
        help="launch the web UI for an ingested database",
        description="Serve the read-only web dashboard for an existing "
                    "SQLite database produced by 'ingest', 'mitm', or 'cdp'. "
                    "Polls the database every 5 seconds and re-renders when "
                    "the underlying data changes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=SERVE_EPILOG)
    p_sv.add_argument("db",
                      help="Path to a SQLite database previously produced by "
                           "'ingest', 'mitm', or 'cdp'.")
    p_sv.add_argument("--host", default="127.0.0.1",
                      help="Bind address. Default: 127.0.0.1. Bind to "
                           "0.0.0.0 only on a trusted network — there is no "
                           "authentication.")
    p_sv.add_argument("--port", type=int, default=8765,
                      help="Bind port. Default: 8765.")
    p_sv.add_argument("--no-browser", action="store_true",
                      help="Do not auto-open a browser tab on startup.")
    p_sv.set_defaults(func=cmd_serve)

    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    setup_logging(verbose=getattr(args, "verbose", 0),
                  quiet=getattr(args, "quiet", False))
    return args.func(args)


def main_cli() -> None:
    """Console-script entry point used by ``pyproject.toml``.

    Wraps :func:`main` so the ``tats`` script in site-packages can be a
    zero-arg callable.
    """
    sys.exit(main(sys.argv[1:]))


if __name__ == "__main__":
    main_cli()
