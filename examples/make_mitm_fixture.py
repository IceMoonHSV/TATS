"""Generate a small synthetic mitmproxy flow file to smoke-test
``python -m tats mitm``.

Produces two flows:
  1. POST https://idp.example.com/oauth/token (password grant) issuing
     access / refresh / id tokens — exercises the HTTP token extractor.
  2. GET wss://chat.example.com/ws/notify with a follow-up WebSocket
     message that carries an access_token in JSON — exercises the
     WebSocket frame ingest path.
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import mitmproxy.io as mio
from mitmproxy import http
from mitmproxy.http import Headers
from mitmproxy.test import tflow

DEST = Path(sys.argv[1] if len(sys.argv) > 1 else "fixture.mitm").expanduser()


def fake_jwt(payload: dict) -> str:
    def b64u(obj):
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    h = b64u({"alg": "RS256", "typ": "JWT"})
    p = b64u(payload)
    return f"{h}.{p}.{'s' * 32}"


AT = fake_jwt({
    "iss": "https://idp.example.com", "sub": "alice@example.com",
    "upn": "alice@example.com", "aud": "https://api.example.com",
    "scope": "read write", "exp": 1900000000,
})
RT = "0.AR" + "X" * 80
IDT = fake_jwt({
    "iss": "https://idp.example.com", "sub": "alice@example.com",
    "preferred_username": "alice@example.com",
    "aud": "client-abc", "exp": 1900000000,
})
WS_AT = fake_jwt({
    "iss": "https://chat.example.com",
    "aud": "https://chat.example.com",
    "sub": "alice@example.com", "scope": "chat.read", "exp": 1900000500,
})


def http_flow():
    f = tflow.tflow(resp=True)
    f.request.method = "POST"
    f.request.scheme = "https"
    f.request.host = "idp.example.com"
    f.request.port = 443
    f.request.path = "/oauth/token"
    f.request.headers = Headers(
        [(b"Host", b"idp.example.com"),
         (b"Content-Type", b"application/x-www-form-urlencoded")])
    body = "grant_type=password&username=alice&password=hunter2&client_id=web-app"
    f.request.content = body.encode("utf-8")
    f.response.status_code = 200
    f.response.headers = Headers(
        [(b"Content-Type", b"application/json")])
    resp_body = json.dumps({
        "access_token": AT, "refresh_token": RT, "id_token": IDT,
        "token_type": "Bearer", "expires_in": 3600,
    })
    f.response.content = resp_body.encode("utf-8")
    f.request.timestamp_start = 1900000000.0
    f.response.timestamp_start = 1900000001.0
    return f


def ws_flow():
    f = tflow.twebsocketflow()
    f.request.scheme = "https"
    f.request.host = "chat.example.com"
    f.request.port = 443
    f.request.path = "/ws/notify"
    f.request.headers = Headers(
        [(b"Host", b"chat.example.com"),
         (b"Upgrade", b"websocket"),
         (b"Connection", b"Upgrade")])
    f.request.timestamp_start = 1900000100.0
    f.response.status_code = 101
    f.response.timestamp_start = 1900000100.5
    # Replace canned messages with our own
    from mitmproxy.websocket import WebSocketMessage
    auth_msg = WebSocketMessage(
        type=1, from_client=True,
        content=json.dumps({"action": "auth",
                            "access_token": WS_AT}).encode("utf-8"),
        timestamp=1900000101.0,
    )
    server_ack = WebSocketMessage(
        type=1, from_client=False,
        content=json.dumps({"action": "ack",
                            "user": "alice@example.com"}).encode("utf-8"),
        timestamp=1900000101.5,
    )
    f.websocket.messages = [auth_msg, server_ack]
    return f


def main():
    flows = [http_flow(), ws_flow()]
    with DEST.open("wb") as out:
        writer = mio.FlowWriter(out)
        for f in flows:
            writer.add(f)
    print(f"wrote {DEST} ({len(flows)} flows)")


if __name__ == "__main__":
    main()
