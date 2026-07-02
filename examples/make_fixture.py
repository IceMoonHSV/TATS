"""Generate a tiny synthetic Burp 'Save items' XML for smoke-testing."""

from __future__ import annotations

import base64
import json
from xml.sax.saxutils import escape


def b64(blob: str) -> str:
    return base64.b64encode(blob.encode("utf-8")).decode("ascii")


# Fake JWTs: header.payload.sig — all b64url, payloads have iss/sub/aud/exp.
def jwt(payload: dict) -> str:
    def enc(obj: dict) -> str:
        return base64.urlsafe_b64encode(
            json.dumps(obj, separators=(",", ":")).encode("utf-8")
        ).decode("ascii").rstrip("=")
    header = enc({"alg": "RS256", "typ": "JWT"})
    body = enc(payload)
    sig = "s" * 32
    return f"{header}.{body}.{sig}"


import time as _ftime0
_NOW0 = int(_ftime0.time())
AT1 = jwt({"iss": "https://idp.example.com", "sub": "user-42",
           "upn": "user-42@example.com",
           "aud": "api.example.com", "scope": "read",
           "exp": _NOW0 - 600})              # already expired
RT1 = "r1_" + "a" * 40
AT2 = jwt({"iss": "https://idp.example.com", "sub": "user-42",
           "upn": "user-42@example.com",
           "aud": "api.example.com", "scope": "read",
           "exp": _NOW0 + 1800})             # ~30 minutes valid
RT2 = "r2_" + "b" * 40
IDT1 = jwt({"iss": "https://idp.example.com", "sub": "user-42",
            "preferred_username": "user-42@example.com",
            "name": "User Forty-Two",
            "aud": "client-abc",
            "exp": _NOW0 + 900})             # ~15 minutes valid


def item(time, host, method, path, request, response, status=200, port="443"):
    return f"""  <item>
    <time>{escape(time)}</time>
    <url>https://{host}{path}</url>
    <host ip=\"1.2.3.4\">{host}</host>
    <port>{port}</port>
    <protocol>https</protocol>
    <method>{method}</method>
    <path>{escape(path)}</path>
    <extension>null</extension>
    <request base64=\"true\">{b64(request)}</request>
    <status>{status}</status>
    <responselength>{len(response)}</responselength>
    <mimetype>JSON</mimetype>
    <response base64=\"true\">{b64(response)}</response>
    <comment></comment>
  </item>"""


# 1) Token issuance: POST /oauth/token (password grant) -> access + refresh + id
req1 = (
    "POST /oauth/token HTTP/1.1\r\n"
    "Host: idp.example.com\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 99\r\n"
    "\r\n"
    "grant_type=password&username=alice&password=hunter2&client_id=web-app"
)
resp1_body = json.dumps({
    "access_token": AT1, "refresh_token": RT1, "id_token": IDT1,
    "token_type": "Bearer", "expires_in": 3600,
})
resp1 = (
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: application/json\r\n"
    f"Content-Length: {len(resp1_body)}\r\n"
    "\r\n" + resp1_body
)

# 2) Use AT1 against api.example.com
req2 = (
    "GET /v1/me HTTP/1.1\r\n"
    "Host: api.example.com\r\n"
    f"Authorization: Bearer {AT1}\r\n"
    "\r\n"
)
resp2 = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":\"user-42\"}"

# 3) Use AT1 against api.example.com again (second endpoint)
req3 = (
    "GET /v1/orders HTTP/1.1\r\n"
    "Host: api.example.com\r\n"
    f"Authorization: Bearer {AT1}\r\n"
    "\r\n"
)
resp3 = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"orders\":[]}"

# 4) Refresh exchange: RT1 -> AT2 + RT2 (rotating refresh)
req4 = (
    "POST /oauth/token HTTP/1.1\r\n"
    "Host: idp.example.com\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "\r\n"
    f"grant_type=refresh_token&refresh_token={RT1}&client_id=web-app"
)
resp4_body = json.dumps({
    "access_token": AT2, "refresh_token": RT2,
    "token_type": "Bearer", "expires_in": 3600,
})
resp4 = (
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: application/json\r\n\r\n" + resp4_body
)

# 5) AT2 now used against api.example.com
req5 = (
    "GET /v1/me HTTP/1.1\r\n"
    "Host: api.example.com\r\n"
    f"Authorization: Bearer {AT2}\r\n"
    "\r\n"
)
resp5 = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":\"user-42\"}"

# 6) AT2 leaking to an unexpected third-party host in a cookie
req6 = (
    "GET /pixel.gif HTTP/1.1\r\n"
    "Host: analytics.example.net\r\n"
    f"Cookie: access_token={AT2}; sid=xyz\r\n"
    "\r\n"
)
resp6 = "HTTP/1.1 204 No Content\r\n\r\n"


# Microsoft / Entra ID flows for FOCI + BroCI detection -------------------

TENANT = "6c12b0b0-b2cc-4a73-8252-0b94bfca2145"
# Family-1 (FOCI) client IDs from the Secureworks research.
TEAMS_CLIENT_ID = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"   # Microsoft Teams
AZCLI_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"   # Azure CLI
# BroCI example: Azure Portal (broker) hosting ADIbizaUX (nested).
PORTAL_CLIENT_ID = "c44b4083-3bb0-49c1-b47d-974e53cbdf3c"  # Azure Portal
ADIBIZAUX_CLIENT_ID = "74658136-14ec-4630-ad9b-26e160ff0fc6"  # ADIbizaUX


import time as _ftime
# Use realistic exp values relative to "now" so the dashboard's
# valid-vs-expired counts are meaningful when the fixture is rebuilt.
_NOW = int(_ftime.time())
EXP_TEAMS_AT      = _NOW + 3600          # ~1 hour out (typical access token)
EXP_AZCLI_AT      = _NOW + 3500
EXP_ADIBIZAUX_AT  = _NOW + 3300
EXP_AT1           = _NOW - 600           # already expired (legacy idp.example)
EXP_AT2           = _NOW + 1800
EXP_IDT1          = _NOW + 900

MS_AT_TEAMS = jwt({
    "iss": f"https://sts.windows.net/{TENANT}/",
    "aud": "https://graph.microsoft.com",
    "appid": TEAMS_CLIENT_ID,
    "azp": TEAMS_CLIENT_ID,
    "tid": TENANT,
    "oid": "aaaaaaaa-1111-2222-3333-444444444444",
    "sub": "F-TeamsSubject",
    "upn": "alice@contoso.com",
    "name": "Alice Example",
    "preferred_username": "alice@contoso.com",
    "unique_name": "alice@contoso.com",
    "scp": "User.Read Mail.Read offline_access openid profile",
    "exp": EXP_TEAMS_AT,
})
MS_RT_FAMILY1 = "0.AR" + "A" * 120    # opaque, looks like Entra RT
MS_AT_AZCLI = jwt({
    "iss": f"https://sts.windows.net/{TENANT}/",
    "aud": "https://management.core.windows.net/",
    "appid": AZCLI_CLIENT_ID,
    "azp": AZCLI_CLIENT_ID,
    "tid": TENANT,
    "oid": "aaaaaaaa-1111-2222-3333-444444444444",
    "sub": "F-AzCliSubject",
    "upn": "alice@contoso.com",
    "name": "Alice Example",
    "preferred_username": "alice@contoso.com",
    "unique_name": "alice@contoso.com",
    "scp": "user_impersonation",
    "exp": EXP_AZCLI_AT,
})
MS_RT_FAMILY1_NEW = "0.AR" + "B" * 120

MS_AT_ADIBIZAUX = jwt({
    "iss": f"https://sts.windows.net/{TENANT}/",
    "aud": "https://management.azure.com",
    "appid": ADIBIZAUX_CLIENT_ID,
    "azp": ADIBIZAUX_CLIENT_ID,
    "tid": TENANT,
    "oid": "aaaaaaaa-1111-2222-3333-444444444444",
    "sub": "BroCI-NestedSubject",
    "upn": "alice@contoso.com",
    "name": "Alice Example",
    "preferred_username": "alice@contoso.com",
    "unique_name": "alice@contoso.com",
    "scp": "user_impersonation",
    "exp": EXP_ADIBIZAUX_AT,
})
MS_RT_BROCI = "0.AR" + "C" * 120


# 7) FOCI issuance: Teams gets AT + foci-flagged RT for graph.microsoft.com
ms_token_path = f"/{TENANT}/oauth2/v2.0/token"
ms_host = "login.microsoftonline.com"

ms_req1_body = (
    f"client_id={TEAMS_CLIENT_ID}"
    "&grant_type=authorization_code"
    "&code=fakeauthcodefakeauthcode"
    "&scope=User.Read+Mail.Read+offline_access+openid+profile"
    "&redirect_uri=https%3A%2F%2Fteams.microsoft.com%2Fauth-callback"
)
ms_req1 = (
    f"POST {ms_token_path} HTTP/1.1\r\n"
    f"Host: {ms_host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    f"Content-Length: {len(ms_req1_body)}\r\n"
    "\r\n" + ms_req1_body
)
ms_resp1_body = json.dumps({
    "token_type": "Bearer", "scope": "User.Read Mail.Read openid profile",
    "expires_in": 3599, "ext_expires_in": 3599,
    "access_token": MS_AT_TEAMS,
    "refresh_token": MS_RT_FAMILY1,
    "foci": "1",
    "client_info": "eyJ1aWQiOiJtb2NrLXVpZCJ9",
})
ms_resp1 = ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
            + ms_resp1_body)

# 8) FOCI cross-redemption: Azure CLI redeems the Teams refresh token for an
#    ARM access token (new RT is still foci:1).
ms_req2_body = (
    f"client_id={AZCLI_CLIENT_ID}"
    "&grant_type=refresh_token"
    f"&refresh_token={MS_RT_FAMILY1}"
    "&scope=https%3A%2F%2Fmanagement.core.windows.net%2F.default+offline_access"
    "&redirect_uri=http%3A%2F%2Flocalhost"
)
ms_req2 = (
    f"POST {ms_token_path} HTTP/1.1\r\n"
    f"Host: {ms_host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    f"Content-Length: {len(ms_req2_body)}\r\n"
    "\r\n" + ms_req2_body
)
ms_resp2_body = json.dumps({
    "token_type": "Bearer",
    "scope": "https://management.core.windows.net/user_impersonation",
    "expires_in": 3599, "ext_expires_in": 3599,
    "access_token": MS_AT_AZCLI,
    "refresh_token": MS_RT_FAMILY1_NEW,
    "foci": "1",
})
ms_resp2 = ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
            + ms_resp2_body)

# 9) BroCI / NAA: Azure Portal (broker) mints a token for ADIbizaUX (nested).
ms_req3_body = (
    f"client_id={ADIBIZAUX_CLIENT_ID}"
    f"&redirect_uri=brk-{PORTAL_CLIENT_ID}%3A%2F%2Fportal.azure.com"
    "&scope=https%3A%2F%2Fmanagement.azure.com%2F.default"
    "&grant_type=refresh_token"
    f"&refresh_token={MS_RT_FAMILY1_NEW}"
    f"&brk_client_id={PORTAL_CLIENT_ID}"
    "&brk_redirect_uri=https%3A%2F%2Fportal.azure.com%2F"
)
ms_req3 = (
    f"POST {ms_token_path} HTTP/1.1\r\n"
    f"Host: {ms_host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    f"Content-Length: {len(ms_req3_body)}\r\n"
    "\r\n" + ms_req3_body
)
ms_resp3_body = json.dumps({
    "token_type": "Bearer",
    "scope": "https://management.azure.com/user_impersonation",
    "expires_in": 3599, "ext_expires_in": 3599,
    "access_token": MS_AT_ADIBIZAUX,
    "refresh_token": MS_RT_BROCI,
})
ms_resp3 = ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
            + ms_resp3_body)

# 10) Use the nested AT against ARM.
ms_req4 = (
    "GET /subscriptions?api-version=2022-12-01 HTTP/1.1\r\n"
    "Host: management.azure.com\r\n"
    f"Authorization: Bearer {MS_AT_ADIBIZAUX}\r\n"
    "\r\n"
)
ms_resp4 = ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
            "{\"value\":[]}")


xml = """<?xml version=\"1.0\"?>
<!DOCTYPE items>
<items burpVersion=\"2025.x\">
""" + "\n".join([
    item("Mon Apr 20 10:00:00 UTC 2026", "idp.example.com", "POST", "/oauth/token", req1, resp1),
    item("Mon Apr 20 10:00:01 UTC 2026", "api.example.com", "GET", "/v1/me", req2, resp2),
    item("Mon Apr 20 10:00:02 UTC 2026", "api.example.com", "GET", "/v1/orders", req3, resp3),
    item("Mon Apr 20 10:05:00 UTC 2026", "idp.example.com", "POST", "/oauth/token", req4, resp4),
    item("Mon Apr 20 10:05:01 UTC 2026", "api.example.com", "GET", "/v1/me", req5, resp5),
    item("Mon Apr 20 10:05:02 UTC 2026", "analytics.example.net", "GET", "/pixel.gif", req6, resp6, status=204),
    item("Mon Apr 20 11:00:00 UTC 2026", ms_host, "POST", ms_token_path, ms_req1, ms_resp1),
    item("Mon Apr 20 11:05:00 UTC 2026", ms_host, "POST", ms_token_path, ms_req2, ms_resp2),
    item("Mon Apr 20 11:10:00 UTC 2026", ms_host, "POST", ms_token_path, ms_req3, ms_resp3),
    item("Mon Apr 20 11:10:05 UTC 2026", "management.azure.com", "GET",
         "/subscriptions?api-version=2022-12-01", ms_req4, ms_resp4),
]) + "\n</items>\n"


if __name__ == "__main__":
    import pathlib, sys
    out = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "fixture.xml")
    out.write_text(xml, encoding="utf-8")
    print(f"wrote {out}")
