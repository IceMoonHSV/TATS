"""Unit tests for the token extraction primitives.

These exercise pure functions — no DB writes, no fixture files — so they
can run in milliseconds and surface regressions in detection logic
without any external setup.
"""
from __future__ import annotations

import base64
import json

import pytest

import tats as btt


def _b64u(obj: dict) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(obj, separators=(",", ":")).encode("utf-8")
    ).decode("ascii").rstrip("=")


def _make_jwt(payload: dict, header: dict | None = None) -> str:
    h = _b64u(header or {"alg": "RS256", "typ": "JWT"})
    p = _b64u(payload)
    return f"{h}.{p}.{'s' * 32}"


# ---- JWT parsing -----------------------------------------------------------

class TestParseJwt:
    def test_valid_jwt_returns_header_and_payload(self):
        token = _make_jwt({"sub": "alice", "exp": 1900000000})
        out = btt.parse_jwt(token)
        assert out is not None
        assert out["payload"]["sub"] == "alice"
        assert out["header"]["alg"] == "RS256"

    def test_non_jwt_string_returns_none(self):
        assert btt.parse_jwt("not.a.jwt") is None
        # "eyJ" decodes to "{" — incomplete JSON, so parse_jwt returns None.
        assert btt.parse_jwt("eyJ.eyJ") is None
        assert btt.parse_jwt("") is None

    def test_jwt_without_payload_returns_none(self):
        # Header-only token (no payload segment) should fail the parse.
        h = _b64u({"alg": "none"})
        assert btt.parse_jwt(h) is None


# ---- token-shape heuristic ------------------------------------------------

class TestIsTokenish:
    def test_short_strings_rejected(self):
        assert not btt.is_tokenish("")
        assert not btt.is_tokenish("short")
        assert not btt.is_tokenish("a" * 15)  # below the 16-char floor

    def test_long_url_safe_strings_accepted(self):
        assert btt.is_tokenish("a" * 24)
        assert btt.is_tokenish("0.AR" + "X" * 80)  # MS opaque RT shape

    def test_jwt_shape_accepted_unconditionally(self):
        token = _make_jwt({"x": 1})
        assert btt.is_tokenish(token)

    def test_strings_with_spaces_rejected(self):
        # A 22-char string with a space isn't URL-safe.
        assert not btt.is_tokenish("hello world hello world!")


# ---- cookie-name classifier (regression test for ESTSAUTH bug) ------------

class TestCookieTypeHint:
    def test_refresh_token_substring_wins(self):
        assert btt.cookie_type_hint("my_refresh_token") == "refresh"

    def test_session_substring_maps_to_access(self):
        assert btt.cookie_type_hint("session_id") == "access"

    @pytest.mark.parametrize("name", [
        "ESTSAUTH",
        "ESTSAUTHPERSISTENT",
        "ESTSAUTHLIGHT",
        "estsauth",
        "estsAuthPersistent",   # mixed case
        "SignInStateCookie",
    ])
    def test_microsoft_session_cookies_classified_as_refresh(self, name):
        # Regression: previously these were misclassified as 'access'
        # because of the generic 'auth' substring rule.
        assert btt.cookie_type_hint(name) == "refresh"

    def test_unknown_cookie_returns_none(self):
        assert btt.cookie_type_hint("MUIDB") is None
        assert btt.cookie_type_hint("buid") is None
        assert btt.cookie_type_hint("fpc") is None


# ---- token-endpoint matcher -----------------------------------------------

class TestIsTokenEndpoint:
    @pytest.mark.parametrize("path", [
        "/oauth/token",
        "/oauth2/v2.0/token",
        "/connect/token",
        "/auth/refresh",
        "/common/oauth2/token",
        "/12345678-1234-1234-1234-123456789abc/oauth2/v2.0/token",
    ])
    def test_known_token_endpoints_match(self, path):
        assert btt.is_token_endpoint(path)

    @pytest.mark.parametrize("path", [
        "/api/users",
        "/me",
        "/v1/orders",
    ])
    def test_unrelated_paths_dont_match(self, path):
        assert not btt.is_token_endpoint(path)


# ---- FOCI detection -------------------------------------------------------

class TestDetectFoci:
    def test_foci_field_in_response(self):
        assert btt.detect_foci({"foci": "1", "access_token": "..."}) == "1"

    def test_no_foci_field(self):
        assert btt.detect_foci({"access_token": "..."}) is None

    def test_non_dict_input(self):
        assert btt.detect_foci(None) is None
        assert btt.detect_foci("not a dict") is None  # type: ignore[arg-type]


# ---- BroCI / NAA detection ------------------------------------------------

class TestDetectBroci:
    def test_brk_client_id_alone_triggers(self):
        info = btt.detect_broci({
            "grant_type": "refresh_token",
            "client_id": "nested-app-id",
            "brk_client_id": "broker-app-id",
        })
        assert info is not None
        assert info["broker_client_id"] == "broker-app-id"
        assert info["nested_client_id"] == "nested-app-id"
        assert "brk_client_id" in info["evidence"]

    def test_brk_redirect_scheme_triggers(self):
        info = btt.detect_broci({
            "client_id": "nested",
            "redirect_uri":
                "brk-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee://portal.azure.com",
        })
        assert info is not None
        assert info["broker_client_id"].lower() == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    def test_no_broci_markers_returns_none(self):
        assert btt.detect_broci({
            "grant_type": "refresh_token",
            "client_id": "regular-app",
        }) is None


# ---- claim summary --------------------------------------------------------

class TestClaimSummary:
    def test_includes_known_claims(self):
        s = btt.claim_summary({"iss": "x", "aud": "y", "scp": "User.Read"})
        assert "iss=x" in s and "aud=y" in s and "scp=User.Read" in s

    def test_brk_claims_included_even_if_not_in_curated_list(self):
        s = btt.claim_summary({"iss": "x", "brk_brokerid": "b"})
        assert "brk_brokerid=b" in s

    def test_empty_payload_returns_empty_string(self):
        assert btt.claim_summary(None) == ""
        assert btt.claim_summary({}) == ""


# ---- security feature detection -------------------------------------------

class TestDeriveSecurityFeatures:
    def test_none_input_returns_none(self):
        assert btt.derive_security_features(None) is None
        assert btt.derive_security_features("not a dict") is None  # type: ignore[arg-type]

    def test_payload_with_no_security_claims_returns_none(self):
        # A plain access token without CAE / PoP / acr / amr markers.
        assert btt.derive_security_features({"aud": "x", "exp": 1}) is None

    def test_cae_capable_client_detected(self):
        assert btt.derive_security_features({"xms_cc": ["CP1"]}) == {"cae": True}
        # also accept the legacy string-only shape
        assert btt.derive_security_features({"xms_cc": "CP1"}) == {"cae": True}

    def test_other_xms_cc_values_dont_trigger_cae(self):
        out = btt.derive_security_features({"xms_cc": ["FOO"]})
        assert out is None

    def test_pop_detection_with_kid(self):
        out = btt.derive_security_features({"cnf": {"kid": "AbCdEf"}})
        assert out == {"pop": True, "pop_kid": "AbCdEf"}

    def test_acr_acrs_amr_collected(self):
        out = btt.derive_security_features({
            "acr": "1",
            "acrs": ["urn:foo", "urn:bar"],
            "amr": ["pwd", "mfa"],
        })
        assert out == {
            "acr": "1",
            "acrs": ["urn:foo", "urn:bar"],
            "amr": ["pwd", "mfa"],
        }

    def test_security_features_text_is_stable_json(self):
        # The DB-bound serialiser must be deterministic so UPSERTs
        # don't churn on insertion order.
        payload = {"xms_cc": ["CP1"], "acr": "c1", "amr": ["mfa"]}
        a = btt.security_features_text(payload)
        b = btt.security_features_text(payload)
        assert a == b
        assert a.startswith("{")
        assert "cae" in a and "acr" in a and "amr" in a


# ---- token-facts facade ---------------------------------------------------

class TestDeriveTokenFacts:
    def test_aggregates_every_derived_field(self):
        payload = {
            "iss": "https://sts.windows.net/x/",
            "aud": "y", "scp": "User.Read",
            "tid": "11111111-1111-1111-1111-111111111111",
            "upn": "alice@example.com",
            "exp": 1900000000,
            "xms_cc": ["CP1"], "acr": "c1",
        }
        f = btt.derive_token_facts(payload)
        assert f.user_identity == "alice@example.com"
        assert f.exp_unix == 1900000000
        assert f.tenant_id == "11111111-1111-1111-1111-111111111111"
        assert f.scopes_text == "User.Read"
        assert "cae" in (f.security_features_text or "")
        assert "iss=" in f.claim_summary and "scp=User.Read" in f.claim_summary

    def test_empty_payload_returns_safe_defaults(self):
        f = btt.derive_token_facts(None)
        assert f.user_identity is None
        assert f.exp_unix is None
        assert f.tenant_id is None
        assert f.scopes_text is None
        assert f.security_features_text is None
        assert f.claim_summary == ""
