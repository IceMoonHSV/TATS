"""Unit tests for the PII redaction helpers."""
from __future__ import annotations

import tats as btt


class TestRedactValue:
    def test_strings_replaced_with_stable_placeholder(self):
        out = btt._redact_value("alice@contoso.com")
        assert out.startswith("<redacted:") and out.endswith(">")
        # Same value -> same placeholder (stable across calls).
        assert btt._redact_value("alice@contoso.com") == out

    def test_distinct_values_get_distinct_placeholders(self):
        a = btt._redact_value("alice@contoso.com")
        b = btt._redact_value("bob@contoso.com")
        assert a != b

    def test_numbers_and_bools_pass_through(self):
        assert btt._redact_value(42) == 42
        assert btt._redact_value(3.14) == 3.14
        assert btt._redact_value(True) is True
        assert btt._redact_value(None) is None

    def test_lists_walk_recursively(self):
        out = btt._redact_value(["alice@x", "bob@x"])
        assert isinstance(out, list)
        assert all(s.startswith("<redacted:") for s in out)
        # Same list element redacts to the same placeholder.
        assert out[0] == btt._redact_value("alice@x")

    def test_dicts_walk_recursively(self):
        out = btt._redact_value({"a": "alice", "n": 1})
        assert out["a"].startswith("<redacted:")
        assert out["n"] == 1


class TestRedactPayload:
    def test_only_listed_fields_redacted(self):
        payload = {"sub": "alice", "iss": "https://x", "aud": "api"}
        out = btt.redact_payload(payload, {"sub"})
        assert out["sub"].startswith("<redacted:")
        assert out["iss"] == "https://x"
        assert out["aud"] == "api"

    def test_field_match_is_case_insensitive(self):
        out = btt.redact_payload({"UPN": "alice"}, {"upn"})
        assert out["UPN"].startswith("<redacted:")

    def test_empty_payload_returned_as_is(self):
        assert btt.redact_payload(None, {"sub"}) is None
        assert btt.redact_payload({}, {"sub"}) == {}

    def test_empty_field_set_returns_payload_unchanged(self):
        p = {"sub": "alice"}
        assert btt.redact_payload(p, set()) is p


class TestParseRedactArg:
    def test_none_means_disabled(self):
        assert btt.parse_redact_arg(None) is None

    def test_empty_string_means_defaults(self):
        out = btt.parse_redact_arg("")
        assert out == set(btt.DEFAULT_REDACT_CLAIMS)

    def test_explicit_list_used_verbatim(self):
        assert btt.parse_redact_arg("sub,oid") == {"sub", "oid"}

    def test_whitespace_around_commas_stripped(self):
        assert btt.parse_redact_arg(" sub , oid ") == {"sub", "oid"}


class TestApplyRedaction:
    def test_redaction_modifies_token_payloads_in_place(self):
        tracker = btt.Tracker()
        tok = btt.Token(
            fp="abc", sample="ey…", token_type="access", sub_type="jwt",
            first_seen_time="t", last_seen_time="t",
            jwt_header={"alg": "RS256", "typ": "JWT"},
            jwt_payload={"sub": "alice", "iss": "https://x"},
        )
        tracker.tokens["abc"] = tok
        n = btt.apply_redaction(tracker, {"sub"})
        assert n == 1
        assert tok.jwt_payload["sub"].startswith("<redacted:")
        assert tok.jwt_payload["iss"] == "https://x"

    def test_no_fields_no_changes(self):
        tracker = btt.Tracker()
        tok = btt.Token(
            fp="abc", sample="ey…", token_type="access", sub_type="jwt",
            first_seen_time="t", last_seen_time="t",
            jwt_payload={"sub": "alice"},
        )
        tracker.tokens["abc"] = tok
        assert btt.apply_redaction(tracker, set()) == 0
        assert tok.jwt_payload["sub"] == "alice"
