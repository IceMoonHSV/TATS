# Examples

Synthetic captures and the scripts that produce them. Use these to smoke-test
the tool end-to-end without needing a real engagement, real browser, or a
running mitmproxy.

## Files

| File | What it is |
|---|---|
| `make_fixture.py` | Builds `fixture.xml` — a Burp "Save items" XML export covering a password grant, a refresh-token rotation, a FOCI cross-redemption, and a BroCI nested-app exchange. |
| `make_mitm_fixture.py` | Builds `fixture.mitm` — a mitmproxy flow file containing an HTTP token-issuance flow plus a WebSocket session with a frame that carries an access token in JSON. |
| `fixture.xml` | Pre-built Burp XML fixture (committed for convenience). Regenerate with `python examples/make_fixture.py`. |
| `fixture.mitm` | Pre-built mitmproxy flow fixture. Regenerate with `python examples/make_mitm_fixture.py examples/fixture.mitm`. |

`make_mitm_fixture.py` requires `mitmproxy`:

```bash
pip install mitmproxy
```

## Quick tour

From the repository root:

```bash
# Burp XML ingest with Microsoft enrichment
python -m tats ingest examples/fixture.xml -o tokens.db --enrich

# add the mitmproxy flow file (HTTP + WebSocket frames carrying tokens)
python -m tats mitm   examples/fixture.mitm -o tokens.db --enrich --append

# open the dashboard
python -m tats serve  tokens.db
```

After both ingest steps your `tokens.db` will hold:

* 15 distinct tokens (11 from the Burp XML + 4 from the mitmproxy flow)
* 23 events including a WebSocket-frame event with role `ws-frame-sent` and
  source `ws[body_json[access_token]]`
* 3 exchanges: a refresh-token rotation, a FOCI cross-redemption between
  Microsoft Teams and Azure CLI, and a BroCI / NAA exchange between the
  Azure Portal (broker) and ADIbizaUX (nested client)

## Regenerating the fixtures

```bash
python examples/make_fixture.py             # writes ./fixture.xml (legacy default)
python examples/make_fixture.py examples/fixture.xml          # explicit path
python examples/make_mitm_fixture.py examples/fixture.mitm    # mitmproxy flow
```

The expiry timestamps on the synthetic Microsoft tokens are computed
relative to the wall clock at generation time, so re-running the generator
keeps the dashboard's "currently valid" / "expired" / "next to expire"
counts looking realistic.

## Using these fixtures in tests

The `tests/` suite consumes these fixtures via `tmp_path` copies — see
`tests/conftest.py`. If you regenerate them, the test assertions about
counts (15 tokens, 23 events, 3 exchanges) should continue to hold.
