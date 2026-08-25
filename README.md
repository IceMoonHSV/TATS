# TATS — Token Analysis and Tracking System



Track OAuth 2.0, OIDC, and Microsoft Entra ID tokens across captured network
traffic. Ingests Burp Suite XML exports, mitmproxy flow files, or live Chrome
DevTools Protocol streams into a single SQLite database, then serves an
interactive web dashboard for filtering tokens, walking exchanges, spotting
risky scopes, exporting tokens for replay, and visualising token lifecycles
as Mermaid graphs.

> **Status:** TATS is stable for personal / engagement use. Optimised for the
> Microsoft 365 / Entra ecosystem (FOCI, BroCI/NAA, ESTSAUTH session
> cookies, entrascopes.com enrichment) but works against any standard-ish
> OAuth/OIDC traffic.

---

## Why it exists

When you proxy a long Microsoft 365 or Azure session through Burp / mitmproxy
the resulting capture is enormous and most tools either:

* Only show one token at a time (Burp's JWT extension), or
* Don't follow Microsoft's OAuth dialect (FOCI, BroCI, ESTSAUTH cookies), or
* Don't track WebSocket frames, where Teams / Skype / SignalR send tokens, or
* Don't tell you which tokens are *still valid right now*.

This tool extracts every observed access / refresh / id token, fingerprints
them so it can correlate the same token across sources, decodes JWT claims,
resolves Microsoft client / resource GUIDs against
[entrascopes.com](https://entrascopes.com/), and renders the whole picture
as a single dashboard — including a refresh-token chain view that follows
FOCI cross-app exchanges and BroCI nested-app token issuance.

This project is intended primarily for research and education purposes but 
provides options such as command preview and token export features that can
support some offensive tooling. 

---

## Features

### Core
* **Three ingest sources** in one tool:
  * `ingest` — Burp Suite "Save items" XML export
  * `mitm` — mitmproxy `.mitm` flow file (HTTP **and** WebSocket frames)
  * `cdp` — live attach to Chrome / Edge via DevTools Protocol
    (real-time, captures TLS-decrypted HTTP **and** WebSocket frames
    without a proxy CA; tracks every existing tab AND every tab opened
    during the run via browser-level auto-attach)
* **One canonical SQLite store** the dashboard reads from. Each ingest pass
  can be run with `--append` to merge into an existing database; tokens
  are upserted (uses count + observed lifetime accumulate), events and
  exchanges are appended, and the row's `source_tag` records every pass
  that has seen the token.
* **Live web dashboard** served by a stdlib HTTP server. Polls the database
  every 5 seconds and re-renders when the underlying data changes — so a
  running CDP capture updates the dashboard in near real-time.
* **No proprietary dependencies for the core paths.** Burp ingest, the
  database layer, the web UI, and CDP attach are all stdlib only. The
  mitmproxy import is the one optional dep (`pip install mitmproxy`).

### Token classification & enrichment
* **OAuth body keys** (`access_token`, `refresh_token`, `id_token`) and
  cookie-name heuristics drive the token type.
* **Microsoft session cookies** (`ESTSAUTH`, `ESTSAUTHPERSISTENT`,
  `ESTSAUTHLIGHT`, `SignInStateCookie`) are explicitly recognised as
  refresh-equivalent tokens (they would otherwise be misclassified by the
  generic "auth" cookie hint).
* **JWT claims** (header + payload) decoded and stored verbatim — never
  truncated.
* **Microsoft FOCI** (Family of Client IDs) detected via the `foci` field
  in token-endpoint responses.
* **Microsoft BroCI / Nested App Authentication** detected via
  `brk_client_id`, `brk_redirect_uri`, and `brk-<guid>://` redirect schemes
  in the request body.
* **Optional `--enrich` flag** fetches `firstpartyscopes.json` and
  `resources.json` from <https://entrascopes.com/> and resolves `appid` /
  `azp` / `aud` GUIDs into friendly names with clickable links.

### Dashboard cards
* **Summary tiles** — token counts, hosts, exchanges (with FOCI / BroCI
  call-outs), and an enrichment status indicator.
* **Users** — token bucketing by `upn` / `preferred_username` /
  `unique_name` / `email` / `name`, falling back to `sub@iss` or `oid`,
  and surfacing app-only and unknown-identity buckets separately. Each
  identity row shows a **captures** badge when the user appears in
  ≥2 `source_tag`s (cross-capture survival, the headline `--append`
  research signal) plus a `first_seen → last_seen` span and a
  **timeline** button that highlights every token for that user on
  the Sequence-diagram tab.
* **Token validity** — counts of currently-valid vs expired access tokens,
  refresh-token expiry status (with "unknown expiry" for opaque tokens),
  and a top-3 "next to expire" list with a 30-second auto-refresh.
* **Clients** — every distinct app (`appid` / `azp` / form-body
  `client_id` / `brk_client_id` / `brk_nested_id`) that's appeared in
  exchanges, with FOCI / brokerable / broker / nested badges.
* **Audiences** — every `aud` claim observed, resolved to entrascopes
  resource names where possible.
* **Tenants** — distinct `tid` values with token / user / app counts.
* **Hosts** — events, distinct bearer recipients, distinct issuers, and
  exchange counts per host.
* **Privileged scopes & roles** — checks each token's `scp` / `scope` /
  `roles` against a curated watchlist of high-impact Microsoft Graph
  permissions and Azure resource scopes.
* **Audience / host mismatches** — flags every `(token, host)` pair where
  the token was used at a host that disagrees with its `aud` claim
  (suggests credential leak or misuse).
* **Auth methods** (`amr`) — `pwd` / `mfa` / `pop` / `smartcard`
  distribution.
* **Security features** — flags Continuous Access Evaluation (`xms_cc=CP1`),
  proof-of-possession binding (`cnf` claim, with shared-`kid` detection
  across audiences), step-up auth requirements (`acrs`), and the `acr`
  authentication-context level. Each row is clickable and filters the
  Tokens tab to only the tokens that carry that marker.
* **Refresh-token chains** — walks exchange edges to identify rotation
  lineages, longest chain length, and idle refresh tokens. Each chain
  shows a **Δ scopes** column (added / removed scopes across hops, with
  the full per-hop diff on hover) and flags chains where an added scope
  matches the privileged-scope watchlist with a `⚠ priv` badge — the
  FOCI / BroCI-style privilege-expansion research signal.
* **Sources** — per-`source_tag` token counts so you can see how many
  rows came from each ingest pass.

### Tokens / Exchanges tabs
* Click a column header to sort.
* Multi-select checkboxes drive a toolbar:
  * **Highlight in Graph** — yellow accent on the selected nodes.
  * **Isolate in Graph** — redraw the diagram showing only the selected
    tokens plus the tokens they exchange with.
  * **Show in Sequence** — focused sequence diagram for the selected
    token(s).
* Click a row to expand an inline panel with full JWT header + payload
  (raw JSON), all events, related exchanges, replay-ready export buttons
  (raw / Bearer / curl / JSON / roadtx token cache), and a
  command-preview block with copy-paste snippets for `roadtx describe`,
  `roadtx auth`, `curl`, Python `requests`, and PowerShell
  `Invoke-RestMethod`.
* **Filters:** type chips (access / refresh / id / unknown), format chips
  (jwt / opaque), used / unused dropdown, validity dropdown
  (any / valid / expired / unknown expiry), FOCI-only, BroCI-only,
  has-app-match, has-resource-match, plus a free-text search across
  fp / sample / claims / host / app / resource / source_tag / user.
* **CSV / JSON export** of the currently filtered + sorted rows.
* **URL hash persistence** — the active tab and every filter state is
  serialised to the URL hash, so links to specific filtered views are
  shareable.

### WebSocket support
* mitmproxy and CDP captures preserve every WebSocket text / binary frame
  payload. Frame contents are scanned for tokens with the same
  JSON / form / raw-JWT walker that handles HTTP bodies.
* Tokens found in frames generate events with role `ws-frame-sent` /
  `ws-frame-received`, source `ws[body_json[<key>]]`, and a
  `ws_session_id` that groups all frames within one WebSocket connection.
* The handshake is captured as a normal HTTP event so cookies / bearer
  tokens carried into the upgrade are also tracked.

### Privacy
* The database stores SHA-256 fingerprints (first 12 hex chars) and a
  12-character prefix of every observed token. **Full token strings never
  leave the input file.**
* Decoded JWT claim *contents* (header + payload, including `oid`, `sub`,
  `upn`, `email`, `tid`, scope lists, etc.) are stored verbatim by
  default because they're the whole point of the analysis. Treat the
  database and any shared dashboard URL as sensitive whenever JWTs are
  present.
* **`--redact-claims`** (available on `ingest`, `mitm`, and `cdp`)
  replaces listed claim values with stable hash placeholders before they
  ever land in the database. The default field list covers `sub`, `oid`,
  `upn`, `email`, `name`, `unique_name`, `preferred_username`, `emails`,
  `mail`, `ipaddr`, `given_name`, `family_name`. Pass an explicit
  comma-separated list (e.g. `--redact-claims sub,upn,oid`) to override
  the default. Same input always maps to the same placeholder, so the
  dashboard's Users / Tenants grouping still works without revealing the
  user.
* **`--store-tokens`** (available on `ingest`, `mitm`, and `cdp`,
  off by default) opts into writing the **full** token string to the
  database so the dashboard can offer:
  * Copy raw / Copy Bearer / Copy curl actions.
  * Download token JSON (raw + claims + observed events).
  * Copy / Download as roadtools token cache (drop the file into
    `.roadtools_auth` and any `roadtx` subcommand picks it up).
  * A **Command preview** block per token that pre-fills the most common
    replay invocations — `roadtx describe`, `roadtx auth`, `curl`,
    Python `requests`, PowerShell `Invoke-RestMethod` — using the
    token's actual `tid`, `appid`, and `aud` claims.
  * `/api/export?fps=...` returning up to 200 tokens (raw, claims,
    events, exchanges) in one JSON bundle for downstream tooling.

  Enabling this turns the database into a wholesale credential — every
  byte needed to replay any captured session is in it. Combine with
  `--redact-claims` to scrub the *decoded* JWT view, but be aware the
  raw token still carries the unredacted claims encoded inside it.
  When the flag is off, the dashboard's command-preview block still
  renders, just with `<TOKEN>` as a placeholder so it works as a
  syntax reference; the export buttons render a hint to re-ingest.

---

## Installation

### Requirements

* **Python 3.10+** (uses match-statement-friendly type syntax and modern
  `dataclasses`). Tested on 3.12.
* No build step. Clone the repo and run `python -m tats` directly.

### Optional dependencies

| Need | Install |
|---|---|
| `mitm` subcommand | `pip install mitmproxy` |
| Live capture from Chrome / Edge | None — uses a stdlib WebSocket client |
| `--enrich` (entrascopes.com) | None — uses `urllib.request` |

### Quick install

**Run from a checkout (no install):**

```bash
git clone <repo-url> tats
cd tats
python -m tats --help
```

The dashboard's HTML / CSS / JS live in `tats/static/` and are loaded
on first import, so no build step is required — just run the module
directly out of the checkout.

**Install as a package (gives you the `tats` console script):**

```bash
pip install .                # core only
pip install .[mitm]          # + mitmproxy flow file support
pip install .[test]          # + pytest for the test suite
pip install .[all]           # everything
```

After installing you can call the tool by its short name:

```bash
tats ingest engagement.xml -o tokens.db --enrich
tats serve  tokens.db
```

If you only need the Burp / CDP paths the file is fully self-contained
with the Python standard library — no install or extras required.

---

## Quick start

**Analyse a Burp XML export and open the dashboard:**

```bash
tats ingest examples/fixture.xml -o tokens.db --enrich
tats serve tokens.db
```

**Combine a Burp capture with a mitmproxy flow file in one DB:**

```bash
tats ingest engagement.xml -o tokens.db --enrich
tats mitm chat-session.mitm -o tokens.db --enrich --append
tats serve tokens.db
```

**Live capture from a Chrome browser (sees TLS-decrypted HTTP + WebSocket
frames, no proxy CA needed) — letting the tool launch the browser:**

```bash
# Terminal 1 — auto-launch Chrome / Edge / Chromium / Brave
tats cdp -o tokens.db --enrich --launch-chrome

# Terminal 2 — open the dashboard (auto-refreshes every 5 s)
tats serve tokens.db
```

The launched browser is terminated and its temporary profile is deleted
when you Ctrl-C the `cdp` command.

If you'd rather attach to an already-running browser, start it with
`--remote-debugging-port=9222 --user-data-dir=/tmp/cdp-profile` and run
`cdp` without `--launch-chrome`.

**Sanitise a database before sharing it (PII redaction):**

```bash
tats ingest engagement.xml -o tokens.db \
    --enrich --redact-claims
# every sub / oid / upn / email / name / unique_name / preferred_username
# (and a few related claims) is replaced with a stable hash placeholder
```

The redaction is content-stable: identical values map to identical
placeholders, so the dashboard's per-user grouping still works without
showing the user.

The header of the dashboard shows `live · updated <time>` once data starts
flowing in.

---

## Subcommands

Every subcommand accepts `--help` for the canonical option list. The notes
below explain *when* and *how* you'd reach for each one.

### Global flags

These apply to every subcommand and go *before* the subcommand name:

* `-v` / `--verbose` — adds INFO log lines (enrichment status, ingest
  redaction counts). `-vv` adds DEBUG (every server request).
* `-q` / `--quiet` — silences INFO log lines; only WARNINGs and ERRORs
  surface. The final user-output line (e.g. `wrote tokens.db (...)`) and
  any `error: …` diagnostics are unaffected so you'll still see what
  matters from a script.
* `--version` — print the tool version and exit.

### `ingest` — Burp Suite XML export

Reads a "Save items" XML (Proxy → HTTP history → right-click → Save items).
Binary `.burp` project files are **not** supported — the format is
proprietary and unstable across Burp versions; exporting the items you
care about is the supported workflow.

```bash
tats [-v|-q] ingest <burp_items.xml> -o tokens.db \
    [--enrich] [--enrich-cache-dir DIR] [--no-enrich-cache] \
    [--append] [--source-tag TAG] [--no-progress] \
    [--redact-claims [CLAIMS]] [--no-serve-hint]
```

Examples:

```bash
# fresh DB, with Microsoft enrichment
tats ingest burp.xml -o tokens.db --enrich

# add another Burp export to an existing DB without losing the first one
tats ingest day2.xml -o tokens.db --append \
    --source-tag burp:day2
```

### `mitm` — mitmproxy `.mitm` flow file

Reads a flow file produced by `mitmdump`, `mitmproxy`, or `mitmweb`. This
is the only ingest path that captures **WebSocket frames** without a live
browser session — flow files preserve every text / binary frame payload.

```bash
tats [-v|-q] mitm <flow_file.mitm> -o tokens.db \
    [--enrich] [--enrich-cache-dir DIR] [--no-enrich-cache] \
    [--append] [--source-tag TAG] [--no-progress] \
    [--redact-claims [CLAIMS]] [--no-serve-hint]
```

Requires `pip install mitmproxy`. The tool will emit a clear error if the
package is missing.

Capture a flow file with mitmproxy:

```bash
mitmdump -w session.mitm
# ... drive the browser ...
# Ctrl-C to stop

tats mitm session.mitm -o tokens.db --enrich
```

### `cdp` — live attach to Chrome / Edge

Connects to a running Chromium-family browser via the DevTools Protocol
and streams `Network.*` events into the database. Captures HTTP requests /
responses (with bodies fetched via `Network.getResponseBody`), WebSocket
upgrades, and every WebSocket frame in both directions. Buffer flushes to
the database every N events (default 25), so the dashboard's 5-second
poll picks up new tokens within seconds of the browser making the
request.

```bash
tats [-v|-q] cdp [-o tokens.db] \
    [--host 127.0.0.1] [--port 9222] [--target ID] \
    [--launch-chrome [PATH]] [--flush-every N] \
    [--enrich] [--append] [--redact-claims [CLAIMS]]
```

### Letting the tool launch the browser (`--launch-chrome`)

```bash
# auto-detect Chrome / Edge / Chromium / Brave
tats cdp -o tokens.db --launch-chrome

# explicit path (useful for non-default installs / sandboxed builds)
tats cdp -o tokens.db \
    --launch-chrome /opt/google/chrome-canary/chrome
```

The launched browser runs with `--remote-debugging-port=<port>` and a
fresh temporary user-data-dir. When you stop the `cdp` command (Ctrl-C),
the browser is terminated and the temp profile is deleted.

### Attaching to an already-running browser

Start the browser yourself, with a fresh profile, then run `cdp` without
`--launch-chrome`:

```bash
# Windows
"C:\Program Files\Google\Chrome\Application\chrome.exe" ^
    --remote-debugging-port=9222 ^
    --user-data-dir="%TEMP%\cdp-profile"

# macOS
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
    --remote-debugging-port=9222 --user-data-dir=/tmp/cdp-profile

# Linux
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/cdp-profile
```

A separate user-data-dir avoids attaching to a personal profile and
prevents the running browser from refusing the debug flag.

By default `cdp` attaches at the **browser** level and tracks every tab
that exists when it starts AND every tab opened during the run
(window.open, Ctrl-click, new-tab button). All tabs share the single
WebSocket via the CDP flat-protocol session multiplexer, so opening or
closing tabs while capture is running is fully supported. Each tab attach
/ detach prints a one-line note to stderr at INFO level.

If you'd rather pin to a single tab and have the attach end when that
tab closes, list the available targets:

```bash
curl http://127.0.0.1:9222/json/list
```

…then pass `--target <id>`.

Press Ctrl-C to stop. The tail of any in-flight buffer is flushed to the
database before the process exits.

### `serve` — web dashboard

Reads an existing database and serves a single-page web UI on
`127.0.0.1:8765`. The server is read-only; it never writes to the
database, so it's safe to run alongside an in-flight `cdp` or `mitm`
ingest.

```bash
tats serve <tokens.db> \
    [--host 127.0.0.1] [--port 8765] [--no-browser]
```

Examples:

```bash
# default — opens a browser tab automatically
tats serve tokens.db

# bind to a different port without auto-launching the browser
tats serve tokens.db --port 9000 --no-browser

# (do this only on a trusted network — no auth)
tats serve tokens.db --host 0.0.0.0
```

> **Warning:** the web UI exposes decoded JWT payloads (claims), token
> fingerprints, the activity timeline, and Mermaid graphs to anyone who
> can reach the bind address. If you ingested with `--store-tokens`, it
> also exposes the **full raw tokens** through `/api/token/<fp>` and
> `/api/export?fps=...`. There is **no authentication**. Keep
> `--host` on `127.0.0.1` unless you specifically intend otherwise.

#### Replay-ready export

When the database was built with `--store-tokens`, each expanded token
in the Tokens tab gets a row of one-click actions:

* **Copy raw** — the full token string to the clipboard.
* **Copy Bearer header** — `Authorization: Bearer <token>`, paste-ready.
* **Copy curl example** — a one-liner that targets the token's `aud`
  (or its issuer host) with the bearer header attached.
* **Download JSON** — a single-token JSON file containing raw, claims,
  observed events, and exchanges.
* **Copy as roadtx** — the JSON shape of a roadtools token cache
  (`tokenType`, `accessToken` / `refreshToken` / `idToken`, `expiresOn`,
  `tenantId`, `_clientId`, `resource`, `foci`, `scope`). Paste straight
  into a `.roadtools_auth` file.
* **Download .roadtools_auth** — same payload, downloaded as a file.
  Rename it to `.roadtools_auth` (or pass it via `roadtx <cmd>
  --tokens-file`) and any roadtx subcommand picks it up.

The Tokens-tab toolbar also has **Export selected for replay**, which
hits `/api/export?fps=fp1,fp2,...` and downloads a single JSON document
with up to 200 tokens (raw, claims, events) in one bundle. Without
`--store-tokens`, the same buttons render a hint to re-ingest before
replay-ready export becomes possible.

#### Command preview

Each expanded token also has a collapsible **Command preview** block
that pre-fills the most common replay / inspection invocations using
the token's actual claims (and full raw value when `--store-tokens` is
on). Each snippet has a one-click Copy button. The exact mix depends on
token type:

* **Any JWT:** `roadtx describe -t '<token>'` (decode without network).
* **Refresh tokens:**
  * `roadtx auth --refresh-token '...' -c <client_id> -t <tenant_id>` —
    swap a refresh token for fresh access tokens.
  * `curl -X POST .../oauth2/v2.0/token` — the OAuth-equivalent for
    users not running roadtx.
* **Access / id / unknown tokens:**
  * `curl -H 'Authorization: Bearer ...' '<aud>'`
  * Python `requests.get(...)` with the bearer header set.
  * PowerShell `Invoke-RestMethod` with the same header.
* **Always:** the JSON object to drop into `.roadtools_auth`.

When `--store-tokens` is off, the snippets render with `<TOKEN>` as a
placeholder so the panel is still useful as a documentation reference.

---

## The web UI in detail

### Top navigation

`Summary | Tokens | Exchanges | FOCI | BroCI | Graph | Sequence`

Each tab is rendered independently from the same in-memory snapshot of
`/api/data`. Switching tabs is instantaneous; the graph and sequence
diagrams are re-rendered on demand and respect the current selection in
the Tokens tab.

### Summary

Stat tiles across the top (tokens / access / refresh / id / unknown /
used / unused / events / exchanges / FOCI exchanges / BroCI exchanges /
hosts) followed by a grid of cards described in
[Features → Dashboard cards](#dashboard-cards).

Click any row in any card to jump to a pre-filtered Tokens tab — for
example, clicking a tenant row filters the inventory to tokens carrying
that `tid`.

### Tokens

Filterable, sortable inventory. Multi-select drives the highlight /
isolate / sequence buttons. Row expansion shows the full decoded JWT
(header + payload as raw JSON), every event involving that token, and
every exchange where it was an input or output.

### Exchanges

Sortable list of every detected token-for-token exchange — refresh-token
rotations, FOCI cross-redemptions, and BroCI nested-app exchanges. The
BroCI column shows broker + nested client IDs side by side with the
evidence that triggered detection.

### FOCI

Two tables: every refresh token tagged with a FOCI family (currently
Microsoft only emits `"1"`), and every exchange whose response carried
the `foci` field.

### BroCI

The Nested App Authentication exchanges. For each one: the broker app
(`brk_client_id`), the nested client (`client_id`), the evidence that
triggered detection (`brk_client_id`, `brk_redirect_uri`,
`brk-<guid>://` redirect URI), and the input / output token
fingerprints.

### Graph

Mermaid `flowchart LR` of token ↔ service relationships. Refresh tokens
are drawn as cylinders, access / id tokens as stadiums. Edges show
issuance, presentation, exchange, and rotation. Highlighting (from the
Tokens tab) adds a yellow accent; isolation re-renders the graph with
only the selected tokens and the tokens they exchange with.

### Sequence

Mermaid sequence diagram of every event in capture order. Selecting a
single token shows only its sequence; selecting multiple keeps the full
view but stars the selected tokens. Configurable max-event cap (default
200; Mermaid sequence diagrams become unreadable past a few hundred
messages).

---

## Microsoft-specific support

### Family of Client IDs (FOCI)

Microsoft permits a refresh token issued to one app in a "family" to be
redeemed at the token endpoint by **any other app** in the same family.
The tool detects FOCI on the wire by parsing the token-endpoint response
JSON for a `foci` field (currently always `"1"` for the only known
family). Refresh tokens issued in such a response are tagged with the
family id and surfaced in the dedicated **FOCI** tab.

If `--enrich` is enabled, the inventory's app column also surfaces
`firstpartyscopes.json`'s `foci: true/false` flag — note that this can
disagree with on-wire detection (the entrascopes dataset is sometimes
conservative). The on-wire `foci` field is always the authoritative
signal.

### Brokered Client Init / Nested App Authentication (BroCI / NAA)

Office add-ins, Teams apps, and the Azure Portal use NAA to acquire
tokens for a nested client through a broker app. The tool detects this
on the request side via:
* the `brk_client_id` form parameter (broker app's GUID),
* the `brk_redirect_uri` form parameter (broker's actual redirect URI),
* a `redirect_uri` of the form `brk-<guid>://...` (where `<guid>` is the
  broker).

The resulting access token's `appid` / `azp` claim is the nested
client; the broker only appears on the wire — never as a JWT claim. The
dashboard surfaces both sides clearly.

### `ESTSAUTH` session cookies

`ESTSAUTH`, `ESTSAUTHPERSISTENT`, `ESTSAUTHLIGHT`, and
`SignInStateCookie` are Microsoft Entra session cookies that don't
travel in `Authorization: Bearer` but are used by the browser to mint
new access tokens via silent-auth flows. The tool labels them as
`refresh` (their functional role) instead of letting the generic `auth`
substring rule misclassify them as `access`.

### entrascopes.com enrichment (`--enrich`)

Fetches and caches `firstpartyscopes.json` (~2.8 MB; 504 first-party
apps with their FOCI flag, redirect URIs, scopes, and broker
capability) and `resources.json` (~170 KB; 1,750+ resource → display
name mappings) from <https://entrascopes.com/>. Cache lives in:

| Variable | Default |
|---|---|
| `$TATS_CACHE` | (highest priority; `$BURP_TOKEN_TRACKER_CACHE` is honored as a fallback for one-release migration) |
| `$XDG_CACHE_HOME/tats` | (Linux/macOS) |
| `%LOCALAPPDATA%\tats\cache` | (Windows) |
| `~/.cache/tats` | (fallback) |

TTL is 7 days. Use `--no-enrich-cache` to force a re-fetch. The cache
is reused as a stale fallback when the tool is run offline.

When `--enrich` is on, every `appid` / `azp` / `client_id` GUID and every
GUID-or-URL `aud` claim is resolved to a friendly name with a clickable
`https://entrascopes.com/?appId=<guid>` link.

---

## Architecture

### One-shot: file → DB → web UI

```
  burp.xml ─┐
   .mitm   ─┼─→ Tracker ─→ ingest_to_db ─→ tokens.db ─→ Store ─→ /api/data ─→ dashboard
   CDP WS  ─┘                  ▲                                       │
            (live, repeated)   └───── --append upserts on every flush ─┘
```

Every source path produces the same `Tracker` object. `ingest_to_db`
turns it into rows in the database. `Store` reads the database for the
HTTP server, which exposes JSON over `/api/data`, `/api/meta`,
`/api/token/<fp>`, `/api/export`, `/api/graph`, and `/api/sequence`.

### Database schema (v4)

* **`tokens`** (primary key `fp`) — fingerprint, sample prefix, type,
  format, observed lifetime, JWT header / payload as JSON, enrichment
  fields, derived fields (`user_identity`, `exp_unix`, `tenant_id`,
  `scopes_text`), comma-separated `source_tag`, `raw` (full token
  string, NULL unless ingested with `--store-tokens`), and
  `security_features` (compact JSON describing detected CAE / PoP /
  step-up markers — see the Security features card).
  Older v2 / v3 databases auto-migrate when reopened in append mode:
  v2 → v3 adds the nullable `raw` column; v3 → v4 adds the nullable
  `security_features` column and backfills it from each token's stored
  `jwt_payload_json` on first open. Pre-existing rows keep both
  columns at their previous values.
* **`events`** — every observed token interaction: HTTP request /
  response or WebSocket frame. Roles: `issued` / `returned` /
  `presented` / `used` / `exchanged-in` / `ws-frame-sent` /
  `ws-frame-received`. Carries `ws_session_id` for grouping frames
  within a connection.
* **`exchanges`** — when a token-bearing request to a token endpoint
  produced new tokens in its response. Records FOCI / BroCI metadata.
* **`exchange_inputs`**, **`exchange_outputs`** — token fingerprints on
  each side of every exchange.
* **`hosts`** — distinct host:port labels.
* **`meta`** — schema version, source list, generated_at, last_modified
  (used by the dashboard's live poll), counts.

### Source tagging and append mode

Every row written to the DB carries a `source_tag` — by default
`burp:<filename>`, `mitm:<filename>`, or `cdp:<host>:<port>`, but
overridable via `--source-tag`. When the same fingerprint is seen by
more than one ingest pass, the `source_tag` field accumulates as a
comma-separated list, so the dashboard's Sources card can show
provenance for every token.

`--append` keeps an existing DB and merges into it via UPSERT for
tokens (uses count + observed lifetime accumulate, unknown types
upgrade) and INSERT for events / exchanges (with their `seq` numbers
offset past the existing max, so the activity timeline stays
monotonic). Schema version mismatch refuses the merge to prevent silent
data loss.

### Live updates

The web server's `/api/meta` endpoint returns the `meta` table (~200
bytes). The dashboard polls it every 5 seconds and only re-fetches the
full `/api/data` when `last_modified` changes. The `cdp` ingest path
flushes its in-memory tracker to the DB every 25 events by default, so
the wall-clock latency from a browser request to a dashboard update is
typically < 10 seconds.

---

## Limitations

* **Burp `.burp` project files are not supported.** Use `Save items` to
  produce the XML the tool consumes.
* **No proxy CA management.** This tool doesn't intercept TLS itself.
  Use it downstream of Burp / mitmproxy, or use the CDP path which sees
  TLS-decrypted traffic from inside the browser.
* **CDP attach covers top-level page targets.** Out-of-process iframes
  (OOPIFs) and dedicated workers are not auto-attached recursively, so
  events that flow through those target types may be missed. For the
  Microsoft / OAuth flows this tool is built around, top-level page
  attach catches everything that matters.
* **No signature verification** on JWTs. The tool decodes claims for
  display; signature checking, `alg=none`, and key-confusion attacks
  are out of scope. Use a dedicated JWT auditor for those.
* **Opaque-token false positives.** The "is this a token?" heuristic
  treats any 20+-char URL-safe string in OAuth-shaped contexts as a
  token. Long random IDs may be incorrectly flagged. Tokens whose type
  can't be inferred end up as `unknown` and are hidden by default
  unless `--include-unknown` is set on the (Burp-only) older flag.
* **`--enrich` makes outbound HTTP requests** to
  `https://entrascopes.com/`. Skip the flag if your environment doesn't
  permit that.
* **The web UI has no authentication.** Bind it to localhost unless
  you've put another auth layer in front.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `error: could not parse <file> as XML` | Trying to ingest a binary `.burp` project file | In Burp: Proxy → HTTP history → select items → right-click → Save items |
| `error: no <item> elements found` | The XML wasn't produced by Burp's Save items | Re-export from Burp; the root element should be `<items>` |
| `error: cannot append to DB with schema_version 1` | DB was created by an earlier build | Delete the DB and re-ingest the original sources; schema migration is intentionally not automatic |
| `error: the 'mitm' source needs the mitmproxy Python package` | mitmproxy not installed | `pip install mitmproxy` |
| `error: cannot reach Chrome at 127.0.0.1:9222` | Chrome wasn't started with `--remote-debugging-port` | See the launch incantation in [`cdp` subcommand](#cdp--live-attach-to-chrome--edge) |
| CDP attaches but no events flow | Page hasn't made any network requests yet, or all activity is in an OOPIF / worker (not auto-attached) | Reload the page; confirm tabs were registered (look for `tab attached: …` log lines on stderr) |
| `no browser-level webSocketDebuggerUrl at /json/version` | Chrome version is too old for browser-level CDP, or it returned the wrong shape | Update Chrome, or pass `--target <id>` to use legacy single-tab attach |
| `target … has no webSocketDebuggerUrl` | Another debugger (e.g. DevTools window) is already attached | Close DevTools, or attach to a different target |
| Dashboard shows `Failed to load /api/data` | Server can't read the database file | Check the DB path is correct, the file is readable, and the schema version matches |
| Live updates stop arriving | The `cdp` process exited or the network buffer flush hasn't fired yet | Check the `cdp` terminal for errors; reduce `--flush-every` for snappier updates |

---

## Development

### Smoke-test fixtures

Two fixture-builders live in [`examples/`](examples/):

```bash
# Burp XML fixture (HTTP-only, includes FOCI + BroCI exchanges)
python examples/make_fixture.py examples/fixture.xml
tats ingest examples/fixture.xml -o tokens.db --enrich

# mitmproxy flow fixture (HTTP + WebSocket frames carrying tokens)
python examples/make_mitm_fixture.py examples/fixture.mitm
tats mitm   examples/fixture.mitm -o tokens.db --enrich --append
```

After both runs `tokens.db` has 15 tokens (11 from Burp + 4 from
mitmproxy), 23 events including a WebSocket-frame event, and 3
exchanges.

### Test suite

```bash
pip install .[test]
pytest
```

The suite covers token extraction, JWT parsing, Microsoft session-cookie
classification, FOCI / BroCI detection, claim summary, PII redaction,
the Burp XML ingest path with append-mode UPSERT semantics, and the
mitmproxy WebSocket-frame ingest path (auto-skipped when the optional
`mitmproxy` dep is missing).

```text
$ pytest tests/
============================= test session starts =============================
…
======================== 62 passed in 1.4s =================================
```

### Running the server in foreground

```bash
tats serve tokens.db --no-browser
```

…and open `http://127.0.0.1:8765` manually. The server logs every
request and any handler errors to stderr.

### File layout

| Path | Purpose |
|---|---|
| `tats/__init__.py` | The whole tool — parsers, DB layer, HTTP server, CDP client; loads the dashboard from `tats/static/` |
| `tats/__main__.py` | Entry point for `python -m tats`; same logic as the installed `tats` console script |
| `tats/static/index.html` | Dashboard HTML skeleton with `{{CSS}}` / `{{JS}}` placeholders |
| `tats/static/style.css` | Dashboard styling — edit with your normal CSS tooling |
| `tats/static/app.js` | Dashboard logic — edit with your normal JS tooling (LSP / lint / formatter) |
| `pyproject.toml` | Packaging metadata, optional extras (`[mitm]`, `[test]`, `[all]`), console entry point |
| `LICENSE` | GNU General Public License v3 |
| `README.md` | This file |
| `examples/` | Synthetic captures + fixture-builder scripts (see [examples/README.md](examples/README.md)) |
| `examples/make_fixture.py` | Synthetic Burp XML generator |
| `examples/make_mitm_fixture.py` | Synthetic mitmproxy flow file generator |
| `examples/fixture.xml` | Pre-built Burp XML fixture |
| `examples/fixture.mitm` | Pre-built mitmproxy flow fixture |
| `tests/` | pytest suite (run with `pytest`) |

The single-file layout is deliberate: the tool is meant to be read,
audited, and dropped into investigations by anyone with Python
installed. There's no hidden setup, no dependency tree to evaluate, and
no surface other than the file itself.

### Maintaining this README

If you change subcommands, schema, dashboard cards, or the public API
surface (CLI flags, `/api/*` endpoints), update the relevant sections
of this file in the same change. Sections most likely to drift:

* [Features](#features) — when adding ingest sources or dashboard cards
* [Subcommands](#subcommands) — when changing flags
* [Microsoft-specific support](#microsoft-specific-support) — when
  detection logic changes
* [Architecture](#architecture) — when the schema or live-update flow
  changes
* [Troubleshooting](#troubleshooting) — when a new error message lands

---

## License

[GNU General Public License v3.0 or later](LICENSE) — full text in the
`LICENSE` file at the repository root. The script's source carries the
standard short header pointing to the same.

You may redistribute and/or modify the tool under the terms of the GPL
v3 (or any later version, at your option). It is distributed without
any warranty; see the LICENSE for full terms.
