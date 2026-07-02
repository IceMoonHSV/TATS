"use strict";
mermaid.initialize({ startOnLoad: false, theme: "dark",
  securityLevel: "strict", themeVariables: { fontSize: "13px" } });

const state = {
  meta: {}, hosts: [], tokens: [], exchanges: [], hostUsage: [],
  selected: new Set(),
  expanded: new Set(),
  // Cache of rendered detail-pad HTML, keyed by fp. Lets the live poll
  // re-render the token table without flashing "Loading details…" on
  // any row the user has expanded — the cached HTML fills the placeholder
  // while a background loadTokenDetail() refreshes the data.
  detailHtml: new Map(),
  sort: { col: "first_seen", dir: "asc" },
  xsort: { col: "seq", dir: "asc" },
  highlight: new Set(),
  isolate: new Set(),
  sequenceFp: null,
  currentTab: "summary",
  filters: {
    search: "", types: new Set(["access","refresh","id"]),
    formats: new Set(["jwt","opaque"]),
    uses: "all", validity: "all",
    foci:false, broci:false, hasApp:false, hasRes:false,
    // Active security-feature filter (cae / pop / acr / acrs / amr).
    // null = no constraint; otherwise the token must carry that key in
    // its security_features object.
    securityFeature: null,
  },
  xfilters: { search: "", foci:false, broci:false },
  // identity for tokens that have a JWT but no human-identifying claim
  // (idtyp=app, service principal tokens, etc.)
  APP_BUCKET: "(app-only token, no user)",
  ANON_BUCKET: "(unknown identity)",
};

// Scope substrings worth flagging on the dashboard. Matched case-insensitively
// as substrings so we cover both Microsoft Graph permission names and Azure
// resource scopes. Hand-curated; not exhaustive — the list is meant to draw
// attention, not replace a permission audit.
const RISKY_SCOPES = [
  "Directory.ReadWrite.All",
  "Directory.AccessAsUser.All",
  "RoleManagement.ReadWrite.Directory",
  "RoleManagement.ReadWrite.All",
  "Application.ReadWrite.All",
  "Application.ReadWrite.OwnedBy",
  "AppRoleAssignment.ReadWrite.All",
  "Group.ReadWrite.All",
  "User.ReadWrite.All",
  "User.Export.All",
  "Mail.ReadWrite",
  "Mail.Read.All",
  "Mail.Send",
  "Mail.Send.Shared",
  "Files.ReadWrite.All",
  "Sites.ReadWrite.All",
  "Sites.FullControl.All",
  "Sites.Manage.All",
  "Calendars.ReadWrite",
  "Chat.ReadWrite.All",
  "ChannelMessage.Send",
  "TeamMember.ReadWrite.All",
  "AuditLog.Read.All",
  "DeviceManagementConfiguration.ReadWrite.All",
  "DeviceManagementManagedDevices.ReadWrite.All",
  "IdentityRiskEvent.ReadWrite.All",
  "IdentityRiskyUser.ReadWrite.All",
  "PrivilegedAccess.ReadWrite.AzureAD",
  "PrivilegedAccess.ReadWrite.AzureADGroup",
  "PrivilegedAccess.ReadWrite.AzureResources",
  "RoleAssignmentSchedule.ReadWrite.Directory",
  "RoleEligibilitySchedule.ReadWrite.Directory",
  "Policy.ReadWrite.ConditionalAccess",
  "Policy.ReadWrite.PermissionGrant",
  "ConsentRequest.ReadWrite.All",
  "DelegatedPermissionGrant.ReadWrite.All",
  // Azure resource scopes:
  "user_impersonation",
  "full_access_as_user",
];

// --- helpers --------------------------------------------------------------

const $ = sel => document.querySelector(sel);
const $$ = sel => Array.from(document.querySelectorAll(sel));
const escapeHtml = s => (s ?? "").toString().replace(/[&<>"']/g, c => ({
  "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;"})[c]);
const escapeAttr = escapeHtml;

function appLink(app){
  if(!app || !app.guid) return "";
  const badges = [];
  if(app.foci) badges.push('<span class="badge foci">FOCI</span>');
  if(app.brokerable) badges.push('<span class="badge brokerable">brokerable</span>');
  const name = escapeHtml(app.name || "(unknown)");
  return `<a href="${escapeAttr(app.link)}" target="_blank" rel="noopener">${name}</a> ${badges.join("")}`;
}
function resLink(res){
  if(!res || !res.guid) return "";
  return `<a href="${escapeAttr(res.link)}" target="_blank" rel="noopener">${escapeHtml(res.name||"(unknown)")}</a>`;
}

// --- tab nav --------------------------------------------------------------

$$("#nav button").forEach(btn => btn.addEventListener("click", () => {
  state.currentTab = btn.dataset.tab;
  $$("#nav button").forEach(b => b.classList.toggle("active", b===btn));
  $$(".section").forEach(s => s.classList.toggle("active", s.id===btn.dataset.tab));
  if(btn.dataset.tab==="graph") refreshGraph();
  if(btn.dataset.tab==="sequence") refreshSequence();
  syncUrlHash();
}));

// --- bootstrap ------------------------------------------------------------

async function loadData(){
  const r = await fetch("/api/data");
  if(!r.ok) throw new Error("API /api/data returned " + r.status);
  const data = await r.json();
  state.meta = data.meta || {};
  state.hosts = data.hosts || [];
  state.tokens = data.tokens || [];
  state.exchanges = data.exchanges || [];
  state.hostUsage = data.host_usage || [];
  // Caches that derive from the snapshots above; invalidate on every reload.
  state._tokenByFpCache = null;
  state._chainsCache = null;
  state._snapshotKey = state.meta && state.meta.last_modified;
  // Precompute the BroCI fp set in one O(E) pass so per-token tagging
  // is O(1) instead of O(E). Old code called state.exchanges.some(...)
  // inside a state.tokens.forEach loop — quadratic for big captures.
  const brociFps = new Set();
  state.exchanges.forEach(x => {
    if(!x.broci_broker_id) return;
    x.input_fps.forEach(fp => brociFps.add(fp));
    x.output_fps.forEach(fp => brociFps.add(fp));
  });
  state.tokens.forEach(t => {
    t._used = (t.uses|0) > 0;
    t._search = [t.fp, t.sample, t.type, t.sub_type, t.issuer_host,
      t.claim_summary, t.user_identity, t.source_tag,
      t.app && t.app.name, t.app && t.app.guid,
      t.resource && t.resource.name, t.resource && t.resource.guid,
      t.foci_family].filter(Boolean).join(" ").toLowerCase();
    t._brociKey = brociFps.has(t.fp);
    // Identity bucketing: real user / app-only / unknown.
    if(t.user_identity) t._identityBucket = t.user_identity;
    else if(t.has_jwt) t._identityBucket = state.APP_BUCKET;
    else t._identityBucket = state.ANON_BUCKET;
  });
  state.exchanges.forEach(x => {
    x._search = [x.host, x.path, x.grant_type, x.client_id,
      x.broci_broker_id, x.broci_nested_id, x.broci_evidence,
      x.foci_family].filter(Boolean).join(" ").toLowerCase();
  });
}

function renderAll(){
  renderKpis(); renderSummary(); renderTokens(); renderExchanges();
  renderFoci(); renderBroci();
}

async function bootstrap(){
  try{
    await loadData();
    applyUrlHash();
    renderAll();
    if(state.currentTab && state.currentTab !== "summary"){
      openTabSilently(state.currentTab);
    }
    startValidityTimer();
    startLivePoll();
  }catch(err){
    document.body.insertAdjacentHTML("afterbegin",
      `<div class="warning">Failed to load /api/data: ${escapeHtml(err.message)}</div>`);
  }
}

// --- Live poller ---------------------------------------------------------

let liveTimer = null;
let livePollInFlight = false;

async function pollMeta(){
  if(livePollInFlight) return;
  livePollInFlight = true;
  try{
    const r = await fetch("/api/meta");
    if(!r.ok) return;
    const m = await r.json();
    const lastSeen = (state.meta || {}).last_modified;
    if(m.last_modified && m.last_modified !== lastSeen){
      await loadData();
      renderAll();
      // Refresh any open token detail panels — cached HTML keeps them
      // visible while the fetch is in flight, so no "Loading details…"
      // flash on the live-poll path.
      refreshExpandedDetails();
      // re-render diagrams if their tabs are visible
      if(state.currentTab === "graph") refreshGraph();
      if(state.currentTab === "sequence") refreshSequence();
      const ind = $("#live-status");
      if(ind){
        ind.textContent = "live · updated " + new Date().toLocaleTimeString();
      }
    } else {
      const ind = $("#live-status");
      if(ind){
        ind.textContent = m.last_modified
          ? "live · " + (m.last_modified.replace("T"," ").replace("Z"," UTC"))
          : "";
      }
    }
  } finally {
    livePollInFlight = false;
  }
}

function startLivePoll(){
  if(liveTimer) clearInterval(liveTimer);
  // Poll every 5 seconds. /api/meta is tiny (~200 bytes) so this is cheap
  // even when no ingest is running.
  liveTimer = setInterval(pollMeta, 5000);
}

function renderKpis(){
  const m = state.meta || {};
  const counts = state.tokens.reduce((a,t)=>{a[t.type]=(a[t.type]||0)+1;return a;},{});
  $("#kpis").innerHTML = `
    <span class="kpi">tokens<b>${state.tokens.length}</b></span>
    <span class="kpi">access<b>${counts.access||0}</b></span>
    <span class="kpi">refresh<b>${counts.refresh||0}</b></span>
    <span class="kpi">id<b>${counts.id||0}</b></span>
    <span class="kpi">events<b>${m.events_count||"?"}</b></span>
    <span class="kpi">exchanges<b>${state.exchanges.length}</b></span>`;
}

function renderSummary(){
  const m = state.meta || {};
  const focix = state.exchanges.filter(x => x.foci_family).length;
  const brocix = state.exchanges.filter(x => x.broci_broker_id).length;
  const counts = state.tokens.reduce((a,t)=>{a[t.type]=(a[t.type]||0)+1;return a;},{});
  const used = state.tokens.filter(t => t._used).length;
  $("#summary-meta").innerHTML =
    `Source: <code>${escapeHtml(m.source||"?")}</code> · Generated ${escapeHtml(m.generated_at||"?")} · Enrichment ${m.enrichment_used==="1" ? "<b>on</b>" : "off"}`;
  $("#summary-stats").innerHTML = `
    ${statTile(state.tokens.length, "tokens")}
    ${statTile(counts.access||0, "access", "ok")}
    ${statTile(counts.refresh||0, "refresh", "warn")}
    ${statTile(counts.id||0, "id", "ok")}
    ${statTile(counts.unknown||0, "unknown", (counts.unknown||0)?"danger":"")}
    ${statTile(used, "used")}
    ${statTile(state.tokens.length - used, "unused", (state.tokens.length - used)?"warn":"")}
    ${statTile(m.events_count||"?", "events")}
    ${statTile(state.exchanges.length, "exchanges")}
    ${statTile(focix, "FOCI exchanges", focix?"warn":"")}
    ${statTile(brocix, "BroCI exchanges", brocix?"warn":"")}
    ${statTile(state.hosts.length, "hosts")}
  `;
  renderUsersCard();
  renderClientsCard();
  renderAudiencesCard();
  renderValidityCard();
  renderTenantsCard();
  renderHostsCard();
  renderScopesCard();
  renderAnomaliesCard();
  renderAmrCard();
  renderSecurityCard();
  renderChainsCard();
  renderSourcesCard();
}

function statTile(num, label, tone=""){
  return `<div class="dash-stat"><div class="num ${tone}">${num}</div><div class="lbl">${label}</div></div>`;
}

// --- Users card -----------------------------------------------------------

function renderUsersCard(){
  // Bucket tokens by user identity. Track per-identity:
  // - tokens, type counts (access/refresh/id)
  // - tids / issuers (already supported)
  // - source_tags this identity appears in (new) — comma-split because
  //   --append accumulates tags into one column
  // - first_seen / last_seen across all the identity's tokens (new)
  // The cross-capture flag is a research-grade signal: a user who shows
  // up in two captures means tokens / state survived between sessions.
  const buckets = new Map();
  state.tokens.forEach(t => {
    const key = t._identityBucket;
    if(!buckets.has(key)) buckets.set(key, {
      name: key, tokens: [], tids: new Set(), iss: new Set(),
      sources: new Set(),
      firstSeen: null, lastSeen: null,
      access:0, refresh:0, id:0,
    });
    const b = buckets.get(key);
    b.tokens.push(t);
    b[t.type] = (b[t.type]||0) + 1;
    const claims = t.claim_summary || "";
    const tidM = claims.match(/(?:^|;\s*)tid=([^;]+)/);
    if(tidM) b.tids.add(tidM[1].trim());
    const issM = claims.match(/(?:^|;\s*)iss=([^;]+)/);
    if(issM) b.iss.add(issM[1].trim());
    if(t.source_tag){
      t.source_tag.split(",").map(s => s.trim()).filter(Boolean)
        .forEach(s => b.sources.add(s));
    }
    if(t.first_seen && (!b.firstSeen || t.first_seen < b.firstSeen)){
      b.firstSeen = t.first_seen;
    }
    if(t.last_seen && (!b.lastSeen || t.last_seen > b.lastSeen)){
      b.lastSeen = t.last_seen;
    }
  });
  // Sort: real users first by token count, then app-only, then unknown last.
  const order = (b) => b.name===state.ANON_BUCKET ? 2 : (b.name===state.APP_BUCKET ? 1 : 0);
  const list = Array.from(buckets.values()).sort((a,b) => {
    const o = order(a) - order(b);
    if(o) return o;
    return b.tokens.length - a.tokens.length;
  });
  const realUsers = list.filter(b => order(b)===0).length;
  const crossCapture = list.filter(b => order(b)===0 && b.sources.size > 1).length;
  $("#users-hint").textContent = realUsers===1 ? "1 distinct user" : `${realUsers} distinct users`;
  $("#users-stats").innerHTML = `
    ${statTile(realUsers, "identifiable users")}
    ${statTile(crossCapture, "across ≥2 captures", crossCapture ? "ok" : "")}
    ${statTile((buckets.get(state.ANON_BUCKET)||{tokens:[]}).tokens.length, "unknown-identity tokens", (buckets.get(state.ANON_BUCKET)?"warn":""))}
    ${statTile((buckets.get(state.APP_BUCKET)||{tokens:[]}).tokens.length, "app-only tokens")}
  `;
  if(list.length === 0){
    $("#users-list").innerHTML = `<div class="empty">No tokens.</div>`;
    return;
  }
  const rows = list.map(b => {
    const isAnon = b.name===state.ANON_BUCKET;
    const isApp = b.name===state.APP_BUCKET;
    const label = isAnon || isApp
      ? `<span class="id-anon">${escapeHtml(b.name)}</span>`
      : `<b>${escapeHtml(b.name)}</b>`;
    const tids = Array.from(b.tids).slice(0,2).map(escapeHtml).join(", ") +
                 (b.tids.size>2 ? ` <span class="muted">(+${b.tids.size-2} more)</span>` : "");
    const iss = Array.from(b.iss).slice(0,1).map(escapeHtml).join(", ") +
                (b.iss.size>1 ? ` <span class="muted">(+${b.iss.size-1} more)</span>` : "");
    // Cross-capture badge: presence in ≥2 source_tags is the research
    // signal that tokens for this user survived across capture sessions.
    const srcs = Array.from(b.sources);
    const crossBadge = srcs.length > 1
      ? ` <span class="badge brokerable" title="appears in ${srcs.length} captures: ${escapeAttr(srcs.join(', '))}">${srcs.length} captures</span>`
      : "";
    // Timeline action: open the sequence diagram filtered to this
    // identity's tokens. Stops on first match — researchers usually want
    // to start from the earliest event for the user.
    const tlBtn = (isAnon || isApp)
      ? ""
      : ` <button class="tinybtn" data-act-identity-timeline="${escapeAttr(b.name)}" title="Show this user's tokens on the Sequence diagram, ordered by first observed event">timeline</button>`;
    const span = (b.firstSeen && b.lastSeen)
      ? `<br><span class="id-badge muted" title="first observed → last observed">${escapeHtml(b.firstSeen)} → ${escapeHtml(b.lastSeen)}</span>`
      : "";
    return `<tr data-jump-identity="${escapeAttr(b.name)}" class="row-clickable">
      <td>${label}${crossBadge}${tlBtn}<br><span class="id-badge muted">${iss}${tids?` · tid ${tids}`:""}</span>${span}</td>
      <td>${b.tokens.length}</td>
      <td>${b.access||0}</td>
      <td>${b.refresh||0}</td>
      <td>${b.id||0}</td>
    </tr>`;
  }).join("");
  $("#users-list").innerHTML = `
    <table>
      <thead><tr><th>User</th><th>Total</th><th>access</th><th>refresh</th><th>id</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

// --- Clients card ---------------------------------------------------------

function renderClientsCard(){
  // Aggregate clients by GUID across:
  // 1. JWT appid/azp claims (and our enriched app field);
  // 2. Form-body client_id observed on token-endpoint requests / exchanges;
  // 3. brk_client_id (broker, BroCI).
  const clients = new Map();   // guid_or_label -> { guid, name, link, foci, brokerable, role, tokens:Set, exchanges:Set }
  function bump(key, info, role, fp, xid){
    if(!clients.has(key)) clients.set(key, {
      guid: info.guid||"", name: info.name||"", link: info.link||"",
      foci: !!info.foci, brokerable: !!info.brokerable,
      roles: new Set(), tokens: new Set(), exchanges: new Set(),
    });
    const c = clients.get(key);
    c.roles.add(role);
    if(fp) c.tokens.add(fp);
    if(xid != null) c.exchanges.add(xid);
    if(info.name && !c.name) c.name = info.name;
    if(info.link && !c.link) c.link = info.link;
    c.foci = c.foci || !!info.foci;
    c.brokerable = c.brokerable || !!info.brokerable;
  }
  state.tokens.forEach(t => {
    if(t.app && t.app.guid){
      bump(t.app.guid.toLowerCase(), t.app, "issued-to", t.fp, null);
    }
  });
  state.exchanges.forEach(x => {
    if(x.client_id){
      const key = x.client_id.toLowerCase();
      const enriched = clients.get(key);
      bump(key, {guid: x.client_id, name: enriched?enriched.name:"", link: enriched?enriched.link:""},
           "exchange-caller", null, x.id);
      [...x.input_fps, ...x.output_fps].forEach(fp => clients.get(key).tokens.add(fp));
    }
    if(x.broci_broker_id){
      const key = x.broci_broker_id.toLowerCase();
      const enriched = clients.get(key);
      bump(key, {guid: x.broci_broker_id, name: enriched?enriched.name:"", link: enriched?enriched.link:""},
           "broker", null, x.id);
    }
    if(x.broci_nested_id){
      const key = x.broci_nested_id.toLowerCase();
      const enriched = clients.get(key);
      bump(key, {guid: x.broci_nested_id, name: enriched?enriched.name:"", link: enriched?enriched.link:""},
           "nested", null, x.id);
    }
  });
  const list = Array.from(clients.values()).sort((a,b) => b.tokens.size - a.tokens.size || (a.name||a.guid).localeCompare(b.name||b.guid));
  $("#clients-hint").textContent = list.length===1 ? "1 client" : `${list.length} clients`;
  if(list.length === 0){
    $("#clients-list").innerHTML = `<div class="empty">No clients identified.</div>`;
    return;
  }
  const rows = list.map(c => {
    const label = c.name
      ? (c.link
          ? `<a href="${escapeAttr(c.link)}" target="_blank" rel="noopener">${escapeHtml(c.name)}</a>`
          : escapeHtml(c.name))
      : `<span class="muted">(unresolved)</span>`;
    const badges = [];
    if(c.foci) badges.push('<span class="badge foci">FOCI</span>');
    if(c.brokerable) badges.push('<span class="badge brokerable">brokerable</span>');
    if(c.roles.has("broker")) badges.push('<span class="badge broci">broker</span>');
    if(c.roles.has("nested")) badges.push('<span class="badge access">nested</span>');
    return `<tr class="row-clickable" data-jump-client="${escapeAttr(c.guid)}">
      <td>${label} ${badges.join(" ")}<br><span class="code muted">${escapeHtml(c.guid)}</span></td>
      <td>${c.tokens.size}</td>
      <td>${c.exchanges.size}</td>
    </tr>`;
  }).join("");
  $("#clients-list").innerHTML = `
    <table>
      <thead><tr><th>Client</th><th>Tokens</th><th>Exchanges</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

// --- Audiences card -------------------------------------------------------

function renderAudiencesCard(){
  // Aggregate by aud claim, preferring resolved resource_guid when available.
  const auds = new Map();
  state.tokens.forEach(t => {
    let key, label, link;
    if(t.resource && t.resource.guid){
      key = t.resource.guid.toLowerCase();
      label = t.resource.name || t.resource.guid;
      link = t.resource.link;
    } else {
      // Pull aud from claim_summary as a last resort (no decoded payload here).
      const m = (t.claim_summary || "").match(/(?:^|;\s*)aud=([^;]+)/);
      if(!m) return;
      key = m[1].trim().toLowerCase();
      label = m[1].trim();
      link = "";
    }
    if(!auds.has(key)) auds.set(key, {key, label, link, tokens: new Set(), uses: 0, types: new Set()});
    const a = auds.get(key);
    a.tokens.add(t.fp);
    a.uses += t.uses|0;
    a.types.add(t.type);
  });
  const list = Array.from(auds.values()).sort((a,b) => b.tokens.size - a.tokens.size || a.label.localeCompare(b.label));
  $("#aud-hint").textContent = list.length===1 ? "1 audience" : `${list.length} audiences`;
  if(list.length === 0){
    $("#audiences-list").innerHTML = `<div class="empty">No audiences resolved.</div>`;
    return;
  }
  const rows = list.map(a => {
    const label = a.link
      ? `<a href="${escapeAttr(a.link)}" target="_blank" rel="noopener">${escapeHtml(a.label)}</a>`
      : escapeHtml(a.label);
    const types = Array.from(a.types).map(tt =>
      `<span class="badge ${tt}">${tt}</span>`).join(" ");
    return `<tr class="row-clickable" data-jump-aud="${escapeAttr(a.key)}">
      <td>${label}<br><span class="code muted">${escapeHtml(a.key)}</span></td>
      <td>${a.tokens.size} ${types}</td>
      <td>${a.uses}</td>
    </tr>`;
  }).join("");
  $("#audiences-list").innerHTML = `
    <table>
      <thead><tr><th>Audience</th><th>Tokens</th><th>Total uses</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

// --- Validity card --------------------------------------------------------

function fmtRel(secsFromNow){
  const a = Math.abs(secsFromNow);
  if(a < 60) return `${secsFromNow|0}s`;
  if(a < 3600) return `${Math.floor(a/60)}m`;
  if(a < 86400) return `${Math.floor(a/3600)}h ${Math.floor((a%3600)/60)}m`;
  return `${Math.floor(a/86400)}d ${Math.floor((a%86400)/3600)}h`;
}

function renderValidityCard(){
  const now = Math.floor(Date.now()/1000);
  const buckets = { access: {valid:0, expired:0, unknown:0},
                    refresh:{valid:0, expired:0, unknown:0},
                    id:     {valid:0, expired:0, unknown:0} };
  const valid = [];
  state.tokens.forEach(t => {
    if(!buckets[t.type]) buckets[t.type] = {valid:0, expired:0, unknown:0};
    const v = tokenValidity(t, now);
    buckets[t.type][v]++;
    if(v==="valid") valid.push(t);
  });
  const accValid = (buckets.access||{valid:0}).valid;
  const refrValid = (buckets.refresh||{valid:0}).valid;
  const idValid = (buckets.id||{valid:0}).valid;
  const accExp = (buckets.access||{expired:0}).expired;
  const refrUnknown = (buckets.refresh||{unknown:0}).unknown;
  $("#validity-now").textContent = "as of " + new Date(now*1000).toLocaleTimeString();
  $("#validity-stats").innerHTML = `
    ${statTile(accValid, "valid access", accValid?"ok":"")}
    ${statTile(accExp, "expired access", accExp?"danger":"")}
    ${statTile(refrValid, "valid refresh (JWT exp)", refrValid?"ok":"")}
    ${statTile(refrUnknown, "refresh w/ unknown expiry", refrUnknown?"warn":"")}
    ${statTile(idValid, "valid id tokens", idValid?"ok":"")}
  `;
  // Top-3 next to expire among currently valid JWT tokens.
  valid.sort((a,b) => (a.exp_unix||0) - (b.exp_unix||0));
  const top = valid.slice(0,3);
  if(top.length){
    $("#next-expire").innerHTML = `
      <div class="muted" style="font-size:.75rem;text-transform:uppercase;letter-spacing:.04em">Next to expire</div>
      ${top.map(t => `
        <div class="next-expire-item">
          <span><span class="badge ${t.type}">${t.type}</span>
            <span class="token-fp">${escapeHtml(t.fp)}</span>
            ${t.user_identity ? `· ${escapeHtml(t.user_identity)}` : ""}
            ${t.app && t.app.name ? ` · ${escapeHtml(t.app.name)}` : ""}</span>
          <span class="when">in ${fmtRel(t.exp_unix - now)}</span>
        </div>`).join("")}`;
  } else {
    $("#next-expire").innerHTML = `<div class="muted" style="font-size:.83rem;border-top:1px dashed var(--line);padding-top:.4rem">No JWT tokens currently valid.</div>`;
  }
  $("#validity-actions").innerHTML = `
    <button class="tinybtn" id="v-show-valid">View valid tokens</button>
    <button class="tinybtn" id="v-show-expired">View expired tokens</button>
    <button class="tinybtn" id="v-show-unknown">View unknown-expiry tokens</button>`;
  $("#v-show-valid").addEventListener("click", () =>
    jumpToTokens({validity:"valid", search:""}));
  $("#v-show-expired").addEventListener("click", () =>
    jumpToTokens({validity:"expired", search:""}));
  $("#v-show-unknown").addEventListener("click", () =>
    jumpToTokens({validity:"unknown", search:""}));
}

// --- Tenants card ---------------------------------------------------------

function renderTenantsCard(){
  const tenants = new Map();
  state.tokens.forEach(t => {
    if(!t.tenant_id) return;
    if(!tenants.has(t.tenant_id)) tenants.set(t.tenant_id, {
      tid: t.tenant_id, tokens: new Set(), users: new Set(), apps: new Set(),
      iss: new Set(),
    });
    const e = tenants.get(t.tenant_id);
    e.tokens.add(t.fp);
    if(t.user_identity) e.users.add(t.user_identity);
    if(t.app && t.app.guid) e.apps.add(t.app.guid);
    if(t.issuer_host) e.iss.add(t.issuer_host);
  });
  const list = Array.from(tenants.values()).sort((a,b) => b.tokens.size - a.tokens.size);
  $("#tenants-hint").textContent = list.length===1 ? "1 tenant" : `${list.length} tenants`;
  if(list.length === 0){
    $("#tenants-list").innerHTML = `<div class="empty">No <code>tid</code> claims observed (capture has no Entra JWTs).</div>`;
    return;
  }
  const rows = list.map(e => `
    <tr class="row-clickable" data-jump-tenant="${escapeAttr(e.tid)}">
      <td><span class="code">${escapeHtml(e.tid)}</span><br>
        <span class="muted code">${Array.from(e.iss).slice(0,1).map(escapeHtml).join("")}${e.iss.size>1?` <span class="muted">(+${e.iss.size-1} more)</span>`:""}</span></td>
      <td>${e.tokens.size}</td>
      <td>${e.users.size}</td>
      <td>${e.apps.size}</td>
    </tr>`).join("");
  $("#tenants-list").innerHTML = `
    <table>
      <thead><tr><th>Tenant id</th><th>Tokens</th><th>Users</th><th>Apps</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

// --- Hosts card -----------------------------------------------------------

function renderHostsCard(){
  // Aggregate per-host counts from /api/data's host_usage rows.
  const stats = new Map();
  function ensure(h){
    if(!stats.has(h)) stats.set(h, {
      host: h, events: 0, bearerFps: new Set(), issuedFps: new Set(),
      exchangedFps: new Set(),
    });
    return stats.get(h);
  }
  state.hostUsage.forEach(u => {
    const s = ensure(u.host);
    s.events += u.count|0;
    if(u.role === "used" || u.role === "presented") s.bearerFps.add(u.fp);
    if(u.role === "issued" || u.role === "returned") s.issuedFps.add(u.fp);
    if(u.role === "exchanged-in") s.exchangedFps.add(u.fp);
  });
  // Make sure every known host appears even if it had no events of interest.
  state.hosts.forEach(h => ensure(h));
  const list = Array.from(stats.values()).sort((a,b) => b.events - a.events);
  $("#hosts-hint").textContent = list.length===1 ? "1 host" : `${list.length} hosts`;
  if(list.length === 0){
    $("#hosts-list").innerHTML = `<div class="empty">No hosts captured.</div>`;
    return;
  }
  const rows = list.map(s => `
    <tr class="row-clickable" data-jump-host="${escapeAttr(s.host)}">
      <td><b>${escapeHtml(s.host)}</b></td>
      <td>${s.events}</td>
      <td>${s.bearerFps.size}</td>
      <td>${s.issuedFps.size}</td>
      <td>${s.exchangedFps.size}</td>
    </tr>`).join("");
  $("#hosts-list").innerHTML = `
    <table>
      <thead><tr><th>Host</th><th>Events</th><th title="distinct tokens presented as Authorization: Bearer">Bearer rcvd</th><th>Issued</th><th>Exchanged</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

// --- Privileged scopes card -----------------------------------------------

function renderScopesCard(){
  const lowerPatterns = RISKY_SCOPES.map(p => p.toLowerCase());
  const seen = new Map();   // pattern -> {pattern, tokens:Set}
  let tokensWithRisky = 0;
  state.tokens.forEach(t => {
    if(!t.scopes_text) return;
    const text = t.scopes_text.toLowerCase();
    let touched = false;
    lowerPatterns.forEach((pat, idx) => {
      if(text.includes(pat.toLowerCase())){
        const orig = RISKY_SCOPES[idx];
        if(!seen.has(orig)) seen.set(orig, {pattern: orig, tokens: new Set()});
        seen.get(orig).tokens.add(t.fp);
        touched = true;
      }
    });
    if(touched) tokensWithRisky++;
  });
  const list = Array.from(seen.values()).sort((a,b) => b.tokens.size - a.tokens.size);
  $("#scopes-hint").textContent = list.length===1 ? "1 scope" : `${list.length} scopes`;
  $("#scopes-stats").innerHTML = `
    ${statTile(tokensWithRisky, "tokens with privileged scope", tokensWithRisky?"warn":"")}
    ${statTile(list.length, "distinct scopes flagged", list.length?"warn":"")}
  `;
  if(list.length === 0){
    $("#scopes-list").innerHTML = `<div class="empty">No scopes from the privileged-scopes watch list were observed.</div>`;
    return;
  }
  const rows = list.map(s => `
    <tr class="row-clickable" data-jump-search="${escapeAttr(s.pattern)}">
      <td class="code">${escapeHtml(s.pattern)}</td>
      <td>${s.tokens.size}</td>
    </tr>`).join("");
  $("#scopes-list").innerHTML = `
    <table>
      <thead><tr><th>Scope / role</th><th>Tokens</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

// --- Audience / host mismatch card ---------------------------------------

function audHostFromAudClaim(aud){
  if(!aud) return null;
  const trimmed = aud.trim();
  try{
    if(trimmed.startsWith("http://") || trimmed.startsWith("https://")){
      return new URL(trimmed).hostname.toLowerCase();
    }
  }catch(e){ /* malformed URL */ }
  // GUIDs are not hostnames.
  if(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(trimmed)) return null;
  // Plain hostname-shaped value? Heuristic: dots and tld-ish suffix.
  if(/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(trimmed)) return trimmed.toLowerCase();
  return null;
}

function hostsCompatible(audHost, eventHost){
  if(!audHost || !eventHost) return true;
  if(audHost === eventHost) return true;
  if(eventHost.endsWith("." + audHost)) return true;
  if(audHost.endsWith("." + eventHost)) return true;
  return false;
}

function renderAnomaliesCard(){
  // For each token, determine its expected aud-host (if any). Then walk
  // host_usage rows where the token was used / presented and flag the
  // (fp, host) pairs whose host doesn't match.
  const expected = new Map();   // fp -> {audHost, audLabel}
  state.tokens.forEach(t => {
    const m = (t.claim_summary || "").match(/(?:^|;\s*)aud=([^;]+)/);
    const audRaw = m ? m[1].trim() : null;
    const audHost = audHostFromAudClaim(audRaw);
    if(audHost) expected.set(t.fp, {audHost, audLabel: audRaw,
      resourceName: t.resource && t.resource.name});
  });
  const findings = [];
  state.hostUsage.forEach(u => {
    if(!(u.role === "used" || u.role === "presented")) return;
    const exp = expected.get(u.fp);
    if(!exp) return;
    if(hostsCompatible(exp.audHost, u.host)) return;
    findings.push({fp: u.fp, eventHost: u.host, count: u.count,
                   expected: exp.audHost, label: exp.audLabel,
                   resource: exp.resourceName});
  });
  $("#anomalies-hint").textContent = findings.length===1 ? "1 mismatch" : `${findings.length} mismatches`;
  if(findings.length === 0){
    $("#anomalies-list").innerHTML = `<div class="empty">No tokens were observed at hosts that disagree with their <code>aud</code> claim.</div>`;
    return;
  }
  const rows = findings.sort((a,b) => b.count - a.count).map(f => `
    <tr class="row-clickable" data-jump-search="${escapeAttr(f.fp)}">
      <td><span class="token-fp">${escapeHtml(f.fp)}</span></td>
      <td><b>${escapeHtml(f.eventHost)}</b><br><span class="muted">presented ${f.count}x</span></td>
      <td>${escapeHtml(f.expected)}<br><span class="muted">${escapeHtml(f.resource||f.label||"")}</span></td>
    </tr>`).join("");
  $("#anomalies-list").innerHTML = `
    <table>
      <thead><tr><th>Token</th><th>Used at</th><th>Audience says</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

// --- Auth methods (amr) card ---------------------------------------------

function renderAmrCard(){
  const counts = new Map();
  state.tokens.forEach(t => {
    const m = (t.claim_summary || "").match(/(?:^|;\s*)amr=([^;]+)/);
    if(!m) return;
    // amr is rendered as a comma-joined list by stringify_claim. Split it.
    m[1].split(/[,\s]+/).map(s => s.trim()).filter(Boolean).forEach(method => {
      if(!counts.has(method)) counts.set(method, new Set());
      counts.get(method).add(t.fp);
    });
  });
  const list = Array.from(counts.entries())
    .map(([method, fps]) => ({method, count: fps.size}))
    .sort((a,b) => b.count - a.count);
  $("#amr-hint").textContent = list.length===1 ? "1 method" : `${list.length} methods`;
  if(list.length === 0){
    $("#amr-list").innerHTML = `<div class="empty">No JWT carried an <code>amr</code> claim.</div>`;
    return;
  }
  const rows = list.map(e => `
    <tr class="row-clickable" data-jump-search="amr=${escapeAttr(e.method)}">
      <td class="code">${escapeHtml(e.method)}</td>
      <td>${e.count}</td>
    </tr>`).join("");
  $("#amr-list").innerHTML = `
    <table>
      <thead><tr><th>Method</th><th>Tokens</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

// Inline security-feature badges for the token detail pane. Empty
// dash when none of the markers fired; otherwise a compact set of
// short badges with tooltips. Mirrors the data shown on the
// Security features summary card.
function renderSecurityFeaturesBadges(sf){
  if(!sf) return '<span class="muted">—</span>';
  const parts = [];
  if(sf.cae) parts.push(`<span class="badge brokerable" title="xms_cc contains CP1: CAE-capable">CAE</span>`);
  if(sf.pop){
    const kid = sf.pop_kid ? ` (kid=${escapeHtml(sf.pop_kid.slice(0,12))}…)` : "";
    parts.push(`<span class="badge broci" title="cnf claim present — proof-of-possession bound${sf.pop_pl ? '; xms_pl=' + escapeHtml(sf.pop_pl) : ''}">PoP${kid}</span>`);
  }
  if(typeof sf.acr === "string"){
    parts.push(`<span class="badge" title="acr (auth context)">acr=${escapeHtml(sf.acr)}</span>`);
  }
  if(Array.isArray(sf.acrs) && sf.acrs.length){
    parts.push(`<span class="badge foci" title="acrs (step-up auth requirement): ${escapeAttr(sf.acrs.join(', '))}">step-up</span>`);
  }
  if(Array.isArray(sf.amr) && sf.amr.length){
    parts.push(`<span class="badge" title="amr authentication methods">amr=${escapeHtml(sf.amr.join(','))}</span>`);
  }
  return parts.length ? parts.join(" ") : '<span class="muted">—</span>';
}

// --- Security features card ----------------------------------------------
//
// Counts how many tokens fired each CAE / PoP / step-up marker stored
// in ``tokens.security_features``. Clicking a row jumps to the Tokens
// tab pre-filtered to tokens that carry that marker — useful for
// "which of these access tokens are PoP-bound and which fall back to
// Bearer".

const SECURITY_FEATURE_LABELS = {
  cae:  ["CAE-capable",           "client signalled CP1 in xms_cc; the IDP may issue revocable tokens that downstream RPs must re-validate"],
  pop:  ["Proof-of-possession",   "cnf claim is present — token is bound to a caller-held key; Bearer-style replay against the audience will fail"],
  acr:  ["acr (auth context)",    "single acr claim recording the strength of the auth event (e.g. '1' plain, 'c1' MFA)"],
  acrs: ["acrs (step-up)",        "list of acrs values the resource will enforce; presence often indicates conditional-access step-up requirements"],
  amr:  ["amr (auth methods)",    "authentication methods used to issue the token (pwd, mfa, smartcard, pop, ...)"],
};

function renderSecurityCard(){
  // feature -> Set(fp); plus a few rollups for the stat tiles.
  const featCounts = new Map();
  let popKidGroups = new Map();   // pop_kid -> Set(fp): shared keys are a research signal
  let acrValues = new Map();      // acr value -> Set(fp)
  let amrValues = new Map();      // amr method -> Set(fp)
  let jwtTokens = 0;

  state.tokens.forEach(t => {
    if(t.sub_type === "jwt") jwtTokens++;
    const sf = t.security_features;
    if(!sf) return;
    for(const key of ["cae","pop","acr","acrs","amr"]){
      if(sf[key] === undefined || sf[key] === null) continue;
      if(Array.isArray(sf[key]) && sf[key].length === 0) continue;
      if(!featCounts.has(key)) featCounts.set(key, new Set());
      featCounts.get(key).add(t.fp);
    }
    if(sf.pop_kid){
      if(!popKidGroups.has(sf.pop_kid)) popKidGroups.set(sf.pop_kid, new Set());
      popKidGroups.get(sf.pop_kid).add(t.fp);
    }
    if(typeof sf.acr === "string"){
      if(!acrValues.has(sf.acr)) acrValues.set(sf.acr, new Set());
      acrValues.get(sf.acr).add(t.fp);
    }
    if(Array.isArray(sf.amr)){
      sf.amr.forEach(m => {
        if(!amrValues.has(m)) amrValues.set(m, new Set());
        amrValues.get(m).add(t.fp);
      });
    }
  });

  const caeN = (featCounts.get("cae") || new Set()).size;
  const popN = (featCounts.get("pop") || new Set()).size;
  const stepN = (featCounts.get("acrs") || new Set()).size;
  $("#security-hint").textContent =
    `${jwtTokens} jwt token(s) scanned`;
  $("#security-stats").innerHTML = `
    ${statTile(caeN, "CAE-capable", caeN ? "ok" : "")}
    ${statTile(popN, "PoP-bound",   popN ? "ok" : "")}
    ${statTile(stepN, "step-up req",stepN ? "warn" : "")}
  `;
  if(featCounts.size === 0){
    $("#security-list").innerHTML =
      `<div class="empty">No JWT in this capture carries CAE / PoP / step-up claims.<br>` +
      `<span class="muted" style="font-size:.78rem">(xms_cc=CP1, cnf, acr, acrs, amr)</span></div>`;
    return;
  }
  const featureRows = Array.from(featCounts.entries())
    .map(([key, fps]) => {
      const [label, hint] = SECURITY_FEATURE_LABELS[key] || [key, ""];
      return `<tr class="row-clickable" data-jump-feature="${escapeAttr(key)}" title="${escapeAttr(hint)}">
        <td>${escapeHtml(label)}</td>
        <td>${fps.size}</td>
      </tr>`;
    }).join("");

  // Surface kid groups with >1 token (multiple tokens bound to the
  // same proof key — useful for spotting key reuse across audiences).
  const sharedKidEntries = Array.from(popKidGroups.entries())
    .filter(([, fps]) => fps.size > 1)
    .sort((a,b) => b[1].size - a[1].size);
  const sharedKidHtml = sharedKidEntries.length === 0 ? "" : `
    <h4 style="margin:.6rem 0 .2rem;font-size:.74rem;color:var(--muted);text-transform:uppercase;letter-spacing:.04em">Shared PoP keys</h4>
    <table><thead><tr><th>cnf kid</th><th>Tokens</th></tr></thead>
    <tbody>${sharedKidEntries.map(([kid, fps]) => `
      <tr class="row-clickable" data-jump-search="${escapeAttr(kid)}">
        <td class="code" style="word-break:break-all">${escapeHtml(kid)}</td>
        <td>${fps.size}</td>
      </tr>`).join("")}</tbody></table>`;

  const acrEntries = Array.from(acrValues.entries())
    .sort((a,b) => b[1].size - a[1].size);
  const acrHtml = acrEntries.length === 0 ? "" : `
    <h4 style="margin:.6rem 0 .2rem;font-size:.74rem;color:var(--muted);text-transform:uppercase;letter-spacing:.04em">acr values</h4>
    <table><thead><tr><th>acr</th><th>Tokens</th></tr></thead>
    <tbody>${acrEntries.map(([v, fps]) => `
      <tr class="row-clickable" data-jump-search="acr=${escapeAttr(v)}">
        <td class="code">${escapeHtml(v)}</td>
        <td>${fps.size}</td>
      </tr>`).join("")}</tbody></table>`;

  $("#security-list").innerHTML = `
    <table>
      <thead><tr><th>Feature</th><th>Tokens</th></tr></thead>
      <tbody>${featureRows}</tbody>
    </table>
    ${sharedKidHtml}
    ${acrHtml}`;
}

// --- Refresh-token chains card -------------------------------------------
//
// In addition to the chain head/length/tail summary, each chain shows
// the *scope delta* across hops: scopes that appeared in the access
// tokens emitted alongside a later refresh that weren't present at the
// previous hop, and scopes that disappeared. Added scopes matched
// against RISKY_SCOPES get a "⚠ privilege expansion" badge — this is
// the FOCI/BroCI-style escalation signal researchers care about.

function scopesEmittedWithRefresh(rtFp){
  // Find any exchange whose output_fps include this refresh token; then
  // return the union of access-token scopes emitted by that exchange.
  // We use `state.tokens` (already loaded) for lookups.
  const tokenByFp = state._tokenByFpCache ||
    (state._tokenByFpCache = new Map(state.tokens.map(t => [t.fp, t])));
  for(const x of state.exchanges){
    if(!x.output_fps.includes(rtFp)) continue;
    const set = new Set();
    x.output_fps.forEach(fp => {
      const t = tokenByFp.get(fp);
      if(t && t.type === "access" && t.scopes_text){
        t.scopes_text.split(/\s+/).filter(Boolean)
          .forEach(s => set.add(s));
      }
    });
    if(set.size) return set;
  }
  return new Set();
}

function chainScopeDelta(chain){
  // Walk the chain, accumulating scope deltas at each hop. Returns
  // {added, removed, anyPrivilegedAdded, perHop[]} where perHop[i] is
  // {from, to, added, removed} for the i-th transition.
  const lowerPriv = RISKY_SCOPES.map(s => s.toLowerCase());
  const scopesPerHop = chain.map(rt => scopesEmittedWithRefresh(rt));
  const allAdded = new Set();
  const allRemoved = new Set();
  const perHop = [];
  for(let i = 1; i < scopesPerHop.length; i++){
    const prev = scopesPerHop[i-1];
    const cur = scopesPerHop[i];
    const a = []; const r = [];
    cur.forEach(s => { if(!prev.has(s)){ a.push(s); allAdded.add(s); } });
    prev.forEach(s => { if(!cur.has(s)){ r.push(s); allRemoved.add(s); } });
    perHop.push({from: chain[i-1], to: chain[i], added: a, removed: r});
  }
  const anyPrivilegedAdded = Array.from(allAdded).some(s => {
    const sl = s.toLowerCase();
    return lowerPriv.some(p => sl.includes(p));
  });
  return {
    added: Array.from(allAdded).sort(),
    removed: Array.from(allRemoved).sort(),
    anyPrivilegedAdded, perHop,
  };
}

function buildRefreshChains(){
  // Build successor map: refresh fp -> list of refresh fps it produces.
  // The graph here follows EXCHANGE BOUNDARIES, not strict 1:1 rotations,
  // because a single exchange can take one RT in and emit several RT/AT/IDT.
  const refreshFps = new Set(state.tokens.filter(t => t.type === "refresh")
                                          .map(t => t.fp));
  const succ = new Map();        // fp -> Set(next refresh fp)
  const pred = new Map();        // fp -> Set(previous refresh fp)
  state.exchanges.forEach(x => {
    const insRT = x.input_fps.filter(fp => refreshFps.has(fp));
    const outsRT = x.output_fps.filter(fp => refreshFps.has(fp));
    insRT.forEach(i => outsRT.forEach(o => {
      if(i === o) return;
      if(!succ.has(i)) succ.set(i, new Set());
      succ.get(i).add(o);
      if(!pred.has(o)) pred.set(o, new Set());
      pred.get(o).add(i);
    }));
  });
  // Heads: refresh fps with no predecessor RT.
  const heads = [];
  refreshFps.forEach(fp => { if(!pred.has(fp)) heads.push(fp); });
  // Walk from each head greedily following the first successor.
  const chains = heads.map(head => {
    const path = [head];
    const visited = new Set([head]);
    let cur = head;
    while(succ.has(cur)){
      const nexts = Array.from(succ.get(cur)).filter(n => !visited.has(n));
      if(nexts.length === 0) break;
      cur = nexts[0];
      visited.add(cur);
      path.push(cur);
    }
    return path;
  });
  // Idle = refresh fps that are heads of length-1 chains (never used as input).
  const idle = chains.filter(c => c.length === 1).map(c => c[0]);
  return {chains, idle, refreshFps, succ};
}

function renderChainsCard(){
  const tokenByFp = new Map(state.tokens.map(t => [t.fp, t]));
  // Memoized — the chain structure depends only on tokens + exchanges,
  // both of which are reset alongside state._chainsCache on every
  // /api/data load. Two cards (chains + the privilege rollup) and one
  // sequence-diagram path all reuse this.
  const {chains, idle} =
    state._chainsCache || (state._chainsCache = buildRefreshChains());
  const longest = chains.reduce((m, c) => Math.max(m, c.length), 0);
  $("#chains-hint").textContent = chains.length===1 ? "1 chain" : `${chains.length} chains`;
  $("#chains-stats").innerHTML = `
    ${statTile(chains.length, "chains")}
    ${statTile(longest, "longest chain", longest>2?"warn":"")}
    ${statTile(idle.length, "idle refresh tokens", idle.length?"warn":"")}
  `;
  if(chains.length === 0){
    $("#chains-list").innerHTML = `<div class="empty">No refresh tokens were captured.</div>`;
    return;
  }
  // Sort chains by length desc, idle last
  chains.sort((a,b) => b.length - a.length);
  // Compute each chain's scope-delta once and reuse for both the row
  // rendering and the privilege-expansion rollup tile.
  const deltas = chains.map(c => c.length >= 2 ? chainScopeDelta(c) : null);
  let privCount = 0;
  const rows = chains.map((c, ci) => {
    const head = tokenByFp.get(c[0]) || {};
    const tail = tokenByFp.get(c[c.length-1]) || {};
    const headApp = (head.app && head.app.name) ? head.app.name : "?";
    const tailApp = (tail.app && tail.app.name) ? tail.app.name : (c.length===1 ? headApp : "?");
    const idleBadge = c.length === 1 ? `<span class="badge warn" style="color:var(--warn);border-color:var(--warn)">idle</span>` : "";
    const fociBadge = head.foci_family ? `<span class="badge foci">FOCI:${escapeHtml(head.foci_family)}</span>` : "";

    // Scope delta across the chain. Single-hop chains have no delta.
    let deltaCell = '<span class="muted">—</span>';
    const d = deltas[ci];
    if(d){
      if(d.anyPrivilegedAdded) privCount++;
      const addedTip = d.added.length
        ? "added:\n  " + d.added.join("\n  ") : "added: (none)";
      const removedTip = d.removed.length
        ? "removed:\n  " + d.removed.join("\n  ") : "removed: (none)";
      const hopTip = d.perHop.map((h, i) =>
        `hop ${i+1}: ${h.from.slice(0,8)}→${h.to.slice(0,8)}` +
        (h.added.length ? `\n  +${h.added.join("\n  +")}` : "") +
        (h.removed.length ? `\n  -${h.removed.join("\n  -")}` : "")
      ).join("\n");
      const tip = `${addedTip}\n\n${removedTip}\n\n${hopTip}`;
      const privBadge = d.anyPrivilegedAdded
        ? ` <span class="badge" style="color:var(--danger);border-color:var(--danger)" title="An added scope matches the privileged-scope watchlist — possible privilege expansion across this chain.">⚠ priv</span>`
        : "";
      deltaCell = `<span class="code" title="${escapeAttr(tip)}">+${d.added.length} / -${d.removed.length}</span>${privBadge}`;
    }

    return `
      <tr class="row-clickable" data-jump-search="${escapeAttr(c[0])}">
        <td><span class="token-fp">${escapeHtml(c[0])}</span><br><span class="muted">${escapeHtml(headApp)}</span></td>
        <td>${c.length}</td>
        <td>${deltaCell}</td>
        <td><span class="token-fp">${escapeHtml(c[c.length-1])}</span><br><span class="muted">${escapeHtml(tailApp)}</span> ${idleBadge} ${fociBadge}</td>
      </tr>`;
  }).join("");
  if(privCount > 0){
    $("#chains-stats").insertAdjacentHTML("beforeend",
      statTile(privCount, "with priv expansion", "danger"));
  }
  $("#chains-list").innerHTML = `
    <table>
      <thead><tr><th>Head</th><th>Len</th><th title="Scope set added (+) and removed (-) across hops. Hover for full list.">Δ scopes</th><th>Tail</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

// --- Sources card --------------------------------------------------------

function renderSourcesCard(){
  // source_tag is a comma-separated list (UPSERT accumulates across passes).
  // Count tokens that mention each tag at least once.
  const counts = new Map();
  state.tokens.forEach(t => {
    if(!t.source_tag) return;
    t.source_tag.split(",").map(s => s.trim()).filter(Boolean).forEach(tag => {
      counts.set(tag, (counts.get(tag) || 0) + 1);
    });
  });
  const list = Array.from(counts.entries())
    .map(([tag, n]) => ({tag, n}))
    .sort((a, b) => b.n - a.n);
  $("#sources-hint").textContent = list.length === 1
    ? "1 source" : `${list.length} sources`;
  if(list.length === 0){
    $("#sources-list").innerHTML =
      `<div class="empty">No source tags recorded.</div>`;
    return;
  }
  const rows = list.map(s => `
    <tr class="row-clickable" data-jump-search="${escapeAttr(s.tag)}">
      <td><span class="code">${escapeHtml(s.tag)}</span></td>
      <td>${s.n}</td>
    </tr>`).join("");
  $("#sources-list").innerHTML = `
    <table>
      <thead><tr><th>Source</th><th>Tokens</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

// Live re-render of the validity card so expiry counts stay accurate.
let validityTimer = null;
function startValidityTimer(){
  if(validityTimer) clearInterval(validityTimer);
  validityTimer = setInterval(() => {
    if($("#summary").classList.contains("active")) renderValidityCard();
  }, 30000);
}

// --- jump-to-tokens delegation -------------------------------------------

document.addEventListener("click", (e) => {
  // Identity-timeline action: pick all tokens belonging to this user
  // (matched on user_identity), highlight them, drop into the Sequence
  // tab. Take precedence over the row-level data-jump-identity handler.
  const tlBtn = e.target.closest("[data-act-identity-timeline]");
  if(tlBtn){
    e.stopPropagation();
    const identity = tlBtn.dataset.actIdentityTimeline;
    openIdentityTimeline(identity);
    return;
  }
  const u = e.target.closest("[data-jump-user]");
  if(u){ jumpToTokens({search: u.dataset.jumpUser}); return; }
  const c = e.target.closest("[data-jump-client]");
  if(c){ jumpToTokens({search: c.dataset.jumpClient}); return; }
  const a = e.target.closest("[data-jump-aud]");
  if(a){ jumpToTokens({search: a.dataset.jumpAud}); return; }
  const t = e.target.closest("[data-jump-tenant]");
  if(t){ jumpToTokens({search: t.dataset.jumpTenant}); return; }
  const h = e.target.closest("[data-jump-host]");
  if(h){
    // Host doesn't appear in claim_summary; users probably want to filter
    // the activity sequence to events at this host instead, but the closest
    // we have today is to filter tokens whose issuer host matches.
    jumpToTokens({search: h.dataset.jumpHost}); return;
  }
  const feat = e.target.closest("[data-jump-feature]");
  if(feat){ jumpToTokens({feature: feat.dataset.jumpFeature}); return; }
  const ident = e.target.closest("[data-jump-identity]");
  if(ident){
    jumpToTokens({search: ident.dataset.jumpIdentity});
    return;
  }
  const s = e.target.closest("[data-jump-search]");
  if(s){ jumpToTokens({search: s.dataset.jumpSearch}); return; }
});

// Open a cross-capture identity timeline: highlight every token whose
// _identityBucket matches ``identity`` and open the Sequence tab. The
// existing sequence diagram already supports multi-fp ★ highlighting
// via state.selected, so this is just selection + tab switch.
function openIdentityTimeline(identity){
  const matching = state.tokens
    .filter(t => t._identityBucket === identity)
    .map(t => t.fp);
  if(matching.length === 0){
    flashStatus("no tokens for that identity");
    return;
  }
  state.selected = new Set(matching);
  state.sequenceFp = null;       // show full timeline, highlight in it
  renderTokens();                // sync checkboxes
  refreshSequence();
  openTab("sequence");
  flashStatus(`identity timeline: ${matching.length} tokens highlighted`);
}

function jumpToTokens(opts){
  // Reset all filter UI to defaults first, then apply requested overrides.
  $("#t-clear").click();
  if(opts.search != null){
    state.filters.search = opts.search.toString().toLowerCase();
    $("#t-search").value = opts.search;
  }
  if(opts.validity){
    state.filters.validity = opts.validity;
    $("#t-validity-filter").value = opts.validity;
  }
  if(opts.uses){
    state.filters.uses = opts.uses;
    $("#t-uses-filter").value = opts.uses;
  }
  if(opts.feature){
    state.filters.securityFeature = opts.feature;
    const chip = $("#t-filter-security");
    if(chip){
      chip.checked = true;
      const sel = $("#t-security-select");
      if(sel){ sel.value = opts.feature; sel.disabled = false; }
    }
  }
  renderTokens();
  openTab("tokens");
}

// --- Export helpers -------------------------------------------------------

function csvEscape(v){
  const s = (v==null) ? "" : v.toString();
  return /[,"\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

function downloadBlob(filename, content, mime){
  const blob = new Blob([content], {type: mime});
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 250);
}

function exportRowsCSV(filename, rows, columns){
  const header = columns.map(c => csvEscape(c.label)).join(",");
  const body = rows.map(r => columns.map(c =>
    csvEscape(c.get ? c.get(r) : r[c.key])).join(",")).join("\n");
  downloadBlob(filename, header + "\n" + body, "text/csv");
}

function exportRowsJSON(filename, rows, columns){
  const out = rows.map(r => {
    const o = {};
    columns.forEach(c => { o[c.key] = c.get ? c.get(r) : r[c.key]; });
    return o;
  });
  downloadBlob(filename, JSON.stringify(out, null, 2), "application/json");
}

const TOKEN_EXPORT_COLS = [
  {key:"fp", label:"FP"},
  {key:"sample", label:"Sample"},
  {key:"type", label:"Type"},
  {key:"sub_type", label:"Format"},
  {key:"uses", label:"Uses"},
  {key:"first_seen", label:"First seen"},
  {key:"last_seen", label:"Last seen"},
  {key:"issuer_host", label:"Issuer host"},
  {key:"foci_family", label:"FOCI family"},
  {key:"user_identity", label:"User identity"},
  {key:"tenant_id", label:"Tenant id"},
  {key:"exp_unix", label:"Expiry (unix)"},
  {key:"app_guid", label:"App GUID", get:t => t.app && t.app.guid || ""},
  {key:"app_name", label:"App name", get:t => t.app && t.app.name || ""},
  {key:"resource_guid", label:"Resource GUID", get:t => t.resource && t.resource.guid || ""},
  {key:"resource_name", label:"Resource name", get:t => t.resource && t.resource.name || ""},
  {key:"scopes_text", label:"Scopes / roles"},
  {key:"claim_summary", label:"Claim summary"},
];

const EXCHANGE_EXPORT_COLS = [
  {key:"seq", label:"#"}, {key:"time", label:"Time"},
  {key:"host", label:"Host"}, {key:"path", label:"Path"},
  {key:"grant_type", label:"Grant"}, {key:"client_id", label:"Client ID"},
  {key:"foci_family", label:"FOCI"},
  {key:"broci_broker_id", label:"BroCI broker"},
  {key:"broci_nested_id", label:"BroCI nested"},
  {key:"broci_evidence", label:"BroCI evidence"},
  {key:"input_fps", label:"Inputs", get:x => (x.input_fps||[]).join("|")},
  {key:"output_fps", label:"Outputs", get:x => (x.output_fps||[]).join("|")},
];

function visibleSortedTokens(){
  const tokens = applyTokenFilters();
  const {col, dir} = state.sort;
  tokens.sort((a,b) => {
    const r = compareVals(getTokenSortVal(a,col), getTokenSortVal(b,col));
    return dir==="asc" ? r : -r;
  });
  return tokens;
}
function visibleSortedExchanges(){
  const xs = applyXFilters();
  const {col, dir} = state.xsort;
  xs.sort((a,b) => {
    const r = compareVals(getXSortVal(a,col), getXSortVal(b,col));
    return dir==="asc" ? r : -r;
  });
  return xs;
}

$("#t-export-csv").addEventListener("click", () =>
  exportRowsCSV("tokens.csv", visibleSortedTokens(), TOKEN_EXPORT_COLS));
$("#t-export-json").addEventListener("click", () =>
  exportRowsJSON("tokens.json", visibleSortedTokens(), TOKEN_EXPORT_COLS));
$("#t-export-replay").addEventListener("click", downloadSelectedExport);
$("#x-export-csv").addEventListener("click", () =>
  exportRowsCSV("exchanges.csv", visibleSortedExchanges(), EXCHANGE_EXPORT_COLS));
$("#x-export-json").addEventListener("click", () =>
  exportRowsJSON("exchanges.json", visibleSortedExchanges(), EXCHANGE_EXPORT_COLS));

// --- URL hash persistence ------------------------------------------------

const ALL_TYPES = ["access","refresh","id","unknown"];
const ALL_FORMATS = ["jwt","opaque"];
let urlHashSyncing = false;

function encodeUrlState(){
  const f = state.filters;
  const q = new URLSearchParams();
  if(state.currentTab && state.currentTab !== "summary") q.set("tab", state.currentTab);
  if(f.search) q.set("q", f.search);
  if(f.uses && f.uses !== "all") q.set("uses", f.uses);
  if(f.validity && f.validity !== "all") q.set("v", f.validity);
  if(f.foci) q.set("foci", "1");
  if(f.broci) q.set("broci", "1");
  if(f.hasApp) q.set("hasApp", "1");
  if(f.hasRes) q.set("hasRes", "1");
  const types = Array.from(f.types).sort();
  if(types.join(",") !== "access,id,refresh") q.set("types", types.join(","));
  const fmts = Array.from(f.formats).sort();
  if(fmts.join(",") !== "jwt,opaque") q.set("formats", fmts.join(","));
  if(state.sort.col !== "first_seen" || state.sort.dir !== "asc"){
    q.set("sort", state.sort.col + ":" + state.sort.dir);
  }
  return q.toString();
}

function syncUrlHash(){
  if(urlHashSyncing) return;
  const enc = encodeUrlState();
  const next = enc ? "#" + enc : "";
  if(location.hash === next) return;
  // replaceState avoids polluting history with every keystroke.
  history.replaceState(null, "", location.pathname + location.search + next);
}

function applyUrlHash(){
  const raw = location.hash.replace(/^#/, "");
  if(!raw) return;
  const q = new URLSearchParams(raw);
  // filters
  const f = state.filters;
  f.search = (q.get("q") || "").toLowerCase();
  f.uses = q.get("uses") || "all";
  f.validity = q.get("v") || "all";
  f.foci = q.get("foci") === "1";
  f.broci = q.get("broci") === "1";
  f.hasApp = q.get("hasApp") === "1";
  f.hasRes = q.get("hasRes") === "1";
  const types = q.get("types");
  if(types !== null) f.types = new Set(types.split(",").filter(Boolean));
  else f.types = new Set(["access","refresh","id"]);
  const fmts = q.get("formats");
  if(fmts !== null) f.formats = new Set(fmts.split(",").filter(Boolean));
  else f.formats = new Set(["jwt","opaque"]);
  const sort = q.get("sort");
  if(sort){
    const [col, dir] = sort.split(":");
    if(col){ state.sort.col = col; state.sort.dir = (dir==="desc")?"desc":"asc"; }
  }
  // mirror UI controls
  $("#t-search").value = q.get("q") || "";
  $("#t-uses-filter").value = f.uses;
  $("#t-validity-filter").value = f.validity;
  ALL_TYPES.forEach(tt => {
    const id = "#t-filter-" + tt;
    const on = f.types.has(tt);
    $(id).checked = on;
    $(id).parentElement.classList.toggle("on", on);
  });
  ALL_FORMATS.forEach(ft => {
    const id = "#t-filter-" + ft;
    const on = f.formats.has(ft);
    $(id).checked = on;
    $(id).parentElement.classList.toggle("on", on);
  });
  [["#t-filter-foci","foci"], ["#t-filter-broci","broci"],
   ["#t-filter-app","hasApp"], ["#t-filter-resource","hasRes"]].forEach(([id, key]) => {
    $(id).checked = !!f[key];
    $(id).parentElement.classList.toggle("on", !!f[key]);
  });
  // tab last so any data-dependent renders happen
  const tab = q.get("tab") || "summary";
  if(["summary","tokens","exchanges","foci","broci","graph","sequence"].includes(tab)){
    state.currentTab = tab;
  }
}

window.addEventListener("hashchange", () => {
  urlHashSyncing = true;
  try{
    applyUrlHash();
    renderTokens();
    if(state.currentTab) openTabSilently(state.currentTab);
  } finally {
    urlHashSyncing = false;
  }
});

function openTabSilently(name){
  $$("#nav button").forEach(b => b.classList.toggle("active", b.dataset.tab===name));
  $$(".section").forEach(s => s.classList.toggle("active", s.id===name));
  if(name==="graph") refreshGraph();
  if(name==="sequence") refreshSequence();
}

// Wrap state-mutating filter handlers so any change is reflected in the hash.
function withSync(fn){ return (...args) => { fn(...args); syncUrlHash(); }; }
["#t-search","#t-uses-filter","#t-validity-filter",
 "#t-filter-access","#t-filter-refresh","#t-filter-id","#t-filter-unknown",
 "#t-filter-jwt","#t-filter-opaque",
 "#t-filter-foci","#t-filter-broci","#t-filter-app","#t-filter-resource"
].forEach(sel => {
  const el = $(sel);
  if(!el) return;
  ["change","input"].forEach(ev => el.addEventListener(ev, () => syncUrlHash()));
});
$$("#t-table thead th[data-sort]").forEach(th =>
  th.addEventListener("click", () => syncUrlHash()));
$("#t-clear").addEventListener("click", () => syncUrlHash());

// --- tokens tab -----------------------------------------------------------

function getTokenSortVal(t, col){
  switch(col){
    case "fp": return t.fp;
    case "type": return t.type;
    case "sub_type": return t.sub_type;
    case "uses": return t.uses|0;
    case "first_seen": return t.first_seen||"";
    case "last_seen": return t.last_seen||"";
    case "issuer_host": return t.issuer_host||"";
    case "app_name": return (t.app&&t.app.name)||"";
    case "resource_name": return (t.resource&&t.resource.name)||"";
    case "foci_family": return t.foci_family||"";
    default: return "";
  }
}
function compareVals(a,b){
  if(typeof a==="number" && typeof b==="number") return a-b;
  return (a||"").toString().localeCompare((b||"").toString());
}

function tokenValidity(t, nowSec){
  if(typeof t.exp_unix !== "number") return "unknown";
  return t.exp_unix > nowSec ? "valid" : "expired";
}

function applyTokenFilters(){
  const f = state.filters;
  const now = Math.floor(Date.now()/1000);
  return state.tokens.filter(t => {
    if(!f.types.has(t.type)) return false;
    if(!f.formats.has(t.sub_type)) return false;
    if(f.uses==="used" && !t._used) return false;
    if(f.uses==="unused" && t._used) return false;
    if(f.validity && f.validity!=="all"){
      if(tokenValidity(t, now) !== f.validity) return false;
    }
    if(f.foci && !t.foci_family) return false;
    if(f.broci && !t._brociKey) return false;
    if(f.hasApp && !(t.app && t.app.guid)) return false;
    if(f.hasRes && !(t.resource && t.resource.guid)) return false;
    if(f.securityFeature){
      const sf = t.security_features;
      if(!sf) return false;
      const v = sf[f.securityFeature];
      if(v === undefined || v === null) return false;
      if(Array.isArray(v) && v.length === 0) return false;
    }
    if(f.search && !t._search.includes(f.search)) return false;
    return true;
  });
}

function renderTokens(){
  const tokens = applyTokenFilters();
  const {col, dir} = state.sort;
  tokens.sort((a,b) => {
    const r = compareVals(getTokenSortVal(a,col), getTokenSortVal(b,col));
    return dir==="asc" ? r : -r;
  });
  const body = $("#t-body");
  body.innerHTML = tokens.map(t => {
    const sel = state.selected.has(t.fp);
    const exp = state.expanded.has(t.fp);
    const hl = state.highlight.has(t.fp);
    const iso = state.isolate.has(t.fp);
    const cls = [sel?"selected":"", exp?"expanded":""].join(" ").trim();
    const badge = `<span class="badge ${t.type}">${t.type}</span>`;
    const fociB = t.foci_family ? `<span class="badge foci">FOCI:${escapeHtml(t.foci_family)}</span>` : "";
    return `
<tr class="${cls}" data-fp="${escapeAttr(t.fp)}">
  <td><input type="checkbox" class="t-pick" ${sel?"checked":""}></td>
  <td><span class="token-fp">${escapeHtml(t.fp)}</span><br><span class="muted code">${escapeHtml(t.sample)}</span>
    ${hl?'<br><span class="badge foci">graph-hl</span>':""}${iso?'<span class="badge broci">graph-iso</span>':""}</td>
  <td>${badge}</td>
  <td>${escapeHtml(t.sub_type)}</td>
  <td>${t.uses|0}</td>
  <td class="muted">${escapeHtml(t.first_seen||"")}</td>
  <td class="muted">${escapeHtml(t.last_seen||"")}</td>
  <td>${escapeHtml(t.issuer_host||"")}</td>
  <td>${appLink(t.app)}</td>
  <td>${resLink(t.resource)}</td>
  <td>${fociB}</td>
</tr>${exp ? renderTokenDetailRow(t) : ""}`;
  }).join("") || `<tr><td colspan="11" class="empty">No tokens match the current filters.</td></tr>`;
  $("#t-count").textContent = `${tokens.length} of ${state.tokens.length} tokens shown · ${state.selected.size} selected`;
  $$("#t-table thead th[data-sort]").forEach(th => {
    const arrow = th.dataset.sort === col ? (dir==="asc"?"▲":"▼") : "";
    th.querySelector(".arrow")?.remove();
    th.insertAdjacentHTML("beforeend", `<span class="arrow">${arrow}</span>`);
  });
  $("#t-toggle-all").checked = tokens.length>0 && tokens.every(t => state.selected.has(t.fp));
  rebindExpandedDetails();
}

function renderTokenDetailRow(t){
  const cached = state.detailHtml.get(t.fp);
  const inner = cached || '<span class="muted">Loading details…</span>';
  return `<tr class="detail-row" data-detail-for="${escapeAttr(t.fp)}"><td colspan="11"><div class="detail-pad" id="detail-${escapeAttr(t.fp)}">${inner}</div></td></tr>`;
}

// Re-bind action-button listeners on a freshly-rendered detail-pad.
// Called both right after loadTokenDetail finishes and after a live-poll
// re-render restores cached HTML (innerHTML wipes the listeners).
function bindDetailActions(fp){
  document.querySelectorAll(`#detail-${cssEscape(fp)} button[data-act]`).forEach(btn => {
    btn.addEventListener("click", () => {
      const fp2 = btn.dataset.fp;
      if(btn.dataset.act==="hl"){ state.highlight = new Set([fp2]); refreshGraph(); openTab("graph"); }
      else if(btn.dataset.act==="iso"){ state.isolate = new Set([fp2]); state.highlight = new Set([fp2]); refreshGraph(); openTab("graph"); }
      else if(btn.dataset.act==="seq"){ state.sequenceFp = fp2; refreshSequence(); openTab("sequence"); }
      else if(btn.dataset.act==="copy"){ copyTokenExport(fp2, btn.dataset.fmt || "json"); }
      else if(btn.dataset.act==="dl"){ downloadTokenExport(fp2, btn.dataset.fmt || "json"); }
      else if(btn.dataset.act==="copy-cmd"){
        const idx = btn.dataset.idx;
        const pre = document.querySelector(
          `#detail-${cssEscape(fp2)} pre[data-cmd-idx="${idx}"]`);
        if(pre){
          copyToClipboard(pre.textContent).then(ok =>
            flashStatus(ok ? "copied command" : "copy failed"));
        }
      }
    });
  });
}

// Restore expanded-detail panes after a token-table re-render. If the
// cache already has HTML for an expanded fp, it was placed in the DOM by
// renderTokenDetailRow — we just need to re-bind listeners. If not (the
// click that opened it hasn't loaded yet, or the cache was cleared), we
// kick off the fetch.
function rebindExpandedDetails(){
  for(const fp of state.expanded){
    if(state.detailHtml.has(fp)){
      bindDetailActions(fp);
    } else {
      loadTokenDetail(fp).catch(()=>{});
    }
  }
}

// Force-refresh every expanded detail panel from the server. Called on
// the live-poll path: the cached HTML stays visible (no flicker) while
// the fetch is in flight, then gets seamlessly replaced.
function refreshExpandedDetails(){
  for(const fp of state.expanded){
    loadTokenDetail(fp).catch(()=>{});
  }
}

// --- Export helpers -------------------------------------------------------
// Built once we have the token detail in hand (which we cache anyway). Each
// helper either writes to the clipboard or triggers a file download. We
// fetch the detail again on demand instead of stashing it in a side map —
// state.detailHtml only holds the rendered HTML, not the source object.

async function fetchTokenDetailRaw(fp){
  const r = await fetch("/api/token/" + encodeURIComponent(fp));
  if(!r.ok) throw new Error("token fetch failed: " + r.status);
  return r.json();
}

function buildBearerHeader(t){ return "Authorization: Bearer " + t.raw; }

function buildCurlExample(t){
  // The audience claim is the most common replay target for an access
  // token. Fall back to the issuer host or a placeholder.
  const aud = (t.jwt_payload && t.jwt_payload.aud) || "";
  const target = aud && /^https?:\/\//.test(aud) ? aud :
                 aud ? "https://" + aud :
                 (t.issuer_host ? "https://" + t.issuer_host + "/{path}" :
                                  "https://{host}/{path}");
  return `curl -H 'Authorization: Bearer ${t.raw}' '${target}'`;
}

function buildTokenExportJson(t){
  return JSON.stringify({
    fp: t.fp, type: t.type, sub_type: t.sub_type,
    raw: t.raw,
    sample: t.sample,
    first_seen: t.first_seen, last_seen: t.last_seen,
    issuer_host: t.issuer_host,
    app: t.app, resource: t.resource,
    foci_family: t.foci_family,
    user_identity: t.user_identity,
    tenant_id: t.tenant_id,
    scopes_text: t.scopes_text,
    exp_unix: t.exp_unix,
    jwt_header: t.jwt_header, jwt_payload: t.jwt_payload,
    events: t.events,
    exchanges_as_input: t.exchanges_as_input,
    exchanges_as_output: t.exchanges_as_output,
  }, null, 2);
}

// Emit a single-token JSON object that matches roadtools' token-cache
// shape (the contents of ~/.roadtools_auth). Save the file as
// ".roadtools_auth" and any roadtx subcommand will pick it up — or pass
// it explicitly via `roadtx <cmd> --tokens-file <path>`. Fields we don't
// know are omitted; roadtx tolerates a partial record for many commands.
function buildRoadtxJson(t){
  const claims = t.jwt_payload || {};
  const out = { tokenType: "Bearer" };
  if(t.type === "refresh") out.refreshToken = t.raw;
  else if(t.type === "id") out.idToken = t.raw;
  else out.accessToken = t.raw;  // access or unknown
  if(t.exp_unix) out.expiresOn = String(t.exp_unix);
  if(claims.iat) out.notBefore = String(claims.iat);
  if(claims.nbf) out.notBefore = String(claims.nbf);
  if(t.tenant_id || claims.tid) out.tenantId = t.tenant_id || claims.tid;
  const cid = claims.appid || (t.app && t.app.guid);
  if(cid) out._clientId = cid;
  if(claims.aud) out.resource = claims.aud;
  if(t.foci_family) out.foci = String(t.foci_family);
  if(claims.scp) out.scope = claims.scp;
  return JSON.stringify(out, null, 2);
}

// Pre-fill the most common replay / inspection commands using the
// token's claims and (when --store-tokens is enabled) its full raw
// value. When raw is unavailable, the commands still render with a
// <TOKEN> placeholder so the snippet works as a documentation reference.
function buildCommandPreviews(t){
  const raw = t.raw || "<TOKEN>";
  const claims = t.jwt_payload || {};
  const tid = t.tenant_id || claims.tid || "<TENANT_ID>";
  const cid = claims.appid || (t.app && t.app.guid) || "<CLIENT_ID>";
  const aud = claims.aud || "";
  const target = aud && /^https?:\/\//.test(aud) ? aud :
                 aud ? "https://" + aud :
                 (t.issuer_host ? "https://" + t.issuer_host : "<URL>");
  const cmds = [];

  if(t.sub_type === "jwt"){
    cmds.push({
      label: "roadtx describe — decode the JWT (no network)",
      cmd: `roadtx describe -t '${raw}'`,
    });
  }

  if(t.type === "refresh"){
    cmds.push({
      label: "roadtx auth — exchange this refresh token for fresh tokens",
      cmd: `roadtx auth --refresh-token '${raw}' -c ${cid} -t ${tid}`,
    });
    // OAuth-equivalent curl for users not using roadtx
    cmds.push({
      label: "curl — POST /token to exchange the refresh token",
      cmd: `curl -X POST 'https://login.microsoftonline.com/${tid}/oauth2/v2.0/token' \\\n  -d 'grant_type=refresh_token' \\\n  -d 'client_id=${cid}' \\\n  -d 'refresh_token=${raw}' \\\n  -d 'scope=openid offline_access ${aud ? aud + "/.default" : ".default"}'`,
    });
  }

  if(t.type === "access" || t.type === "id" || t.type === "unknown"){
    cmds.push({
      label: "curl — replay against the token's audience",
      cmd: `curl -H 'Authorization: Bearer ${raw}' '${target}'`,
    });
    cmds.push({
      label: "Python (requests)",
      cmd: `import requests\nr = requests.get(\n    '${target}',\n    headers={'Authorization': 'Bearer ${raw}'},\n)\nprint(r.status_code, r.text[:500])`,
    });
    cmds.push({
      label: "PowerShell (Invoke-RestMethod)",
      cmd: `Invoke-RestMethod -Uri '${target}' \`\n  -Headers @{ Authorization = 'Bearer ${raw}' }`,
    });
  }

  cmds.push({
    label: "roadtools token cache — save as .roadtools_auth",
    cmd: buildRoadtxJson(t),
  });

  return cmds;
}

async function copyToClipboard(text){
  // navigator.clipboard requires a secure context; fall back to a
  // throwaway textarea + execCommand for HTTP localhost.
  if(navigator.clipboard && window.isSecureContext){
    try{ await navigator.clipboard.writeText(text); return true; }
    catch(e){ /* fall through */ }
  }
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.style.position = "fixed"; ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try{ ok = document.execCommand("copy"); } catch(e){ ok = false; }
  document.body.removeChild(ta);
  return ok;
}

function flashStatus(msg, ms){
  const ind = document.getElementById("live-status");
  if(!ind) return;
  const prev = ind.textContent;
  ind.textContent = msg;
  setTimeout(() => { ind.textContent = prev; }, ms || 1800);
}

async function copyTokenExport(fp, fmt){
  try{
    const t = await fetchTokenDetailRaw(fp);
    if(!t.raw){ flashStatus("no raw token stored — re-ingest with --store-tokens"); return; }
    let text;
    if(fmt === "bearer") text = buildBearerHeader(t);
    else if(fmt === "curl") text = buildCurlExample(t);
    else if(fmt === "json") text = buildTokenExportJson(t);
    else if(fmt === "roadtx") text = buildRoadtxJson(t);
    else text = t.raw;
    const ok = await copyToClipboard(text);
    flashStatus(ok ? `copied ${fmt} (${text.length} chars)` : "copy failed");
  } catch(err){
    flashStatus("export failed: " + err.message);
  }
}

async function downloadTokenExport(fp, fmt){
  try{
    const t = await fetchTokenDetailRaw(fp);
    if(!t.raw){ flashStatus("no raw token stored — re-ingest with --store-tokens"); return; }
    let text, ext, mime, name;
    if(fmt === "raw"){
      text = t.raw; ext = "txt"; mime = "text/plain";
      name = `token-${fp.slice(0,12)}.${ext}`;
    } else if(fmt === "roadtx"){
      text = buildRoadtxJson(t); ext = "json"; mime = "application/json";
      // Rename to ".roadtools_auth" before pointing roadtx at it.
      name = `roadtx-${fp.slice(0,12)}.${ext}`;
    } else {
      text = buildTokenExportJson(t); ext = "json"; mime = "application/json";
      name = `token-${fp.slice(0,12)}.${ext}`;
    }
    const blob = new Blob([text], {type: mime});
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = name;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    flashStatus(`downloaded ${name}`);
  } catch(err){
    flashStatus("export failed: " + err.message);
  }
}

async function downloadSelectedExport(){
  const fps = Array.from(state.selected);
  if(fps.length === 0){ flashStatus("no tokens selected"); return; }
  try{
    const r = await fetch("/api/export?fps=" + encodeURIComponent(fps.join(",")));
    if(!r.ok) throw new Error("export failed: " + r.status);
    const data = await r.json();
    const blob = new Blob([JSON.stringify(data, null, 2)],
                         {type: "application/json"});
    const url = URL.createObjectURL(blob);
    const stamp = new Date().toISOString().replace(/[:.]/g,"-");
    const a = document.createElement("a");
    a.href = url; a.download = `tokens-export-${stamp}.json`;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    const stored = data.tokens.filter(t => t.raw).length;
    flashStatus(`exported ${data.count} tokens (${stored} with raw)`);
  } catch(err){
    flashStatus("export failed: " + err.message);
  }
}

async function loadTokenDetail(fp){
  const r = await fetch("/api/token/" + encodeURIComponent(fp));
  if(!r.ok){ throw new Error("token detail fetch failed: " + r.status); }
  const t = await r.json();
  const events = t.events || [];
  const claims = t.jwt_payload || {};
  const claimRows = Object.keys(claims).sort().map(k =>
    `<tr><td class="code muted">${escapeHtml(k)}</td><td class="code" style="white-space:pre-wrap;word-break:break-all">${escapeHtml(typeof claims[k]==="object" ? JSON.stringify(claims[k],null,2) : claims[k])}</td></tr>`
  ).join("");
  const eventRows = events.map(e => `
    <tr><td>${e.seq}</td><td class="muted">${escapeHtml(e.time||"")}</td>
        <td>${escapeHtml(e.host||"")}</td><td>${escapeHtml(e.method||"")}</td>
        <td class="code" style="word-break:break-all">${escapeHtml(e.path||"")}</td>
        <td>${e.status||""}</td><td>${escapeHtml(e.direction||"")}</td>
        <td>${escapeHtml(e.role||"")}</td>
        <td class="code">${escapeHtml(e.source||"")}</td>
        <td class="code">${escapeHtml(e.client_id||"")}</td>
        <td class="code">${escapeHtml(e.broci_broker_id||"")}</td></tr>`).join("");
  const exTable = (label, rows) => rows.length===0 ? "" : `
    <h4>${label}</h4>
    <table><thead><tr><th>#</th><th>Time</th><th>Host</th><th>Path</th><th>Grant</th><th>Client ID</th><th>FOCI</th><th>BroCI</th><th>Inputs</th><th>Outputs</th></tr></thead>
    <tbody>${rows.map(x => exchangeRowHtml(x)).join("")}</tbody></table>`;
  const detail = `
    <h3>Token <span class="token-fp">${escapeHtml(t.fp)}</span> · <span class="badge ${t.type}">${t.type}</span> · ${escapeHtml(t.sub_type)} · uses=${t.uses}</h3>
    <div class="detail-grid">
      <div><label>Sample</label><span class="code">${escapeHtml(t.sample)}</span></div>
      <div><label>Issuer host</label>${escapeHtml(t.issuer_host||"(not observed)")}</div>
      <div><label>First seen</label>${escapeHtml(t.first_seen||"")}</div>
      <div><label>Last seen</label>${escapeHtml(t.last_seen||"")}</div>
      <div><label>FOCI family (wire)</label>${escapeHtml(t.foci_family||"")}</div>
      <div><label>App</label>${appLink(t.app)||'<span class="muted">—</span>'}</div>
      <div><label>Resource (aud)</label>${resLink(t.resource)||'<span class="muted">—</span>'}</div>
      <div><label>Security features</label>${renderSecurityFeaturesBadges(t.security_features)}</div>
    </div>
    <div class="row-controls">
      <button class="tinybtn" data-act="hl" data-fp="${escapeAttr(t.fp)}">Highlight in Graph</button>
      <button class="tinybtn" data-act="iso" data-fp="${escapeAttr(t.fp)}">Isolate in Graph</button>
      <button class="tinybtn" data-act="seq" data-fp="${escapeAttr(t.fp)}">Show in Sequence</button>
    </div>
    <div class="row-controls">
      <span class="muted" style="font-size:.78rem">Export:</span>
      ${t.raw ? `
        <button class="tinybtn" data-act="copy" data-fmt="raw" data-fp="${escapeAttr(t.fp)}" title="Copy the full token string to the clipboard">Copy raw</button>
        <button class="tinybtn" data-act="copy" data-fmt="bearer" data-fp="${escapeAttr(t.fp)}" title="Copy 'Authorization: Bearer &lt;token&gt;'">Copy Bearer header</button>
        <button class="tinybtn" data-act="copy" data-fmt="curl" data-fp="${escapeAttr(t.fp)}" title="Copy a curl one-liner that uses the token">Copy curl example</button>
        <button class="tinybtn" data-act="dl" data-fmt="json" data-fp="${escapeAttr(t.fp)}" title="Download the token as JSON (raw + claims + events)">Download JSON</button>
        <button class="tinybtn" data-act="copy" data-fmt="roadtx" data-fp="${escapeAttr(t.fp)}" title="Copy a roadtools-format token cache JSON">Copy as roadtx</button>
        <button class="tinybtn" data-act="dl" data-fmt="roadtx" data-fp="${escapeAttr(t.fp)}" title="Download a roadtools-format token cache file (rename to .roadtools_auth before use)">Download .roadtools_auth</button>
      ` : `
        <span class="muted" style="font-size:.78rem">Raw token not stored. Re-ingest with <code>--store-tokens</code> for one-click copy / replay.</span>
      `}
    </div>
    ${(() => {
      // Pre-filled invocations for replay / inspection tools. Each block
      // has a Copy button that grabs the <pre>'s textContent.
      const cmds = buildCommandPreviews(t);
      const blocks = cmds.map((c, i) => `
        <div style="margin:.5rem 0">
          <div style="display:flex;align-items:center;gap:.5rem;margin-bottom:.15rem">
            <span class="muted" style="font-size:.74rem;text-transform:uppercase;letter-spacing:.04em">${escapeHtml(c.label)}</span>
            <button class="tinybtn" data-act="copy-cmd" data-idx="${i}" data-fp="${escapeAttr(t.fp)}">Copy</button>
          </div>
          <pre data-cmd-idx="${i}">${escapeHtml(c.cmd)}</pre>
        </div>
      `).join("");
      return `
      <details>
        <summary>Command preview <span class="muted">(${cmds.length} snippets — roadtx, curl, Python, PowerShell)</span></summary>
        ${t.raw ? "" : `<div class="muted" style="font-size:.78rem;margin:.3rem 0">Tokens are shown as <code>&lt;TOKEN&gt;</code>. Re-ingest with <code>--store-tokens</code> to pre-fill them.</div>`}
        ${blocks}
      </details>`;
    })()}
    ${t.jwt_payload ? `
      <details open>
        <summary>JWT claim summary (<span class="muted">${Object.keys(claims).length} claims</span>)</summary>
        <table style="margin-top:.4rem"><tbody>${claimRows}</tbody></table>
      </details>
      <details>
        <summary>JWT header (raw JSON)</summary>
        <pre>${escapeHtml(JSON.stringify(t.jwt_header, null, 2))}</pre>
      </details>
      <details>
        <summary>JWT payload (raw JSON)</summary>
        <pre>${escapeHtml(JSON.stringify(t.jwt_payload, null, 2))}</pre>
      </details>
    ` : `<div class="muted">Token is opaque (no decodable JWT structure).</div>`}
    <details ${events.length<25?"open":""}>
      <summary>Events (<span class="muted">${events.length}</span>)</summary>
      <div class="scroll" style="max-height:40vh;margin-top:.4rem">
        <table><thead><tr><th>#</th><th>Time</th><th>Host</th><th>Method</th><th>Path</th><th>Status</th><th>Dir</th><th>Role</th><th>Source</th><th>Client ID</th><th>BroCI broker</th></tr></thead>
        <tbody>${eventRows||'<tr><td colspan="11" class="empty">No events.</td></tr>'}</tbody></table>
      </div>
    </details>
    ${exTable("Exchanges where this token was an INPUT", t.exchanges_as_input||[])}
    ${exTable("Exchanges where this token was an OUTPUT", t.exchanges_as_output||[])}`;
  state.detailHtml.set(fp, detail);
  const el = document.getElementById("detail-" + cssEscape(fp));
  if(el) el.innerHTML = detail;
  bindDetailActions(fp);
}

function cssEscape(s){
  // CSS.escape polyfill-ish: token fps are already [a-f0-9]+ so this is safe.
  return s.replace(/[^A-Za-z0-9_-]/g, "_");
}

function exchangeRowHtml(x){
  const broci = x.broci_broker_id ? `broker=${escapeHtml(x.broci_broker_id)}<br>nested=${escapeHtml(x.broci_nested_id||"?")}<br><span class="muted">${escapeHtml(x.broci_evidence||"")}</span>` : "";
  return `<tr><td>${x.seq}</td><td class="muted">${escapeHtml(x.time||"")}</td>
    <td>${escapeHtml(x.host||"")}</td>
    <td class="code" style="word-break:break-all">${escapeHtml(x.path||"")}</td>
    <td>${escapeHtml(x.grant_type||"")}</td>
    <td class="code">${escapeHtml(x.client_id||"")}</td>
    <td>${x.foci_family ? `<span class="badge foci">${escapeHtml(x.foci_family)}</span>` : ""}</td>
    <td>${broci?`<span class="badge broci">BroCI</span><br>${broci}`:""}</td>
    <td class="code">${(x.input_fps||[]).map(escapeHtml).join("<br>")}</td>
    <td class="code">${(x.output_fps||[]).map(escapeHtml).join("<br>")}</td></tr>`;
}

function openTab(name){
  state.currentTab = name;
  $$("#nav button").forEach(b => b.classList.toggle("active", b.dataset.tab===name));
  $$(".section").forEach(s => s.classList.toggle("active", s.id===name));
  if(name==="graph") refreshGraph();
  if(name==="sequence") refreshSequence();
  syncUrlHash();
}

// Token table event delegation
$("#t-body").addEventListener("click", e => {
  const tr = e.target.closest("tr");
  if(!tr || !tr.dataset.fp) return;
  const fp = tr.dataset.fp;
  if(e.target.classList.contains("t-pick")){
    if(e.target.checked) state.selected.add(fp); else state.selected.delete(fp);
    renderTokens(); return;
  }
  // Click outside the checkbox toggles expansion
  if(e.target.tagName === "INPUT") return;
  if(state.expanded.has(fp)){
    state.expanded.delete(fp);
    renderTokens();
  } else {
    state.expanded.add(fp);
    renderTokens();
    loadTokenDetail(fp).catch(err => {
      const el = document.getElementById("detail-" + cssEscape(fp));
      if(el) el.innerHTML = `<span class="warning">Failed to load detail: ${escapeHtml(err.message)}</span>`;
    });
  }
});

// Sort
$$("#t-table thead th[data-sort]").forEach(th => th.addEventListener("click", () => {
  const c = th.dataset.sort;
  if(state.sort.col === c){ state.sort.dir = state.sort.dir==="asc"?"desc":"asc"; }
  else { state.sort.col = c; state.sort.dir = "asc"; }
  renderTokens();
}));

// Filters
$("#t-search").addEventListener("input", e => { state.filters.search = e.target.value.trim().toLowerCase(); renderTokens(); });
function bindTypeChip(id, name, key){
  $(id).addEventListener("change", e => {
    if(e.target.checked) state.filters[key].add(name); else state.filters[key].delete(name);
    e.target.parentElement.classList.toggle("on", e.target.checked);
    renderTokens();
  });
  // initial chip state
  $(id).parentElement.classList.toggle("on", $(id).checked);
}
bindTypeChip("#t-filter-access","access","types");
bindTypeChip("#t-filter-refresh","refresh","types");
bindTypeChip("#t-filter-id","id","types");
bindTypeChip("#t-filter-unknown","unknown","types");
bindTypeChip("#t-filter-jwt","jwt","formats");
bindTypeChip("#t-filter-opaque","opaque","formats");
$("#t-uses-filter").addEventListener("change", e => { state.filters.uses = e.target.value; renderTokens(); });
$("#t-validity-filter").addEventListener("change", e => { state.filters.validity = e.target.value; renderTokens(); });
function bindBoolChip(id, key){
  $(id).addEventListener("change", e => {
    state.filters[key] = e.target.checked;
    e.target.parentElement.classList.toggle("on", e.target.checked);
    renderTokens();
  });
}
bindBoolChip("#t-filter-foci","foci");
bindBoolChip("#t-filter-broci","broci");
bindBoolChip("#t-filter-app","hasApp");
bindBoolChip("#t-filter-resource","hasRes");
// Security-feature chip + select: chip on/off toggles the constraint,
// the select picks which feature to require.
$("#t-filter-security").addEventListener("change", e => {
  e.target.parentElement.classList.toggle("on", e.target.checked);
  const sel = $("#t-security-select");
  sel.disabled = !e.target.checked;
  state.filters.securityFeature = e.target.checked ? sel.value : null;
  renderTokens();
});
$("#t-security-select").addEventListener("change", e => {
  if($("#t-filter-security").checked){
    state.filters.securityFeature = e.target.value;
    renderTokens();
  }
});
$("#t-clear").addEventListener("click", () => {
  state.filters = { search:"", types:new Set(["access","refresh","id"]),
    formats:new Set(["jwt","opaque"]), uses:"all", validity:"all",
    foci:false, broci:false, hasApp:false, hasRes:false,
    securityFeature: null };
  $("#t-search").value="";
  ["#t-filter-access","#t-filter-refresh","#t-filter-id"].forEach(id=>{$(id).checked=true;$(id).parentElement.classList.add("on");});
  ["#t-filter-jwt","#t-filter-opaque"].forEach(id=>{$(id).checked=true;$(id).parentElement.classList.add("on");});
  ["#t-filter-unknown","#t-filter-foci","#t-filter-broci","#t-filter-app","#t-filter-resource","#t-filter-security"].forEach(id=>{$(id).checked=false;$(id).parentElement.classList.remove("on");});
  $("#t-security-select").disabled = true;
  $("#t-uses-filter").value="all";
  $("#t-validity-filter").value="all";
  renderTokens();
});

// Selection / actions
$("#t-toggle-all").addEventListener("change", e => {
  const visible = applyTokenFilters();
  if(e.target.checked) visible.forEach(t => state.selected.add(t.fp));
  else visible.forEach(t => state.selected.delete(t.fp));
  renderTokens();
});
$("#t-select-all").addEventListener("click", () => {
  applyTokenFilters().forEach(t => state.selected.add(t.fp));
  renderTokens();
});
$("#t-clear-sel").addEventListener("click", () => { state.selected.clear(); renderTokens(); });
$("#t-highlight-graph").addEventListener("click", () => {
  state.highlight = new Set(state.selected);
  refreshGraph();
  openTab("graph");
});
$("#t-isolate-graph").addEventListener("click", () => {
  state.isolate = new Set(state.selected);
  state.highlight = new Set(state.selected);
  refreshGraph();
  openTab("graph");
});
$("#t-show-sequence").addEventListener("click", () => {
  if(state.selected.size === 1){
    state.sequenceFp = Array.from(state.selected)[0];
  } else if(state.selected.size === 0){
    state.sequenceFp = null;
  } else {
    state.sequenceFp = null;  // multi: show all but highlight
  }
  refreshSequence();
  openTab("sequence");
});

// --- exchanges tab --------------------------------------------------------

function getXSortVal(x, col){
  switch(col){
    case "seq": return x.seq|0;
    case "time": return x.time||"";
    case "host": return x.host||"";
    case "path": return x.path||"";
    case "grant_type": return x.grant_type||"";
    case "client_id": return x.client_id||"";
    case "foci_family": return x.foci_family||"";
    default: return "";
  }
}
function applyXFilters(){
  const f = state.xfilters;
  return state.exchanges.filter(x => {
    if(f.foci && !x.foci_family) return false;
    if(f.broci && !x.broci_broker_id) return false;
    if(f.search && !x._search.includes(f.search)) return false;
    return true;
  });
}
function renderExchanges(){
  const xs = applyXFilters();
  const {col, dir} = state.xsort;
  xs.sort((a,b) => {
    const r = compareVals(getXSortVal(a,col), getXSortVal(b,col));
    return dir==="asc" ? r : -r;
  });
  $("#x-body").innerHTML = xs.map(exchangeRowHtml).join("") ||
    `<tr><td colspan="10" class="empty">No exchanges match the current filters.</td></tr>`;
  $$("#x-table thead th[data-sort]").forEach(th => {
    const arrow = th.dataset.sort === col ? (dir==="asc"?"▲":"▼") : "";
    th.querySelector(".arrow")?.remove();
    th.insertAdjacentHTML("beforeend", `<span class="arrow">${arrow}</span>`);
  });
}
$$("#x-table thead th[data-sort]").forEach(th => th.addEventListener("click", () => {
  const c = th.dataset.sort;
  if(state.xsort.col === c){ state.xsort.dir = state.xsort.dir==="asc"?"desc":"asc"; }
  else { state.xsort.col = c; state.xsort.dir = "asc"; }
  renderExchanges();
}));
$("#x-search").addEventListener("input", e => { state.xfilters.search = e.target.value.trim().toLowerCase(); renderExchanges(); });
$("#x-filter-foci").addEventListener("change", e => { state.xfilters.foci = e.target.checked; e.target.parentElement.classList.toggle("on",e.target.checked); renderExchanges(); });
$("#x-filter-broci").addEventListener("change", e => { state.xfilters.broci = e.target.checked; e.target.parentElement.classList.toggle("on",e.target.checked); renderExchanges(); });
$("#x-clear").addEventListener("click", () => {
  state.xfilters = { search:"", foci:false, broci:false };
  $("#x-search").value="";
  ["#x-filter-foci","#x-filter-broci"].forEach(id=>{$(id).checked=false;$(id).parentElement.classList.remove("on");});
  renderExchanges();
});

// --- FOCI tab -------------------------------------------------------------

function renderFoci(){
  const fociTokens = state.tokens.filter(t => t.foci_family);
  const fociX = state.exchanges.filter(x => x.foci_family);
  if(fociTokens.length===0 && fociX.length===0){
    $("#foci-body").innerHTML = `<div class="empty">No FOCI markers observed in this capture.</div>`;
    return;
  }
  const tokRows = fociTokens.map(t => `
    <tr><td><span class="token-fp">${escapeHtml(t.fp)}</span></td>
        <td>${escapeHtml(t.foci_family)}</td>
        <td>${appLink(t.app)}</td>
        <td class="muted">${escapeHtml(t.first_seen||"")}</td>
        <td class="muted">${escapeHtml(t.last_seen||"")}</td></tr>`).join("");
  const xRows = fociX.map(exchangeRowHtml).join("");
  $("#foci-body").innerHTML = `
    <h3>FOCI refresh tokens</h3>
    <table><thead><tr><th>FP</th><th>Family</th><th>App</th><th>First seen</th><th>Last seen</th></tr></thead>
    <tbody>${tokRows||'<tr><td colspan="5" class="empty">None.</td></tr>'}</tbody></table>
    <h3 style="margin-top:1rem">FOCI-flagged exchanges</h3>
    <table><thead><tr><th>#</th><th>Time</th><th>Host</th><th>Path</th><th>Grant</th><th>Client ID</th><th>FOCI</th><th>BroCI</th><th>Inputs</th><th>Outputs</th></tr></thead>
    <tbody>${xRows||'<tr><td colspan="10" class="empty">None.</td></tr>'}</tbody></table>`;
}

// --- BroCI tab ------------------------------------------------------------

function renderBroci(){
  const xs = state.exchanges.filter(x => x.broci_broker_id);
  if(xs.length===0){
    $("#broci-body").innerHTML = `<div class="empty">No BroCI / NAA markers observed in this capture.</div>`;
    return;
  }
  const rows = xs.map(x => {
    const evidenceList = (x.broci_evidence||"").split(/,\s*/).filter(Boolean)
      .map(e => `<li class="code">${escapeHtml(e)}</li>`).join("");
    return `<tr><td>${x.seq}</td>
      <td class="muted">${escapeHtml(x.time||"")}</td>
      <td>${escapeHtml(x.host||"")}</td>
      <td class="code" style="word-break:break-all">${escapeHtml(x.path||"")}</td>
      <td>${escapeHtml(x.grant_type||"")}</td>
      <td class="code">${escapeHtml(x.broci_broker_id||"?")}</td>
      <td class="code">${escapeHtml(x.broci_nested_id||"?")}</td>
      <td><ul class="evidence-list">${evidenceList}</ul></td>
      <td class="code">${(x.input_fps||[]).map(escapeHtml).join("<br>")}</td>
      <td class="code">${(x.output_fps||[]).map(escapeHtml).join("<br>")}</td></tr>`;
  }).join("");
  $("#broci-body").innerHTML = `
    <table><thead><tr><th>#</th><th>Time</th><th>Host</th><th>Path</th><th>Grant</th><th>Broker</th><th>Nested</th><th>Evidence</th><th>Inputs</th><th>Outputs</th></tr></thead>
    <tbody>${rows}</tbody></table>`;
}

// --- Graph + Sequence -----------------------------------------------------

let mermaidCounter = 0;

async function refreshGraph(){
  const params = new URLSearchParams();
  state.highlight.forEach(fp => params.append("highlight", fp));
  state.isolate.forEach(fp => params.append("isolate", fp));
  const r = await fetch("/api/graph?" + params.toString());
  if(!r.ok){ $("#g-wrap").innerHTML = `<div class="empty">Failed to fetch graph (${r.status})</div>`; return; }
  const { mermaid: src } = await r.json();
  const id = "g_" + (++mermaidCounter);
  $("#g-wrap").innerHTML = `<div class="empty">Rendering…</div>`;
  try{
    const { svg } = await mermaid.render(id, src);
    $("#g-wrap").innerHTML = svg;
  }catch(err){
    $("#g-wrap").innerHTML = `<div class="empty">Mermaid render failed: ${escapeHtml(err.message||err)}</div><pre>${escapeHtml(src)}</pre>`;
  }
  const stateText = [];
  if(state.highlight.size) stateText.push(`Highlighted: ${state.highlight.size}`);
  if(state.isolate.size) stateText.push(`Isolated: ${state.isolate.size}`);
  $("#g-state").textContent = stateText.length ? stateText.join(" · ") : "No tokens highlighted.";
}
$("#g-clear").addEventListener("click", () => { state.highlight = new Set(); state.isolate = new Set(); refreshGraph(); renderTokens(); });
$("#g-refresh").addEventListener("click", refreshGraph);

async function refreshSequence(){
  const params = new URLSearchParams();
  if(state.sequenceFp) params.append("fp", state.sequenceFp);
  state.selected.forEach(fp => params.append("highlight", fp));
  params.append("max", $("#s-max").value || "200");
  const r = await fetch("/api/sequence?" + params.toString());
  if(!r.ok){ $("#s-wrap").innerHTML = `<div class="empty">Failed to fetch sequence (${r.status})</div>`; return; }
  const { mermaid: src } = await r.json();
  const id = "s_" + (++mermaidCounter);
  $("#s-wrap").innerHTML = `<div class="empty">Rendering…</div>`;
  try{
    const { svg } = await mermaid.render(id, src);
    $("#s-wrap").innerHTML = svg;
  }catch(err){
    $("#s-wrap").innerHTML = `<div class="empty">Mermaid render failed: ${escapeHtml(err.message||err)}</div><pre>${escapeHtml(src)}</pre>`;
  }
  $("#s-state").textContent = state.sequenceFp
    ? `Showing only events involving ${state.sequenceFp}.`
    : (state.selected.size ? `All events; ${state.selected.size} highlighted with ★.` : "All events.");
}
$("#s-clear").addEventListener("click", () => { state.sequenceFp = null; refreshSequence(); });
$("#s-refresh").addEventListener("click", refreshSequence);

bootstrap();