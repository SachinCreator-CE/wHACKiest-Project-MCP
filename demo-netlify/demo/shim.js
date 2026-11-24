/* SentinelAI static demo shim.
 *
 * Loaded before app.js. It replaces window.fetch for same-origin /api/* calls and answers them from
 * a snapshot recorded from the real app running in its offline fallback (window.__SENTINEL_SNAPSHOT__,
 * see snapshot.js). Approvals, rejections and reports are applied to an in-memory copy only: nothing
 * is sent anywhere and nothing is stored. Reload the page to reset the demo.
 */
(function () {
  "use strict";
  var SNAP = window.__SENTINEL_SNAPSHOT__;
  var realFetch = window.fetch ? window.fetch.bind(window) : null;
  if (!SNAP) { return; }

  var GENESIS = new Array(65).join("0");
  var DEMO_NOTE = "static demo";
  var S = JSON.parse(JSON.stringify(SNAP)); // mutable in-memory copy
  var traceExtra = [];

  function nowIso() { return new Date().toISOString().replace(/\.\d{3}Z$/, "Z"); }
  function clone(v) { return JSON.parse(JSON.stringify(v)); }
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
  function reply(status, body) {
    return new Response(JSON.stringify(body), { status: status, headers: { "content-type": "application/json" } });
  }
  function notFound(path) { return reply(404, { detail: "Not found in the static demo: " + path }); }

  // ----------------------------------------------------------------- hashing (audit chain)
  function sha256Fallback(str) {
    var K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
    var H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    var bytes = Array.prototype.slice.call(new TextEncoder().encode(str));
    var bitLen = bytes.length * 8;
    bytes.push(0x80);
    while (bytes.length % 64 !== 56) { bytes.push(0); }
    var hi = Math.floor(bitLen / 4294967296), lo = bitLen >>> 0;
    [hi, lo].forEach(function (w) { bytes.push((w >>> 24) & 255, (w >>> 16) & 255, (w >>> 8) & 255, w & 255); });
    function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
    for (var off = 0; off < bytes.length; off += 64) {
      var w = new Array(64), i;
      for (i = 0; i < 16; i++) { w[i] = ((bytes[off + 4 * i] << 24) | (bytes[off + 4 * i + 1] << 16) | (bytes[off + 4 * i + 2] << 8) | bytes[off + 4 * i + 3]) >>> 0; }
      for (i = 16; i < 64; i++) {
        var s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        var s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (i = 0; i < 64; i++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        var ch = (e & f) ^ (~e & g);
        var t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      H = [H[0] + a, H[1] + b, H[2] + c, H[3] + d, H[4] + e, H[5] + f, H[6] + g, H[7] + h].map(function (x) { return x >>> 0; });
    }
    return H.map(function (x) { return ("00000000" + x.toString(16)).slice(-8); }).join("");
  }

  async function sha256Hex(str) {
    if (window.crypto && window.crypto.subtle) {
      var buf = await window.crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
      return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
    }
    return sha256Fallback(str);
  }

  // Same canonical JSON as the real store: sorted keys, compact separators, ASCII-only strings.
  function canon(v) {
    if (v === null || v === undefined) { return "null"; }
    if (typeof v === "string") {
      return JSON.stringify(v).replace(/[\u007f-￿]/g, function (c) { return c === "\u007f" ? c : "\\u" + ("0000" + c.charCodeAt(0).toString(16)).slice(-4); });
    }
    if (typeof v === "number" || typeof v === "boolean") { return JSON.stringify(v); }
    if (Array.isArray(v)) { return "[" + v.map(canon).join(",") + "]"; }
    return "{" + Object.keys(v).sort().map(function (k) { return canon(k) + ":" + canon(v[k]); }).join(",") + "}";
  }

  function entryHash(prev, e) {
    return sha256Hex(canon({ prev: prev, ts: e.ts, actor: e.actor, action: e.action, incident_id: e.incident_id, details: e.details }));
  }

  async function verifyChain() {
    var rows = S.audit.entries.slice().sort(function (a, b) { return a.seq - b.seq; });
    if (!rows.length) { return true; }
    var prev = rows[0].prev_hash; // the recorded window may start after the genesis entry
    for (var i = 0; i < rows.length; i++) {
      if (rows[i].prev_hash !== prev) { return false; }
      if ((await entryHash(prev, rows[i])) !== rows[i].hash) { return false; }
      prev = rows[i].hash;
    }
    return true;
  }

  async function appendAudit(actor, action, incidentId, details) {
    var head = S.audit.entries.length ? S.audit.entries[0] : null; // newest first
    var prev = head ? head.hash : GENESIS;
    var e = { seq: head ? head.seq + 1 : 1, ts: nowIso(), actor: actor, action: action, incident_id: incidentId, details: details, prev_hash: prev };
    e.hash = await entryHash(prev, e);
    S.audit.entries.unshift(e);
    return e;
  }

  // ----------------------------------------------------------------- state helpers
  var LABELS = [[80, "CRITICAL"], [60, "HIGH"], [35, "MEDIUM"], [0, "LOW"]];
  function riskLabel(score) { for (var i = 0; i < LABELS.length; i++) { if (score >= LABELS[i][0]) { return LABELS[i][1]; } } return "LOW"; }

  function findAction(id) { return S.actions.actions.filter(function (a) { return a.id === id; })[0] || null; }
  function pendingFor(incId) { return S.actions.actions.filter(function (a) { return a.incident_id === incId && a.status === "proposed"; }).length; }

  function applyMitigation(incId) {
    var d = S.details[incId];
    if (!d || d.incident.status === "mitigated") { return; }
    d.incident.status = "mitigated";
    var risk = d.incident.risk;
    if (risk && Array.isArray(risk.factors)) {
      risk.factors.push({ label: "Mitigated by approved action", points: -30, detail: "A human-approved action addressed this incident." });
      var sum = risk.factors.reduce(function (n, f) { return n + (Number(f.points) || 0); }, 0);
      risk.score = Math.max(0, Math.min(100, sum));
      risk.label = riskLabel(risk.score);
    }
  }

  function incidentList() {
    return {
      incidents: S.incidents.incidents.map(function (s) {
        var d = S.details[s.id];
        var out = clone(s);
        if (d) { out.status = d.incident.status; out.risk = clone(d.incident.risk); }
        out.pending_actions = pendingFor(s.id);
        return out;
      })
    };
  }

  function incidentDetail(id) {
    var d = S.details[id];
    if (!d) { return null; }
    var acts = S.actions.actions.filter(function (a) { return a.incident_id === id; }).map(function (a) {
      return Object.assign(clone(a), { execution: clone(S.execution[a.id] || { real: false, reasons: ["Static demo: actions are always simulated"] }) });
    });
    return { incident: clone(d.incident), actions: acts };
  }

  // ----------------------------------------------------------------- chat
  var STOP = { a: 1, an: 1, the: 1, is: 1, are: 1, was: 1, were: 1, did: 1, do: 1, does: 1, to: 1, of: 1, in: 1, on: 1, it: 1, this: 1, that: 1, we: 1, i: 1, me: 1, you: 1, and: 1, or: 1, for: 1, with: 1, about: 1, s: 1 };
  function norm(q) { return String(q || "").toLowerCase().replace(/['’]/g, "").replace(/[^a-z0-9]+/g, " ").trim(); }
  function tokens(q) { return norm(q).split(" ").filter(function (t) { return t && !STOP[t]; }); }

  var KEYWORDS = [
    [/arjun|benign|false positive|not an incident|suppress/, "why is arjun not an incident"],
    [/audit|hash chain|who approved|log trail/, "show the audit log"],
    [/\blive\b|synthetic|real data|fake|simulated/, "what is live vs synthetic"],
    [/priya|compromis|account takeover|password|brute|mfa/, "is priyas account compromised"],
    [/after github|flagged|leaked key|key used|used after|exposed/, "was the leaked key used after github flagged it"],
    [/next|remediat|recommend|mitigat|fix|respond|plan/, "what should we do next"],
    [/happen|summar|overview|explain|what is going on|tell me about/, "what happened in this incident"]
  ];

  function chatPool(incId) {
    var pool = S.chat.filter(function (c) { return !incId || c.incident_id === incId; });
    return pool.length ? pool : S.chat;
  }

  function findAnswer(message, incId) {
    var q = norm(message);
    var pool = chatPool(incId);
    var hit = pool.filter(function (c) { return norm(c.question) === q; })[0];
    if (hit) { return hit; }
    for (var i = 0; i < KEYWORDS.length; i++) {
      if (KEYWORDS[i][0].test(q)) {
        var want = KEYWORDS[i][1];
        hit = pool.filter(function (c) { return norm(c.question) === want; })[0];
        if (hit) { return hit; }
      }
    }
    var qt = tokens(message);
    var best = null, bestScore = 0;
    pool.forEach(function (c) {
      var ct = tokens(c.question);
      var common = ct.filter(function (t) { return qt.indexOf(t) >= 0; }).length;
      var score = common / Math.max(1, Math.min(ct.length, qt.length));
      if (common >= 2 && score > bestScore) { best = c; bestScore = score; }
    });
    return bestScore >= 0.6 ? best : null;
  }

  function fallbackAnswer() {
    var qs = S.suggestions.concat(S.extra_questions).filter(function (q, i, all) { return all.indexOf(q) === i; });
    return {
      answer: "This static demo only has recorded answers, so it cannot answer that one. Try one of these:\n\n" +
        qs.map(function (q) { return "- " + q; }).join("\n") +
        "\n\nThe full app answers free-form questions using Amazon Bedrock and live AWS evidence.",
      mode: "offline",
      model_id: (S.status.bedrock || {}).model_id || "",
      fallback_reason: "Static demo: recorded answers only",
      trace: [],
      proposed_actions: []
    };
  }

  // ----------------------------------------------------------------- handlers
  async function handle(method, url, body) {
    var path = url.pathname;
    var m;

    // /api/status
    if (path === "/api/status" && method === "GET") { return reply(200, clone(S.status)); }

    // /api/detect
    if (path === "/api/detect" && method === "POST") {
      await sleep(900);
      S.status.detection.last_run_at = nowIso();
      return reply(200, clone(S.detect));
    }

    // /api/incidents and /api/incidents/{id}
    if (path === "/api/incidents" && method === "GET") { return reply(200, incidentList()); }
    if ((m = path.match(/^\/api\/incidents\/([^/]+)$/)) && method === "GET") {
      var id = decodeURIComponent(m[1]);
      var detail = incidentDetail(id);
      return detail ? reply(200, detail) : reply(404, { detail: "Incident " + id + " not found" });
    }

    // /api/chat
    if (path === "/api/chat" && method === "POST") {
      var msg = String((body && body.message) || "").trim();
      if (!msg) { return reply(400, { detail: "Message is empty" }); }
      await sleep(500);
      var found = findAnswer(msg, body && body.incident_id);
      var r = clone(found ? found.response : fallbackAnswer());
      (r.trace || []).forEach(function (t) { traceExtra.push(Object.assign(clone(t), { ts: nowIso() })); });
      S.status.bedrock = Object.assign({}, S.status.bedrock, { last_mode: r.mode, last_error: r.fallback_reason || null });
      return reply(200, r);
    }

    // /api/actions, /api/actions/{id}/approve|reject
    if (path === "/api/actions" && method === "GET") {
      var inc = url.searchParams.get("incident_id");
      var list = S.actions.actions.filter(function (a) { return !inc || a.incident_id === inc; });
      return reply(200, { actions: clone(list) });
    }
    if ((m = path.match(/^\/api\/actions\/([^/]+)\/(approve|reject)$/)) && method === "POST") {
      return decide(decodeURIComponent(m[1]), m[2], body || {});
    }

    // /api/audit
    if (path === "/api/audit" && method === "GET") {
      var limit = Math.max(1, Math.min(parseInt(url.searchParams.get("limit") || "200", 10) || 200, 1000));
      return reply(200, { entries: clone(S.audit.entries.slice(0, limit)), chain_ok: await verifyChain() });
    }

    // /api/reports and /api/reports/{incident_id}
    if (path === "/api/reports" && method === "GET") { return reply(200, clone(S.reports)); }
    if ((m = path.match(/^\/api\/reports\/([^/]+)$/)) && method === "POST") {
      var rid = decodeURIComponent(m[1]);
      if (!S.details[rid]) { return reply(404, { detail: "Incident " + rid + " not found" }); }
      await sleep(400);
      var report = await writeReport(rid);
      var who = String((body && body.requested_by) || "").replace(/\s+/g, " ").trim().slice(0, 100) || "analyst";
      await appendAudit(who, "report_written", rid, { demo: DEMO_NOTE, trigger: "manual", uri: report.uri });
      return reply(200, report);
    }

    // /api/voice/*
    if (path === "/api/voice/status" && method === "GET") { return reply(200, clone(S.voice_status)); }
    if ((path === "/api/voice/speak" || path === "/api/voice/transcribe") && method === "POST") {
      return reply(503, { fallback: "browser", reason: "Static demo: server-side voice is not available; the browser's own speech is used." });
    }

    // /api/trace/recent
    if (path === "/api/trace/recent" && method === "GET") {
      var tl = Math.max(1, Math.min(parseInt(url.searchParams.get("limit") || "50", 10) || 50, 200));
      return reply(200, { trace: clone(S.trace.trace.concat(traceExtra).slice(-tl)) });
    }

    return notFound(path);
  }

  var RESERVED = /^(agent|bedrock|system|rules|sentinel|copilot|amazonnova)/;
  var RESERVED_EXACT = { ai: 1, bot: 1, llm: 1, nova: 1, model: 1, auto: 1, automation: 1, preview: 1, root: 1 };

  async function decide(actionId, kind, body) {
    var approver = String(body.approver || "").replace(/\s+/g, " ").trim().slice(0, 64);
    if (!approver) { return reply(400, { detail: "An approver name is required" }); }
    var key = approver.toLowerCase().replace(/[^a-z0-9]/g, "");
    if (!key || RESERVED_EXACT[key] || RESERVED.test(key)) {
      return reply(400, { detail: "'" + approver + "' is a reserved system/agent name; enter the name of the human approving this" });
    }
    var action = findAction(actionId);
    if (!action) { return reply(404, { detail: "Action " + actionId + " not found" }); }
    if (action.status !== "proposed") { return reply(409, { detail: "Action " + actionId + " was already decided (" + action.status + ")" }); }
    await sleep(350);
    var decidedAt = nowIso();
    action.decided_by = approver;

    if (kind === "reject") {
      var reason = String(body.reason || "").trim().slice(0, 1000);
      action.status = "rejected";
      action.decided_at = decidedAt;
      action.result = { mode: "none", reason: reason };
      await appendAudit(approver, "action_rejected", action.incident_id, { demo: DEMO_NOTE, action_id: action.id, type: action.type, reason: reason });
      return reply(200, clone(action));
    }

    await appendAudit(approver, "action_approved", action.incident_id, { demo: DEMO_NOTE, action_id: action.id, type: action.type, proposed_by: action.proposed_by });
    var started = decidedAt;
    action.status = "simulated";
    action.decided_at = nowIso();
    var verification = { method: "simulated", verified: false };
    if (action.type === "deactivate_access_key") { verification.expected_status = "Inactive"; }
    action.result = {
      mode: "simulated",
      started_at: started,
      ended_at: nowIso(),
      approved_by: approver,
      target: clone(action.target || {}),
      simulated_reasons: ["Static demo: actions are always simulated"],
      verification: verification,
      summary: "Simulated in the static demo; nothing was changed"
    };
    await appendAudit("sentinel", "action_simulated", action.incident_id, {
      demo: DEMO_NOTE, action_id: action.id, type: action.type, mode: "simulated", approved_by: approver,
      reasons: ["Static demo: actions are always simulated"], verification: verification
    });
    var d = S.details[action.incident_id];
    var fits = d && (d.incident.recommended_actions || []).indexOf(action.type) >= 0 && Object.keys(action.target || {}).length > 0;
    if (fits && S.mitigating_types.indexOf(action.type) >= 0) { applyMitigation(action.incident_id); }
    var report = await writeReport(action.incident_id);
    await appendAudit("sentinel", "report_written", action.incident_id, { demo: DEMO_NOTE, action_id: action.id, uri: report.uri });
    action.result.report = clone(report);
    return reply(200, clone(action));
  }

  async function writeReport(incId) {
    var now = new Date();
    var stamp = now.toISOString().replace(/[-:]/g, "").replace(/(\.\d{3})Z$/, "$1Z").replace(/^(\d{8})(T)/, "$1$2");
    var base = "reports/" + incId + "/" + stamp;
    var iso = nowIso();
    var report = {
      uri: "demo://" + base + ".md",
      markdown_key: base + ".md",
      json_key: base + ".json",
      live: false,
      location: "local",
      fallback_reason: "Static demo: nothing is written anywhere"
    };
    ["json", "md"].forEach(function (fmt) {
      S.reports.reports.unshift({
        key: base + "." + fmt, incident_id: incId, format: fmt, size: 0, last_modified: iso,
        uri: "demo://" + base + "." + fmt, location: "local"
      });
    });
    return report;
  }

  // ----------------------------------------------------------------- fetch override
  async function demoFetch(input, init) {
    var url;
    try { url = new URL(typeof input === "string" ? input : (input && input.url) || String(input), window.location.href); } catch (e) { url = null; }
    if (!url || url.origin !== window.location.origin || url.pathname.indexOf("/api/") !== 0) {
      if (realFetch) { return realFetch(input, init); }
      return reply(404, { detail: "Not available in the static demo" });
    }
    var method = String((init && init.method) || (typeof input !== "string" && input && input.method) || "GET").toUpperCase();
    var body = null;
    if (init && typeof init.body === "string") { try { body = JSON.parse(init.body); } catch (e) { body = null; } }
    try {
      return await handle(method, url, body);
    } catch (err) {
      return reply(500, { detail: "Demo error: " + (err && err.message ? err.message : "unknown") });
    }
  }
  window.fetch = demoFetch;
  window.__sentinelDemo = { handle: handle, state: S, sha256Hex: sha256Hex, sha256Fallback: sha256Fallback, canon: canon, verifyChain: verifyChain };

  // ----------------------------------------------------------------- notice dismiss
  var NOTICE_KEY = "sentinel-demo-notice-dismissed";
  document.addEventListener("DOMContentLoaded", function () {
    var box = document.getElementById("demo-notice");
    var btn = document.getElementById("demo-notice-close");
    if (!box || !btn) { return; }
    try { if (window.sessionStorage.getItem(NOTICE_KEY) === "1") { box.hidden = true; } } catch (e) { /* storage unavailable */ }
    btn.addEventListener("click", function () {
      box.hidden = true;
      try { window.sessionStorage.setItem(NOTICE_KEY, "1"); } catch (e) { /* storage unavailable */ }
    });
  });
})();
