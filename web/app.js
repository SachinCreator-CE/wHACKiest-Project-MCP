/* SentinelAI console: vanilla JS, no build step, no external requests. */
"use strict";

(() => {
  const STATUS_POLL_MS = 15000;
  const STATUS_POLL_BUSY_MS = 3000;
  const MAX_HISTORY = 12;
  const MAX_RECORD_MS = 30000;
  const LS_APPROVER = "sentinel.approver";
  const LS_SPEAK = "sentinel.speak";

  const state = {
    status: null,
    incidents: [],
    currentId: null,
    detail: null,
    history: [],
    voiceMode: "browser", // "server" (ElevenLabs via API) or "browser" (Web Speech API)
    recording: null, // {stop()} while the mic is active
    audio: null,
    speakSeq: 0, // bumped by stopSpeaking(); a speak() whose token is stale must not start playback
    speakAbort: null, // AbortController of the in-flight /api/voice/speak request
    decision: null, // {action, kind}
    lastDetectionAt: undefined,
    pollTimer: null,
    chainOk: null, // audit hash chain verdict (null = unknown)
  };

  // ---------------------------------------------------------------- helpers
  const $ = (id) => document.getElementById(id);

  /** Create an element. attrs: class, text, title, dataset, aria-*, on<event>; children: nodes/strings. */
  function h(tag, attrs = {}, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k === "dataset") Object.assign(el.dataset, v);
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : String(v));
    }
    for (const c of children.flat()) {
      if (c === undefined || c === null || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }

  const lsGet = (k) => { try { return localStorage.getItem(k); } catch { return null; } };
  const lsSet = (k, v) => { try { localStorage.setItem(k, v); } catch { /* storage unavailable */ } };

  async function api(path, { method = "GET", json, form } = {}) {
    const init = { method, headers: {} };
    if (json !== undefined) {
      init.body = JSON.stringify(json);
      init.headers["Content-Type"] = "application/json";
    } else if (form) {
      init.body = form;
    }
    const res = await fetch(path, init);
    const isJson = (res.headers.get("content-type") || "").includes("application/json");
    const data = isJson ? await res.json().catch(() => null) : null;
    if (!res.ok) {
      const err = new Error(detailText(data) || `HTTP ${res.status}`);
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  function detailText(data) {
    if (!data) return "";
    if (typeof data.detail === "string") return data.detail;
    if (Array.isArray(data.detail)) return data.detail.map((d) => d.msg).join("; ");
    return data.reason || "";
  }

  // Timeline times are UTC, like the evidence, the agent and the voice ("02:26 UTC"); the date is
  // shown when it is not today (UTC), so a 24 h window or the previous-day arjun session reads correctly.
  function fmtTime(ts) {
    const d = new Date(ts);
    if (Number.isNaN(d.getTime())) return ts || "";
    const time = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false, timeZone: "UTC" });
    const day = (x) => x.toISOString().slice(0, 10);
    if (day(d) === day(new Date())) return time;
    return `${d.toLocaleDateString([], { month: "short", day: "2-digit", timeZone: "UTC" })} ${time}`;
  }

  function fmtDateTime(ts) {
    const d = new Date(ts);
    if (Number.isNaN(d.getTime())) return ts || "";
    return d.toLocaleString([], {
      month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false, timeZoneName: "short",
    });
  }

  const humanize = (k) => String(k).replace(/_/g, " ");

  let toastTimer = null;
  function toast(msg, bad = false) {
    const t = $("toast");
    t.textContent = msg;
    t.classList.toggle("bad", bad);
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.hidden = true; }, bad ? 7000 : 4000);
  }

  /** Tiny, safe markdown: paragraphs, bullet lists, **bold**, `code`. Input is escaped first. */
  function renderMarkdown(text) {
    const esc = (s) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
    const inline = (s) => esc(s).replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    const wrap = h("div", { class: "md" });
    let html = "";
    for (const block of String(text || "").trim().split(/\n{2,}/)) {
      const lines = block.split("\n");
      if (lines.every((l) => /^\s*([-*•]|\d+[.)])\s+/.test(l))) {
        html += "<ul>" + lines.map((l) => `<li>${inline(l.replace(/^\s*([-*•]|\d+[.)])\s+/, ""))}</li>`).join("") + "</ul>";
      } else {
        html += `<p>${lines.map(inline).join("<br>")}</p>`;
      }
    }
    wrap.innerHTML = html;
    return wrap;
  }

  const plainText = (md) => String(md || "").replace(/[*`#>]/g, "").replace(/^\s*[-•]\s+/gm, "").replace(/\s+/g, " ").trim();

  // ---------------------------------------------------------------- status
  async function pollStatus() {
    clearTimeout(state.pollTimer);
    let busy = false;
    try {
      const s = await api("/api/status");
      renderStatus(s);
      busy = Boolean(s.detection && s.detection.running);
      const last = s.detection ? s.detection.last_run_at : null;
      if (state.lastDetectionAt !== undefined && last !== state.lastDetectionAt) {
        await Promise.all([loadIncidents(), loadAudit()]);
      }
      state.lastDetectionAt = last;
    } catch (err) {
      const pill = $("aws-pill");
      pill.className = "pill pill-warn";
      $("aws-label").textContent = "Console offline";
      pill.title = err.message;
    }
    state.pollTimer = setTimeout(pollStatus, busy ? STATUS_POLL_BUSY_MS : STATUS_POLL_MS);
  }

  function renderStatus(s) {
    state.status = s;
    const aws = s.aws || {};
    const pill = $("aws-pill");
    const awsError = !aws.connected && Boolean(s.aws_required); // SENTINEL_MODE=aws: offline is an error
    pill.className = "pill " + (aws.connected ? "pill-ok" : awsError ? "pill-bad" : "pill-warn");
    $("aws-label").textContent = aws.connected ? aws.label : awsError ? "AWS error · offline fallback" : "Offline fallback";
    pill.title = aws.connected ? `Principal: ${aws.principal || "?"}` : (aws.reason || "AWS not connected");

    const bedrock = s.bedrock || {};
    $("model-id").textContent = bedrock.model_id || "n/a";
    $("model-chip").title = bedrock.last_mode
      ? `Amazon Bedrock model. Last answer: ${bedrock.last_mode === "bedrock" ? "Bedrock" : "offline fallback"}${bedrock.last_error ? " (" + bedrock.last_error + ")" : ""}`
      : "Amazon Bedrock model";

    const voice = s.voice || {};
    const eleven = voice.provider === "elevenlabs";
    $("voice-provider").textContent = eleven ? "ElevenLabs" : "Browser";
    const voiceTitle = voice.reason || (eleven ? "ElevenLabs speech-to-text and text-to-speech" : "Browser Web Speech API");
    $("voice-chip").title = voice.last_error && !voiceTitle.includes(voice.last_error)
      ? `${voiceTitle} (last ElevenLabs error: ${voice.last_error})`
      : voiceTitle;
    if (!state.recording) state.voiceMode = eleven ? "server" : "browser";

    const banner = $("banner");
    banner.hidden = !s.banner;
    banner.textContent = s.banner || "";
    banner.classList.toggle("banner-error", awsError);

    const running = Boolean(s.detection && s.detection.running);
    setBusy($("detect-btn"), running, running ? "Detecting…" : "Run detection");

    const bucket = s.settings && s.settings.s3_bucket;
    $("reports-where").textContent = s.mode === "aws" && bucket
      ? `Reports are written to s3://${bucket}/reports/ (SSE-S3)`
      : "Reports are written locally to var/reports/ (offline fallback)";
  }

  function setBusy(btn, busy, label) {
    btn.classList.toggle("busy", busy);
    btn.disabled = busy;
    if (label) btn.querySelector(".btn-label").textContent = label;
  }

  async function runDetection() {
    const btn = $("detect-btn");
    setBusy(btn, true, "Detecting…");
    try {
      const r = await api("/api/detect", { method: "POST" });
      const n = (r.incidents || []).length;
      const sup = (r.suppressed || []).length;
      toast(`Detection complete (${r.mode === "aws" ? "AWS" : "offline"}): ${n} incident${n === 1 ? "" : "s"}, ${sup} suppressed`);
      await Promise.all([loadIncidents(), loadAudit(), loadTrace()]);
    } catch (err) {
      toast(err.message, true);
    } finally {
      setBusy(btn, false, "Run detection");
      pollStatus();
    }
  }

  // ---------------------------------------------------------------- incidents
  async function loadIncidents() {
    try {
      const r = await api("/api/incidents");
      state.incidents = r.incidents || [];
    } catch (err) {
      toast(`Could not load incidents: ${err.message}`, true);
      return;
    }
    renderIncidentList();
    const ids = state.incidents.map((i) => i.id);
    if (!ids.includes(state.currentId)) state.currentId = ids[0] || null;
    if (state.currentId) await loadDetail(state.currentId);
    else renderDetail(null);
  }

  function renderIncidentList() {
    const list = $("incident-list");
    list.replaceChildren(...state.incidents.map((inc) => {
      const mode = inc.data_mode === "live" ? "live" : "synthetic";
      return h("li", {},
        h("button", {
          type: "button",
          class: `incident-item sev-${inc.severity}`,
          "aria-current": inc.id === state.currentId ? "true" : "false",
          onclick: () => selectIncident(inc.id),
        },
          h("span", { class: "row" },
            h("span", { class: "mono case-id", text: inc.id }),
            h("span", { class: `sev sev-${inc.severity}`, text: riskLabel(inc) }),
            hasRisk(inc) ? h("span", { class: "mono risk-mini", title: "Risk score", text: `RISK ${inc.risk.score}` }) : null,
            inc.pending_actions ? h("span", { class: "pending", text: `${inc.pending_actions} pending` }) : null),
          h("span", { class: "title", text: inc.title }),
          h("span", { class: "row" },
            h("span", { class: `chip chip-${inc.status}`, text: inc.status }),
            h("span", { class: `chip chip-${mode}`, text: mode === "live" ? "live AWS" : "synthetic" }),
            h("span", { class: "muted", text: `${inc.event_count ?? 0} events` }))));
    }));
    $("incident-count").textContent = String(state.incidents.length);
    $("incidents-empty").hidden = state.incidents.length > 0;
  }

  const hasRisk = (inc) => Boolean(inc && inc.risk && Number.isFinite(inc.risk.score));
  /** Severity word shown on cards: prefers the risk label, falls back to the rule severity. */
  const riskLabel = (inc) => String(hasRisk(inc) && inc.risk.label ? inc.risk.label : inc.severity || "").toLowerCase();

  async function selectIncident(id) {
    state.currentId = id;
    renderIncidentList();
    await loadDetail(id);
    $("incident-detail").focus({ preventScroll: true });
  }

  async function loadDetail(id) {
    try {
      const r = await api(`/api/incidents/${encodeURIComponent(id)}`);
      if (state.currentId === id) renderDetail(r);
    } catch (err) {
      toast(`Could not load ${id}: ${err.message}`, true);
    }
  }

  const SOURCES = {
    cloudtrail: ["CT", "CloudTrail"],
    github: ["GH", "GitHub"],
    "app-auth": ["AU", "App auth"],
    logs: ["LG", "Logs"],
  };

  const ENTITY_LABELS = {
    access_key_id: "Key",
    iam_user: "IAM user",
    repository: "Repo",
    alert_number: "Alert #",
    app_user: "App user",
    attacker_ips: "Attacker IP",
  };

  function renderDetail(r) {
    state.detail = r;
    $("detail-empty").hidden = Boolean(r);
    $("detail-body").hidden = !r;
    $("incident-detail").classList.toggle("has-case", Boolean(r));
    renderChatContext();
    if (!r) return;
    const inc = r.incident;
    const mode = inc.data_mode === "live" ? "live" : "synthetic";

    const sev = $("d-severity");
    sev.className = `sev sev-${inc.severity}`;
    sev.textContent = inc.severity;
    sev.hidden = hasRisk(inc); // the classification block already carries the label
    renderRisk(inc);
    renderStamps();
    $("d-id").textContent = inc.id;
    $("d-status").className = `chip chip-${inc.status}`;
    $("d-status").textContent = inc.status;
    $("d-mode").className = `chip chip-${mode}`;
    $("d-mode").textContent = mode === "live" ? "live AWS data" : "synthetic data";
    $("d-mode").hidden = true; // shown as a provenance stamp instead
    $("d-title").textContent = inc.title;
    $("d-summary").textContent = inc.summary;

    const chips = [];
    for (const [k, v] of Object.entries(inc.entities || {})) {
      const label = ENTITY_LABELS[k] || humanize(k);
      for (const val of Array.isArray(v) ? v : [v]) {
        if (val === "" || val === null || typeof val === "object") continue;
        chips.push(h("span", { class: "chip", title: humanize(k) }, h("span", { class: "chip-k", text: label }), String(val)));
      }
    }
    $("d-entities").replaceChildren(...chips);

    $("d-counts").replaceChildren(...Object.entries(inc.counts || {}).map(([k, v]) =>
      h("div", { class: "tile" + (/denied|escalation|fail|admin/.test(k) && v > 0 ? " hot" : "") },
        h("div", { class: "v", text: String(v) }),
        h("div", { class: "k", text: humanize(k) }))));

    const events = [...(inc.events || [])].sort((a, b) => String(a.ts).localeCompare(String(b.ts)));
    $("d-timeline").replaceChildren(...(events.length ? events.map(eventRow)
      : [h("tr", {}, h("td", { colspan: 5, class: "muted", text: "No events." }))]));

    $("d-evidence").replaceChildren(...(inc.evidence || []).map((e) => h("li", { text: e })));
    $("d-actions").replaceChildren(...(r.actions.length ? r.actions.map((a) => actionItem(a, inc))
      : [h("li", { class: "muted", text: "No actions proposed yet. Ask the agent for a remediation plan." })]));
  }

  function renderRisk(inc) {
    const box = $("d-risk");
    const how = $("d-risk-how");
    if (!hasRisk(inc)) {
      const sevName = String(inc.severity || "").toUpperCase();
      box.className = `classification sev-${inc.severity}`;
      box.replaceChildren(h("span", { class: "cl-k", text: "Severity" }), h("span", { class: "cl-v", text: sevName }));
      how.hidden = true;
      return;
    }
    const risk = inc.risk;
    const label = String(risk.label || "").toUpperCase();
    box.className = `classification risk-${label.toLowerCase()}`;
    box.replaceChildren(
      h("span", { class: "cl-k", text: "Classification" }),
      h("span", { class: "cl-v", text: `RISK ${risk.score} / ${label}` }));
    how.hidden = false;
    $("d-risk-method").textContent = risk.method || "";
    $("d-risk-method").hidden = !risk.method;
    const factors = Array.isArray(risk.factors) ? risk.factors : [];
    $("d-risk-factors").replaceChildren(...(factors.length ? factors.map((f) => {
      const pts = Number(f.points) || 0;
      return h("li", {},
        h("span", { class: "mono pts " + (pts < 0 ? "neg" : "pos"), text: `${pts > 0 ? "+" : ""}${pts}` }),
        h("span", { class: "f-body" }, h("strong", { text: f.label || "" }), f.detail ? h("span", { class: "f-detail", text: f.detail }) : null));
    }) : [h("li", { class: "muted", text: "No scoring factors recorded." })]));
  }

  /** Rotated "rubber stamp" labels: provenance, approval, verification, evidence integrity. */
  function renderStamps() {
    const box = $("d-stamps");
    const r = state.detail;
    if (!r) { box.replaceChildren(); return; }
    const inc = r.incident;
    const actions = r.actions || [];
    const stamps = [];
    const live = inc.data_mode === "live";
    stamps.push(h("span", { class: "stamp " + (live ? "stamp-live" : "stamp-synth"), title: live ? "Evidence comes from your live AWS account" : "Evidence comes from bundled synthetic demo data", text: live ? "LIVE AWS" : "SYNTHETIC" }));
    if ((inc.events || []).some((e) => e.simulated) || actions.some((a) => a.status === "simulated" || (a.status === "proposed" && !(a.execution || {}).real))) {
      stamps.push(h("span", { class: "stamp stamp-sim", title: "Some traffic or actions are simulated; nothing in AWS changes", text: "SIMULATED" }));
    }
    const verifiedAction = actions.some((a) => ((a.result || {}).verification || {}).verified);
    if (verifiedAction || state.chainOk === true) {
      stamps.push(h("span", { class: "stamp stamp-ok", title: verifiedAction ? "A remediation was confirmed against AWS" : "Audit hash chain verified", text: "VERIFIED" }));
    }
    if (state.chainOk === true) stamps.push(h("span", { class: "stamp stamp-lock", title: "SHA-256 audit hash chain is intact", text: "EVIDENCE LOCKED" }));
    if (actions.some((a) => a.status === "proposed")) stamps.push(h("span", { class: "stamp stamp-warn", title: "A human must approve or reject proposed actions", text: "APPROVAL REQUIRED" }));
    box.replaceChildren(...stamps);
  }

  function eventRow(ev) {
    const [ico, label] = SOURCES[ev.source] || [String(ev.source || "?").slice(0, 2).toUpperCase(), ev.source];
    const outcome = ev.error_code || ev.outcome;
    const tags = [ev.live ? h("span", { class: "chip chip-live", text: "live AWS" }) : h("span", { class: "chip chip-synthetic", text: "synthetic" })];
    if (ev.simulated) tags.push(h("span", { class: "chip chip-sim", text: "simulated app traffic" }));
    return h("tr", {},
      h("td", { class: "time", title: ev.ts, text: fmtTime(ev.ts) }),
      h("td", {}, h("span", { class: `src src-${ev.source}`, title: ev.region ? `${label} · ${ev.region}` : label },
        h("span", { class: "src-ico", "aria-hidden": "true", text: ico }), h("span", { class: "src-label", text: label }))),
      h("td", { class: "kind" }, ev.kind, ev.summary && ev.summary !== ev.kind ? h("small", { title: ev.summary, text: ev.summary }) : null),
      h("td", { class: "actor" },
        h("span", { class: "actor-name", title: ev.actor || "", text: ev.actor || "—" }),
        h("span", { class: "ip", text: ev.ip || "—" })),
      h("td", { class: "result" },
        h("span", { class: `outcome outcome-${ev.outcome}`, text: outcome }),
        h("span", { class: "tags" }, ...tags)));
  }

  function executionChip(a) {
    if (a.status === "executed") {
      const verified = ((a.result || {}).verification || {}).verified;
      return verified
        ? h("span", { class: "chip chip-aws", text: "REAL AWS · done" })
        : h("span", { class: "chip chip-aws", title: "UpdateAccessKey ran but ListAccessKeys did not confirm Inactive; re-run detection to propose a retry", text: "REAL AWS · unverified" });
    }
    if (a.status === "simulated") return h("span", { class: "chip chip-sim", text: "simulated" });
    if (a.status !== "proposed") return null;
    const ex = a.execution || { real: false, reasons: [] };
    return ex.real
      ? h("span", { class: "chip chip-aws", title: "Approving runs this against AWS", text: "REAL AWS" })
      : h("span", { class: "chip chip-sim", title: (ex.reasons || []).join("\n") || "Simulated", text: "simulated" });
  }

  function resultText(a) {
    const res = a.result || {};
    const msg = res.error || res.summary || (res.simulated_reasons || []).join("; ");
    const who = a.decided_by ? `${a.status} by ${a.decided_by} at ${fmtDateTime(a.decided_at)}` : "";
    return [who, msg].filter(Boolean).join(" · ");
  }

  function actionItem(a, inc) {
    const proposed = a.status === "proposed";
    return h("li", { class: "action" },
      h("div", { class: "action-head" },
        h("span", { class: "action-title", text: a.title }),
        executionChip(a),
        h("span", { class: "chip", text: a.proposed_by === "agent" ? "proposed by agent" : "rule recommendation" })),
      a.description ? h("p", { class: "action-desc", text: a.description }) : null,
      a.reason ? h("p", { class: "action-desc", text: `Why: ${a.reason}` }) : null,
      h("div", { class: "action-foot" },
        h("span", { class: `status status-${a.status}`, text: a.status }),
        h("span", { class: "mono muted", text: a.id }),
        h("span", { class: "spacer" }),
        proposed ? h("button", { type: "button", class: "btn btn-reject", onclick: () => openDecision(a, inc, "reject") }, "Reject") : null,
        proposed ? h("button", { type: "button", class: "btn btn-approve", onclick: () => openDecision(a, inc, "approve") }, "Approve") : null),
      proposed ? null : h("div", { class: "action-result", text: resultText(a) }));
  }

  // ---------------------------------------------------------------- approve / reject
  function openDecision(action, inc, kind) {
    state.decision = { action, kind };
    const approve = kind === "approve";
    const ex = action.execution || { real: false, reasons: [] };
    $("dlg-title").textContent = `${approve ? "Approve" : "Reject"}: ${action.title}`;
    $("dlg-action").textContent = `${action.title} — ${inc.id}: ${inc.title}`;
    const mode = $("dlg-mode");
    mode.hidden = !approve;
    if (approve) {
      mode.className = "dlg-mode " + (ex.real ? "real" : "sim");
      mode.replaceChildren(
        h("strong", { text: ex.real ? "This will run for REAL in AWS." : "This will be SIMULATED (no AWS change)." }),
        ex.real
          ? h("div", { text: "iam:UpdateAccessKey sets the key to Inactive, then the change is verified with ListAccessKeys." })
          : h("ul", {}, ...(ex.reasons || []).map((r) => h("li", { text: r }))));
    }
    $("dlg-reason-wrap").hidden = approve;
    $("dlg-reason").value = "";
    $("dlg-error").textContent = "";
    $("dlg-approver").value = lsGet(LS_APPROVER) || "";
    const confirm = $("dlg-confirm");
    confirm.textContent = approve ? (ex.real ? "Approve and run in AWS" : "Approve (simulated)") : "Reject";
    confirm.disabled = false;
    $("decision-dialog").showModal();
    $("dlg-approver").focus();
  }

  async function submitDecision(evt) {
    evt.preventDefault();
    const d = state.decision;
    if (!d) return;
    const approver = $("dlg-approver").value.trim();
    if (!approver) {
      $("dlg-error").textContent = "Please enter your name; it is recorded in the audit log.";
      $("dlg-approver").focus();
      return;
    }
    lsSet(LS_APPROVER, approver);
    const confirm = $("dlg-confirm");
    confirm.disabled = true;
    try {
      const body = { approver, reason: $("dlg-reason").value.trim() };
      const a = await api(`/api/actions/${encodeURIComponent(d.action.id)}/${d.kind}`, { method: "POST", json: body });
      $("decision-dialog").close();
      toast(`${a.id}: ${a.status}${a.status === "executed" ? " in AWS" : ""}`);
      await Promise.all([loadIncidents(), loadAudit(), loadReports(), loadTrace()]);
    } catch (err) {
      $("dlg-error").textContent = err.status === 409 ? `${err.message}. Refreshing…` : err.message;
      confirm.disabled = false;
      if (err.status === 409) loadIncidents();
    }
  }

  // ---------------------------------------------------------------- chat
  function renderChatContext() {
    const inc = state.detail && state.detail.incident;
    $("chat-context").textContent = inc ? `Context: ${inc.id} · ${inc.title}` : "Context: all incidents";
  }

  function chatScroll() {
    const log = $("chat-log");
    log.scrollTop = log.scrollHeight;
  }

  function traceItem(t) {
    const tail = t.ok ? (t.summary || "ok") : `error: ${t.error}`;
    return h("li", { class: t.ok ? "" : "err", title: [t.backend, t.region].filter(Boolean).join(" · ") },
      t.target === "aws" ? h("span", { class: "aws-badge", text: "AWS" }) : h("span", { class: "off-badge", text: t.target === "offline" ? "OFF" : "LOCAL" }),
      h("span", { text: `${t.server} → ${t.tool} → ${tail} in ${t.ms} ms` }));
  }

  /** Evidence-timeline entry: mono time (or sequence), dot on the rule, server, tool, result, ms. */
  function traceEvent(t, n) {
    const tail = t.ok ? (t.summary || "ok") : `error: ${t.error}`;
    const when = t.ts ? fmtTime(t.ts) : `#${String(n).padStart(3, "0")}`;
    return h("li", { class: "etl-item" + (t.ok ? "" : " err") + (t.target === "aws" ? " is-aws" : "") },
      h("span", { class: "etl-time mono", text: when }),
      h("span", { class: "etl-dot", "aria-hidden": "true" }),
      h("span", { class: "etl-body" },
        h("span", { class: "etl-head" },
          h("span", { class: "etl-server", text: t.server }),
          t.target === "aws" ? h("span", { class: "aws-badge", text: "AWS" }) : h("span", { class: "off-badge", text: t.target === "offline" ? "OFFLINE" : "LOCAL" })),
        h("span", { class: "etl-tool mono", text: t.tool }),
        h("span", { class: "etl-result", text: tail })),
      h("span", { class: "etl-ms mono", text: `${t.ms} ms` }));
  }

  function agentMessage(r) {
    const bedrock = r.mode === "bedrock";
    const trace = r.trace || [];
    const onAws = trace.filter((t) => t.target === "aws").length;
    const meta = h("div", { class: "msg-meta" },
      bedrock
        ? h("span", { class: "chip chip-aws", text: `Bedrock ${r.model_id || ""}`.trim() })
        : h("span", { class: "chip chip-sim", title: r.fallback_reason || "", text: "Offline fallback" }),
      ...(r.proposed_actions || []).map((id) => h("span", { class: "chip chip-live", text: `proposed ${id}` })));
    return h("div", { class: "msg msg-agent" },
      renderMarkdown(r.answer),
      meta,
      !bedrock && r.fallback_reason ? h("div", { class: "muted", style: "font-size:12px", text: `Fallback reason: ${r.fallback_reason}` }) : null,
      trace.length ? h("details", { class: "trace-box" },
        h("summary", { text: `${trace.length} tool call${trace.length === 1 ? "" : "s"}${onAws ? ` · ${onAws} on AWS` : ""}` }),
        h("ul", { class: "trace" }, ...trace.map(traceItem))) : null);
  }

  async function sendChat(message, { voice = false } = {}) {
    const text = message.trim();
    if (!text) return;
    $("suggestions").hidden = true;
    const log = $("chat-log");
    log.append(h("div", { class: "msg msg-user", text }));
    const pending = h("div", { class: "msg msg-agent typing", text: "Investigating" });
    log.append(pending);
    chatScroll();
    $("chat-input").value = "";
    $("send-btn").disabled = true;
    try {
      const r = await api("/api/chat", {
        method: "POST",
        json: { message: text, incident_id: state.currentId, voice, history: state.history.slice(-MAX_HISTORY) },
      });
      pending.replaceWith(agentMessage(r));
      state.history.push({ role: "user", content: text }, { role: "assistant", content: r.answer || "" });
      if ((r.proposed_actions || []).length) await loadIncidents();
      if ($("speak-toggle").checked) speak(r.answer);
      loadTrace();
    } catch (err) {
      pending.replaceWith(h("div", { class: "msg msg-agent msg-error", text: `Agent error: ${err.message}` }));
    } finally {
      $("send-btn").disabled = false;
      chatScroll();
    }
  }

  // ---------------------------------------------------------------- voice
  const voiceNote = (msg) => { $("voice-note").textContent = msg || ""; };

  function setMicUi(active) {
    const btn = $("mic-btn");
    btn.classList.toggle("recording", active);
    btn.setAttribute("aria-pressed", String(active));
    btn.setAttribute("aria-label", active ? "Stop voice input" : "Start voice input");
  }

  function onMic() {
    if (state.recording) {
      state.recording.stop();
      return;
    }
    stopSpeaking();
    const canRecord = window.MediaRecorder && navigator.mediaDevices && navigator.mediaDevices.getUserMedia;
    if (state.voiceMode === "server" && canRecord) startRecording();
    else startBrowserRecognition();
  }

  async function startRecording() {
    let stream;
    try {
      stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    } catch (err) {
      voiceNote(`Microphone unavailable (${err.name || err.message}).`);
      return;
    }
    let recorder;
    try {
      recorder = new MediaRecorder(stream);
    } catch (err) {
      stream.getTracks().forEach((t) => t.stop());
      voiceNote(`Recording unavailable (${err.name || err.message}). Tap the mic to use browser speech recognition.`);
      state.voiceMode = "browser";
      return;
    }
    const chunks = [];
    const timer = setTimeout(() => recorder.state !== "inactive" && recorder.stop(), MAX_RECORD_MS);
    recorder.addEventListener("dataavailable", (e) => e.data.size && chunks.push(e.data));
    recorder.addEventListener("stop", () => {
      clearTimeout(timer);
      stream.getTracks().forEach((t) => t.stop());
      state.recording = null;
      setMicUi(false);
      transcribe(new Blob(chunks, { type: recorder.mimeType || "audio/webm" }));
    });
    state.recording = { stop: () => recorder.state !== "inactive" && recorder.stop() };
    recorder.start();
    setMicUi(true);
    voiceNote("Listening (ElevenLabs)… tap the mic again to stop.");
  }

  async function transcribe(blob) {
    if (!blob.size) {
      voiceNote("No audio captured.");
      return;
    }
    voiceNote("Transcribing with ElevenLabs…");
    const ext = (blob.type.split("/")[1] || "webm").split(";")[0];
    const form = new FormData();
    form.append("file", blob, `speech.${ext}`);
    try {
      const r = await api("/api/voice/transcribe", { method: "POST", form });
      const text = (r.text || "").trim();
      voiceNote(text ? `Heard via ElevenLabs in ${r.ms ?? "?"} ms.` : "Didn't catch that; try again.");
      if (text) sendChat(text, { voice: true });
    } catch (err) {
      if (err.status === 503 && err.data && err.data.fallback === "browser") {
        // Server says ElevenLabs is unusable (key, quota, outage): switch to browser speech. Starting recognition
        // here would run outside a user gesture, so ask for a tap instead.
        state.voiceMode = "browser";
        voiceNote(`ElevenLabs unavailable (${err.message}). Tap the mic to ask again with browser speech recognition.`);
      } else {
        voiceNote(`Transcription failed (${err.message}). Please try again or type your question.`);
      }
    }
  }

  function startBrowserRecognition() {
    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SR) {
      voiceNote("Voice input is not supported in this browser. Please type your question.");
      return;
    }
    const rec = new SR();
    rec.lang = "en-US";
    rec.interimResults = true;
    rec.maxAlternatives = 1;
    let finalText = "";
    rec.addEventListener("result", (e) => {
      let interim = "";
      for (let i = e.resultIndex; i < e.results.length; i++) {
        const t = e.results[i][0].transcript;
        if (e.results[i].isFinal) finalText += t;
        else interim += t;
      }
      $("chat-input").value = (finalText + interim).trim();
    });
    rec.addEventListener("error", (e) => voiceNote(`Speech recognition error: ${e.error}`));
    rec.addEventListener("end", () => {
      state.recording = null;
      setMicUi(false);
      if (finalText.trim()) {
        voiceNote("Heard via browser speech recognition.");
        sendChat(finalText, { voice: true });
      }
    });
    state.recording = { stop: () => rec.stop() };
    try {
      rec.start();
    } catch (err) {
      state.recording = null;
      voiceNote(`Speech recognition failed to start: ${err.message}`);
      return;
    }
    setMicUi(true);
    voiceNote("Listening (browser)… tap the mic again to stop.");
  }

  function releaseAudio(audio) {
    audio.pause();
    URL.revokeObjectURL(audio.src);
    if (state.audio === audio) state.audio = null;
  }

  function stopSpeaking() {
    state.speakSeq += 1; // any speak() still awaiting the server is now stale
    if (state.speakAbort) {
      state.speakAbort.abort();
      state.speakAbort = null;
    }
    if (state.audio) releaseAudio(state.audio);
    if (window.speechSynthesis) window.speechSynthesis.cancel();
  }

  async function speak(markdown) {
    const text = plainText(markdown).slice(0, 2500);
    if (!text) return;
    stopSpeaking();
    const my = state.speakSeq;
    const provider = state.status && state.status.voice && state.status.voice.provider;
    if (provider === "elevenlabs") {
      const ctrl = typeof AbortController === "function" ? new AbortController() : null;
      state.speakAbort = ctrl;
      let audio = null;
      try {
        const res = await fetch("/api/voice/speak", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text }),
          signal: ctrl ? ctrl.signal : undefined,
        });
        if (my !== state.speakSeq) return;
        if (res.ok && (res.headers.get("content-type") || "").startsWith("audio/")) {
          const blob = await res.blob();
          if (my !== state.speakSeq) return;
          audio = new Audio(URL.createObjectURL(blob));
          audio.addEventListener("ended", () => releaseAudio(audio));
          state.audio = audio;
          await audio.play();
          return;
        }
      } catch {
        if (audio) releaseAudio(audio); // e.g. autoplay blocked: do not keep a dead element around
        if (my !== state.speakSeq) return; // aborted by stopSpeaking(): stay silent
        /* otherwise fall through to browser speech */
      } finally {
        if (state.speakAbort === ctrl) state.speakAbort = null;
      }
      if (my !== state.speakSeq) return;
    }
    if (!window.speechSynthesis) return;
    const u = new SpeechSynthesisUtterance(text);
    u.rate = 1.05;
    window.speechSynthesis.speak(u);
  }

  // ---------------------------------------------------------------- audit / reports / trace
  async function loadAudit() {
    try {
      const r = await api("/api/audit?limit=200");
      const badge = $("chain-badge");
      badge.hidden = false;
      badge.className = "chip " + (r.chain_ok ? "chip-live" : "chip-bad");
      badge.textContent = r.chain_ok ? "chain verified ✓" : "chain broken ✗";
      state.chainOk = Boolean(r.chain_ok);
      renderStamps();
      badge.title = "SHA-256 hash chain over every audit entry";
      const rows = (r.entries || []).map((e) => h("tr", {},
        h("td", { class: "mono", text: String(e.seq) }),
        h("td", { class: "mono", title: e.ts, text: fmtDateTime(e.ts) }),
        h("td", { text: e.actor }),
        h("td", { class: "mono", text: e.action }),
        h("td", { class: "mono", text: e.incident_id || "—" }),
        h("td", { class: "details", title: JSON.stringify(e.details), text: summarizeDetails(e.details) }),
        h("td", { class: "hash", title: e.hash, text: String(e.hash || "").slice(0, 12) })));
      $("audit-body").replaceChildren(...(rows.length ? rows : [h("tr", {}, h("td", { colspan: 7, class: "muted", text: "No audit entries yet." }))]));
    } catch (err) {
      toast(`Could not load audit log: ${err.message}`, true);
    }
  }

  function summarizeDetails(d) {
    if (!d || typeof d !== "object") return "";
    return Object.entries(d).slice(0, 4).map(([k, v]) => `${k}=${typeof v === "object" ? JSON.stringify(v) : v}`).join("  ");
  }

  async function loadReports() {
    try {
      const r = await api("/api/reports");
      const items = (r.reports || []).map((rep) => {
        const s3 = rep.location === "s3";
        return h("li", {},
          h("span", { class: `chip ${s3 ? "chip-aws" : "chip-sim"}`, text: s3 ? "S3" : "local" }),
          rep.incident_id ? h("span", { class: "mono", text: rep.incident_id }) : null,
          rep.format ? h("span", { class: "chip", text: rep.format }) : null,
          h("span", { class: "loc", text: rep.uri || rep.key || "" }),
          rep.last_modified ? h("span", { class: "muted", text: fmtDateTime(rep.last_modified) }) : null);
      });
      $("reports-list").replaceChildren(...(items.length ? items : [h("li", { class: "muted", text: "No reports yet." })]));
    } catch (err) {
      toast(`Could not load reports: ${err.message}`, true);
    }
  }

  async function generateReport() {
    if (!state.currentId) {
      toast("Select an incident first.", true);
      return;
    }
    const body = { requested_by: lsGet(LS_APPROVER) || "analyst" };
    try {
      const r = await api(`/api/reports/${encodeURIComponent(state.currentId)}`, { method: "POST", json: body });
      toast(`Report written: ${r.uri || r.markdown_key || "ok"}`);
      selectTab("reports");
      await Promise.all([loadReports(), loadAudit()]);
    } catch (err) {
      toast(`Report failed: ${err.message}`, true);
    }
  }

  async function loadTrace() {
    try {
      const r = await api("/api/trace/recent?limit=60");
      const items = (r.trace || []).slice().reverse().map((t, i, all) => traceEvent(t, all.length - i));
      $("trace-list").replaceChildren(...(items.length ? items : [h("li", { class: "muted", text: "No tool calls yet." })]));
    } catch {
      /* the trace tab is informational only */
    }
  }

  // ---------------------------------------------------------------- tabs
  const TABS = ["audit", "reports", "trace"];
  function selectTab(name) {
    for (const t of TABS) {
      const on = t === name;
      const tab = $(`tab-${t}`);
      tab.setAttribute("aria-selected", String(on));
      tab.tabIndex = on ? 0 : -1;
      $(`pane-${t}`).hidden = !on;
    }
    if (name === "reports") loadReports();
    if (name === "trace") loadTrace();
    if (name === "audit") loadAudit();
  }

  function onTabKey(e) {
    const i = TABS.indexOf(e.currentTarget.id.replace("tab-", ""));
    const step = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
    if (!step) return;
    const next = TABS[(i + step + TABS.length) % TABS.length];
    selectTab(next);
    $(`tab-${next}`).focus();
  }

  // ---------------------------------------------------------------- wiring
  function init() {
    $("detect-btn").addEventListener("click", runDetection);
    $("report-btn").addEventListener("click", generateReport);
    $("report-btn-top").addEventListener("click", generateReport);
    $("chat-form").addEventListener("submit", (e) => { e.preventDefault(); sendChat($("chat-input").value); });
    $("chat-input").addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey && !e.isComposing) {
        e.preventDefault();
        sendChat($("chat-input").value);
      }
    });
    for (const b of document.querySelectorAll(".suggestion")) b.addEventListener("click", () => sendChat(b.textContent));
    $("mic-btn").addEventListener("click", onMic);

    const speakToggle = $("speak-toggle");
    speakToggle.checked = lsGet(LS_SPEAK) === "1";
    speakToggle.addEventListener("change", () => {
      lsSet(LS_SPEAK, speakToggle.checked ? "1" : "0");
      if (!speakToggle.checked) stopSpeaking();
    });

    $("decision-form").addEventListener("submit", submitDecision);
    $("dlg-cancel").addEventListener("click", () => $("decision-dialog").close());
    $("decision-dialog").addEventListener("close", () => { state.decision = null; });

    for (const t of TABS) {
      const tab = $(`tab-${t}`);
      tab.addEventListener("click", () => selectTab(t));
      tab.addEventListener("keydown", onTabKey);
    }

    pollStatus();
    loadIncidents();
    loadAudit();
  }

  document.addEventListener("DOMContentLoaded", init);
})();
