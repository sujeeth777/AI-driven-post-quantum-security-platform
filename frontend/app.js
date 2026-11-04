/* Q-SHIELD Web Control Center — vanilla JS SPA (no dependencies) */
"use strict";

/* ---------------- helpers ---------------- */

const $app = document.getElementById("app");

async function api(path, opts = {}) {
  const res = await fetch("/api" + path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  let body = null;
  try { body = await res.json(); } catch { /* non-JSON */ }
  if (!res.ok) {
    const detail = body && body.detail ? String(body.detail) : res.statusText;
    throw new Error(detail);
  }
  return body;
}

function toast(msg, ms = 4200) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(t._h);
  t._h = setTimeout(() => t.classList.remove("show"), ms);
}

const esc = (s) => String(s ?? "").replace(/[&<>"']/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const bandChip = (band) => `<span class="chip ${esc(band)}">${esc(band)}</span>`;
const num = (v, d = 1) => (v == null ? "–" : Number(v).toFixed(d));

function setupCanvas(canvas, height = 130) {
  const dpr = window.devicePixelRatio || 1;
  const width = canvas.parentElement.clientWidth - 2 || 300;
  canvas.width = width * dpr;
  canvas.height = height * dpr;
  canvas.style.width = width + "px";
  canvas.style.height = height + "px";
  const ctx = canvas.getContext("2d");
  ctx.scale(dpr, dpr);
  return { ctx, width, height };
}

/* gauge: 260° arc score */
function drawGauge(canvas, value, color, label) {
  const { ctx, width, height } = setupCanvas(canvas, 132);
  const cx = width / 2, cy = height / 2 + 8, r = Math.min(width, height) / 2 - 14;
  const start = Math.PI * 0.75, end = Math.PI * 2.25; // 270° sweep
  ctx.lineWidth = 10; ctx.lineCap = "round";
  ctx.strokeStyle = "#0a111c";
  ctx.beginPath(); ctx.arc(cx, cy, r, start, end); ctx.stroke();
  ctx.strokeStyle = color;
  ctx.shadowColor = color; ctx.shadowBlur = 12;
  ctx.beginPath(); ctx.arc(cx, cy, r, start, start + (end - start) * Math.min(1, value / 100)); ctx.stroke();
  ctx.shadowBlur = 0;
  ctx.fillStyle = "#d9e3ee";
  ctx.font = "700 26px ui-monospace, Consolas, monospace";
  ctx.textAlign = "center";
  ctx.fillText(String(Math.round(value)), cx, cy + 2);
  ctx.fillStyle = "#7e90a3";
  ctx.font = "10px ui-monospace, monospace";
  ctx.fillText(label, cx, cy + 18);
}

/* donut: band distribution */
function drawDonut(canvas, counts) {
  const { ctx, width, height } = setupCanvas(canvas, 120);
  const colors = { CRITICAL: "#f87171", HIGH: "#fb923c", MEDIUM: "#facc15", LOW: "#4ade80" };
  const total = Object.values(counts).reduce((a, b) => a + b, 0) || 1;
  const cx = 60, cy = height / 2, r = 44;
  let angle = -Math.PI / 2;
  for (const [band, color] of Object.entries(colors)) {
    const frac = (counts[band] || 0) / total;
    if (frac > 0) {
      ctx.beginPath();
      ctx.strokeStyle = color; ctx.lineWidth = 16;
      ctx.arc(cx, cy, r, angle, angle + frac * Math.PI * 2);
      ctx.stroke();
      angle += frac * Math.PI * 2;
    }
  }
  let y = cy - 34;
  ctx.textAlign = "left"; ctx.font = "11px ui-monospace, monospace";
  for (const [band, color] of Object.entries(colors)) {
    ctx.fillStyle = color;
    ctx.fillText(`${band.padEnd(9)} ${String(counts[band] ?? 0).padStart(3)}`, 128, y);
    y += 19;
  }
}

/* ---------------- pages ---------------- */

const state = { msgId: null, scan: null, policies: null };

const pages = {
  overview: renderOverview,
  scanner: renderScanner,
  migration: renderMigration,
  laboratory: renderLaboratory,
  exchange: renderExchange,
  assistant: renderAssistant,
};

function nav(page) {
  document.querySelectorAll("#nav a").forEach((a) =>
    a.classList.toggle("active", a.dataset.page === page));
}

async function route() {
  const page = (location.hash.replace("#/", "") || "overview");
  nav(page);
  const render = pages[page] || renderOverview;
  $app.innerHTML = `<div class="loading">loading…</div>`;
  try { await render(); }
  catch (err) {
    $app.innerHTML = `<div class="panel"><h3>error</h3><p>${esc(err.message)}</p></div>`;
  }
}
window.addEventListener("hashchange", route);

/* ----- overview ----- */

async function renderOverview() {
  const ov = await api("/overview");
  const scan = ov.scan;
  $app.innerHTML = `
    <h1 class="page-title">Quantum Security Operations</h1>
    <p class="page-sub">AI-driven post-quantum security &amp; healthcare privacy platform —
       AI proposes → engine validates → human approves.</p>
    <div class="grid g3">
      <div class="panel"><h3>Quantum Exposure ${scan ? "" : '<span class="hint">— run a scan</span>'}</h3>
        ${scan ? `<canvas class="chart" id="g-exposure"></canvas>` : `<p class="muted">No scan yet. The Scanner page can analyze the bundled vulnerable demo app.</p>`}
      </div>
      <div class="panel"><h3>Quantum Readiness (QRS)</h3>
        ${scan ? `<canvas class="chart" id="g-qrs"></canvas>` : `<p class="muted">Readiness is computed from the cryptographic inventory after a scan.</p>`}
      </div>
      <div class="panel"><h3>Risk distribution</h3>
        ${scan ? `<canvas class="chart" id="d-bands"></canvas>` : `<p class="muted">—</p>`}
      </div>
    </div>
    <div class="grid g2" style="margin-top:16px">
      <div class="panel"><h3>Platform</h3>
        <dl class="kv">
          <dt>Key establishment</dt><dd>ML-KEM-768 / ML-KEM-1024 + X25519 (hybrid)</dd>
          <dt>Signatures</dt><dd>ML-DSA-65 / 87 (FIPS 204)</dd>
          <dt>Bulk cipher</dt><dd>AES-256-GCM · HKDF-SHA-256</dd>
          <dt>Validation suite</dt><dd>27/27 security validations</dd>
          <dt>Last benchmark</dt><dd>${scan && ov.benchmark ? esc(ov.benchmark.timestamp.slice(0, 19)) : "none yet"}</dd>
          <dt>Store</dt><dd>data/store.json (Postgres-swappable)</dd>
        </dl>
      </div>
      <div class="panel"><h3>Recent security events</h3><div id="audit">${`<span class="muted">…</span>`}</div></div>
    </div>`;

  if (scan) {
    drawGauge(document.getElementById("g-exposure"), scan.exposure.score,
      scan.exposure.score >= 80 ? "#f87171" : scan.exposure.score >= 60 ? "#fb923c" : "#4ade80",
      scan.exposure.band);
    drawGauge(document.getElementById("g-qrs"), scan.readiness.qrs,
      scan.readiness.qrs >= 70 ? "#4ade80" : scan.readiness.qrs >= 40 ? "#facc15" : "#fb923c",
      scan.readiness.verdict);
    drawDonut(document.getElementById("d-bands"), scan.exposure.counts);
  }
  try {
    const audit = await api("/audit?limit=12");
    document.getElementById("audit").innerHTML = audit.length
      ? audit.map((a) => `<div class="audit-line"><span class="ev">${esc(a.event)}</span> ${esc(a.detail)}</div>`).join("")
      : `<span class="muted">no events yet</span>`;
  } catch { /* ok */ }
}

/* ----- scanner ----- */

async function renderScanner() {
  const ov = await api("/overview");
  const defPath = ov.vulnerable_demo_app || "demo/vulnerable_app";
  $app.innerHTML = `
    <h1 class="page-title">Cryptographic Discovery Engine</h1>
    <p class="page-sub">Scans a source tree for quantum-vulnerable cryptography and scores every finding.</p>
    <div class="panel">
      <div class="row">
        <div><label class="fld">Target path</label><input id="scan-path" size="38" value="${esc(defPath)}"></div>
        <div><label class="fld">Exposure</label>
          <select id="scan-exposure"><option value="public">public internet</option>
          <option value="internal">internal network</option><option value="isolated">isolated</option></select></div>
        <div><label class="fld">Data lifetime (years)</label><input id="scan-years" type="number" min="1" max="100" value="30" style="width:90px"></div>
        <button class="btn" id="btn-scan">Run scan</button>
      </div>
    </div>
    <div id="scan-results"></div>`;

  document.getElementById("btn-scan").onclick = async (e) => {
    const btn = e.target;
    btn.disabled = true; btn.textContent = "scanning…";
    try {
      const scan = await api("/scan", { method: "POST", body: JSON.stringify({
        path: document.getElementById("scan-path").value.trim(),
        exposure: document.getElementById("scan-exposure").value,
        data_lifetime_years: Number(document.getElementById("scan-years").value) || 30,
      })});
      state.scan = scan;
      renderScanResults(scan);
      toast(`Scan complete: ${scan.findings.length} findings, exposure ${scan.exposure.score}/100`);
    } catch (err) { toast("Scan failed: " + err.message); }
    btn.disabled = false; btn.textContent = "Run scan";
  };

  try {
    const latest = await api("/scan/latest");
    state.scan = latest;
    renderScanResults(latest);
  } catch { /* no scan yet */ }
}

function renderScanResults(scan) {
  const byAlg = {};
  scan.findings.forEach((f) => { byAlg[f.algorithm] = (byAlg[f.algorithm] || 0) + 1; });
  document.getElementById("scan-results").innerHTML = `
    <div class="grid g3" style="margin-top:16px">
      <div class="panel"><h3>Exposure</h3>
        <div class="stat-row"><span class="big-num" style="color:${scan.exposure.score >= 80 ? "var(--critical)" : "var(--medium)"}">${scan.exposure.score}</span>
        <div>${bandChip(scan.exposure.band)}<div class="stat-label">quantum exposure / 100</div></div></div>
      </div>
      <div class="panel"><h3>Readiness (QRS)</h3>
        <div class="stat-row"><span class="big-num" style="color:var(--accent)">${scan.readiness.qrs}</span>
        <div><span class="chip info">${esc(scan.readiness.verdict)}</span><div class="stat-label">${esc(scan.readiness.verdict)} readiness / 100</div></div></div>
      </div>
      <div class="panel"><h3>Bands</h3><canvas class="chart" id="d-bands2"></canvas></div>
    </div>
    <div class="panel" style="margin-top:16px"><h3>Cryptographic inventory — ${scan.findings.length} findings in ${scan.files_scanned} files <span class="hint">(${esc(scan.root)})</span></h3>
      <div style="max-height:430px;overflow-y:auto">
      <table><thead><tr><th>Risk</th><th>Algorithm</th><th>Location</th><th>Evidence</th><th>Usage</th></tr></thead><tbody>
      ${scan.findings.map((f) => `
        <tr>
          <td>${bandChip(f.risk_band)}<div class="mono muted">${num(f.risk_score)}</div>${f.hnd_l ? '<span class="flag-hndl">⚠ HNDL</span>' : ""}</td>
          <td><b>${esc(f.algorithm)}</b>${f.key_size ? ` <span class="mono muted">(${f.key_size})</span>` : ""}</td>
          <td class="mono">${esc(f.file.replace(scan.root, ""))}:${f.line}</td>
          <td class="mono muted">${esc(f.snippet.slice(0, 90))}</td>
          <td><span class="chip dim">${esc(f.usage)}</span></td>
        </tr>`).join("")}
      </tbody></table></div>
    </div>`;
  drawDonut(document.getElementById("d-bands2"), scan.exposure.counts);
}

/* ----- migration ----- */

async function renderMigration() {
  const plan = await api("/migration/latest");
  $app.innerHTML = `
    <h1 class="page-title">Quantum Migration Planner</h1>
    <p class="page-sub">Staged migration plan for <span class="mono">${esc(plan.system)}</span> —
      inventory → hybrid → testing → PQC-first → legacy removal.</p>
    <div class="grid g4">
      <div class="panel"><h3>To replace</h3><span class="big-num" style="color:var(--critical)">${plan.summary.to_replace}</span></div>
      <div class="panel"><h3>Keep (quantum-safe)</h3><span class="big-num" style="color:var(--ok)">${plan.summary.to_keep}</span></div>
      <div class="panel"><h3>P0 immediate</h3><span class="big-num" style="color:var(--high)">${plan.summary.p0_actions}</span></div>
      <div class="panel"><h3>Effort S/M/L</h3><span class="big-num mono">${plan.summary.estimated_effort.S}/${plan.summary.estimated_effort.M}/${plan.summary.estimated_effort.L}</span></div>
    </div>
    <div class="panel" style="margin-top:16px"><h3>Immediate actions (P0)</h3>
      <table><thead><tr><th>Priority</th><th>Algorithm</th><th>Replace with</th><th>Location</th></tr></thead><tbody>
      ${plan.immediate_actions.map((i) => `
        <tr><td><span class="chip CRITICAL">${esc(i.priority)}</span></td>
        <td><b>${esc(i.algorithm)}</b></td><td>${esc(i.target)}</td>
        <td class="mono muted">${esc(i.locations)}</td></tr>`).join("")}
      </tbody></table>
    </div>
    <div class="grid g2" style="margin-top:16px">
      ${plan.phases.map((p) => `
        <div class="panel"><h3><span class="phase-num">Phase ${p.stage}</span> — ${esc(p.name)}</h3>
          <ul class="steps">${p.actions.map((a) => `<li>${esc(a)}</li>`).join("")}</ul>
          ${p.items.length ? `<table style="margin-top:10px"><tbody>
            ${p.items.map((i) => `<tr><td><b>${esc(i.algorithm)}</b><div class="muted mono" style="font-size:10.5px">${esc(i.locations)}</div></td>
            <td>→ ${esc(i.target)}</td></tr>`).join("")}
          </tbody></table>` : ""}
        </div>`).join("")}
    </div>
    ${plan.keep.length ? `<div class="panel" style="margin-top:16px"><h3>Keep — already quantum-resistant</h3>
      ${plan.keep.map((i) => `<span class="chip ok" style="margin:2px 6px 2px 0">${esc(i.algorithm)}</span>`).join("")}</div>` : ""}`;
}

/* ----- laboratory ----- */

async function renderLaboratory() {
  $app.innerHTML = `
    <h1 class="page-title">PQC Benchmarking Laboratory</h1>
    <p class="page-sub">Measured on this machine — key generation, encapsulation, signing, and the full hybrid exchange.</p>
    <div class="panel">
      <button class="btn" id="btn-bench">Run benchmark</button>
      <span class="muted" style="margin-left:12px;font-size:12px">~5–10 s synchronous run · results stored to research/results/</span>
    </div>
    <div id="bench-results"></div>`;
  document.getElementById("btn-bench").onclick = async (e) => {
    const btn = e.target;
    btn.disabled = true; btn.textContent = "running…";
    try {
      const res = await api("/benchmark/run", { method: "POST" });
      renderBench(res.rows);
      toast(`Benchmark #${res.benchmark_id}: ${res.rows.length} measurements`);
    } catch (err) { toast("Benchmark failed: " + err.message); }
    btn.disabled = false; btn.textContent = "Run benchmark";
  };
  try {
    const bench = await api("/benchmark/latest");
    renderBench(bench.rows, bench.timestamp);
  } catch { /* none yet */ }
}

function renderBench(rows, ts) {
  const pick = (p, o) => rows.find((r) => r.primitive === p && r.op === o);
  const comparisons = [
    ["ML-KEM-768 keygen vs RSA-2048 keygen", pick("ML-KEM-768", "keygen"), pick("RSA-2048", "keygen")],
    ["ML-DSA-65 sign vs RSA-2048 sign", pick("ML-DSA-65", "sign"), pick("RSA-2048", "sign")],
    ["ML-DSA-65 verify vs RSA-2048 verify", pick("ML-DSA-65", "verify"), pick("RSA-2048", "verify")],
  ];
  document.getElementById("bench-results").innerHTML = `
    ${ts ? `<p class="muted" style="font-size:12px">Latest stored run: ${esc(ts.slice(0, 19))} UTC</p>` : ""}
    <div class="grid g2" style="margin-top:12px">
      <div class="panel"><h3>Headline comparison</h3>
        ${comparisons.map(([label, a, b]) => a && b ? `
          <div style="margin:12px 0">
            <div style="font-size:12px;margin-bottom:4px">${esc(label)}</div>
            <div class="bar-row"><span class="mono">PQC ${esc(a.primitive.split(" ")[0])}</span>
              <div class="bar-track"><div class="bar-fill" style="width:${Math.max(2, 100 * a.mean_ms / Math.max(a.mean_ms, b.mean_ms))}%"></div></div>
              <span class="mono">${a.mean_ms.toFixed(3)} ms</span></div>
            <div class="bar-row"><span class="mono">${esc(b.primitive)}</span>
              <div class="bar-track"><div class="bar-fill" style="width:${Math.max(2, 100 * b.mean_ms / Math.max(a.mean_ms, b.mean_ms))}%"></div></div>
              <span class="mono">${b.mean_ms.toFixed(3)} ms</span></div>
          </div>` : "").join("")}
      </div>
      <div class="panel"><h3>Full exchange cost</h3>
        <dl class="kv">
          <dt>Build package</dt><dd>${num(pick("Hybrid exchange (full)", "build_package")?.mean_ms, 3)} ms</dd>
          <dt>Open package</dt><dd>${num(pick("Hybrid exchange (full)", "open_package")?.mean_ms, 3)} ms</dd>
          <dt>Package size</dt><dd>${pick("Hybrid exchange (full)", "build_package")?.package_size ?? "–"} B</dd>
          <dt>ML-KEM ct / pk</dt><dd>1088 B / 1184 B</dd>
          <dt>ML-DSA sig / pk</dt><dd>3309 B / 1952 B</dd>
          <dt>RSA sig (baseline)</dt><dd>256 B — but Shor-vulnerable</dd>
        </dl>
      </div>
    </div>
    <div class="panel" style="margin-top:16px"><h3>All measurements</h3>
      <div style="max-height:420px;overflow-y:auto"><table>
        <thead><tr><th>Primitive</th><th>Operation</th><th>Mean ms</th><th>P95 ms</th><th>Sizes</th></tr></thead>
        <tbody>${rows.map((r) => `
          <tr><td><b>${esc(r.primitive)}</b></td><td class="mono">${esc(r.op)}</td>
          <td class="mono">${r.mean_ms.toFixed(3)}</td><td class="mono muted">${r.p95_ms.toFixed(3)}</td>
          <td class="mono muted">${["public_key", "signature", "ciphertext", "package_size"].filter((k) => r[k] != null).map((k) => `${k.split("_")[0]}=${r[k]}B`).join(" ") || "—"}</td></tr>`).join("")}
        </tbody></table></div>
    </div>`;
}

/* ----- exchange ----- */

async function renderExchange() {
  const pol = await api("/policies");
  state.policies = pol;
  const kemOpts = Object.keys(pol.kem).map((k) => `<option>${k}</option>`).join("");
  const sigOpts = Object.keys(pol.sig).map((k) => `<option>${k}</option>`).join("");
  $app.innerHTML = `
    <h1 class="page-title">Secure Medical Data Exchange</h1>
    <p class="page-sub">Hospital A → Hospital B over the Q-SHIELD hybrid channel. Switch algorithms live via the crypto agility layer.</p>
    <div class="grid g2">
      <div class="panel"><h3>Send from Hospital A</h3>
        <div class="row">
          <div><label class="fld">KEM</label><select id="pol-kem">${kemOpts}</select></div>
          <div><label class="fld">Signature</label><select id="pol-sig">${sigOpts}</select></div>
          <button class="btn" id="btn-send" style="align-self:end">Encrypt &amp; send</button>
        </div>
        <div class="flow" style="margin-top:14px">
          <span class="node">record</span><span class="arrow">→</span>
          <span class="node hot">ML-KEM + X25519 → HKDF</span><span class="arrow">→</span>
          <span class="node hot">AES-256-GCM</span><span class="arrow">→</span>
          <span class="node hot">ML-DSA sign</span><span class="arrow">→</span>
          <span class="node">transfer/</span>
        </div>
        <div id="pkg-inspect" style="margin-top:12px"></div>
      </div>
      <div class="panel"><h3>Receive at Hospital B</h3>
        <button class="btn ghost" id="btn-recv" ${state.msgId ? "" : "disabled"}>Verify &amp; decrypt latest package</button>
        <div id="recv-out" style="margin-top:12px"><span class="muted">send a package first</span></div>
      </div>
    </div>
    <div class="grid g2" style="margin-top:16px">
      <div class="panel"><h3>Attack laboratory <span class="hint">— watch every adversary get rejected</span></h3>
        <div class="row">
          <button class="btn danger sm" data-attack="tamper">Tamper payload</button>
          <button class="btn danger sm" data-attack="mitm">MITM KEM swap</button>
          <button class="btn danger sm" data-attack="forge">Forge signature</button>
          <button class="btn danger sm" data-attack="replay">Replay package</button>
        </div>
        <div id="attack-out" style="margin-top:12px"><span class="muted">requires a sent package</span></div>
      </div>
      <div class="panel"><h3>Forward-secrecy session <span class="hint">— TLS-style ephemeral handshake</span></h3>
        <button class="btn ghost" id="btn-session">Run FS session handshake</button>
        <div id="session-out" style="margin-top:12px"><span class="muted">ephemeral ML-KEM + X25519 keys, destroyed after use</span></div>
      </div>
    </div>`;

  document.getElementById("btn-send").onclick = async (e) => {
    const btn = e.target;
    btn.disabled = true; btn.textContent = "encrypting…";
    try {
      const res = await api("/exchange/send", { method: "POST", body: JSON.stringify({
        kem: document.getElementById("pol-kem").value,
        sig: document.getElementById("pol-sig").value,
      })});
      state.msgId = res.msg_id;
      document.getElementById("btn-recv").disabled = false;
      document.getElementById("pkg-inspect").innerHTML = `
        <div class="mono" style="font-size:12px">package <b>${esc(res.msg_id)}</b> · built in ${res.build_ms} ms</div>
        <div style="margin:6px 0">
          <span class="chip info">payload ${res.sizes.payload} B</span>
          <span class="chip info">package ${res.sizes.package} B</span>
          <span class="chip info">kem_ct ${res.sizes.kem_ct} B</span>
          <span class="chip info">signature ${res.sizes.signature} B</span>
        </div>
        <div class="pkg-field"><b>ciphertext:</b> ${esc(res.package.ciphertext.slice(0, 88))}…</div>
        <div class="pkg-field"><b>signature:</b> ${esc(res.package.signature.slice(0, 88))}…</div>`;
      document.getElementById("recv-out").innerHTML = `<span class="muted">package ready — receive it</span>`;
      toast(`Package ${res.msg_id} sent (${res.policy.kem} + ${res.policy.sig})`);
    } catch (err) { toast("Send failed: " + err.message); }
    btn.disabled = false; btn.textContent = "Encrypt & send";
  };

  document.getElementById("btn-recv").onclick = async () => {
    const out = document.getElementById("recv-out");
    out.innerHTML = `<span class="muted">verifying…</span>`;
    try {
      const res = await api(`/exchange/receive/${state.msgId}`, { method: "POST" });
      out.innerHTML = `
        <ul class="steps">${res.steps.map((s) => `<li>${esc(s)}</li>`).join("")}</ul>
        <div class="panel" style="margin-top:10px;background:#0a111c">
          <h3>Decrypted record</h3>
          <dl class="kv">
            <dt>Patient</dt><dd>${esc(res.record.patient_id)}</dd>
            <dt>MRI report</dt><dd>${esc(res.record.mri_report || "—")}</dd>
            <dt>Diagnosis</dt><dd>${esc(res.record.diagnosis || "—")}</dd>
            <dt>Prescription</dt><dd>${esc(res.record.prescription || "—")}</dd>
          </dl>
          <div class="muted mono" style="margin-top:8px;font-size:11px">decrypted in ${res.open_ms} ms</div>
        </div>`;
    } catch (err) {
      out.innerHTML = `<span class="chip CRITICAL">REJECTED</span> <span class="muted">${esc(err.message)}</span>`;
    }
  };

  document.querySelectorAll("[data-attack]").forEach((btn) => {
    btn.onclick = async () => {
      if (!state.msgId) { toast("Send a package first"); return; }
      const out = document.getElementById("attack-out");
      out.innerHTML = `<span class="muted">attacking (${btn.dataset.attack})…</span>`;
      try {
        const res = await api("/exchange/attack", { method: "POST", body: JSON.stringify({
          msg_id: state.msgId, kind: btn.dataset.attack })});
        const accepted = res.result.startsWith("ACCEPTED");
        out.innerHTML = accepted
          ? `<span class="chip HIGH">${esc(res.result)}</span>`
          : `<span class="chip LOW">REJECTED</span> <span class="mono muted">${esc(res.error)}</span>
             <div class="muted" style="font-size:12px;margin-top:4px">${esc(res.detail || "")}</div>`;
      } catch (err) {
        const rejected = /rejected/i.test(err.message);
        out.innerHTML = rejected
          ? `<span class="chip LOW">REJECTED</span> <span class="muted">${esc(err.message)}</span>`
          : `<span class="chip HIGH">${esc(err.message)}</span>`;
      }
    };
  });

  document.getElementById("btn-session").onclick = async () => {
    const out = document.getElementById("session-out");
    out.innerHTML = `<span class="muted">handshaking…</span>`;
    try {
      const res = await api("/exchange/session", { method: "POST" });
      out.innerHTML = `
        <ul class="steps">${res.steps.map((s) => `<li>${esc(s.name)} <span class="mono muted">${s.ms} ms</span></li>`).join("")}</ul>
        <div class="chip ok" style="margin-top:8px">${esc(res.forward_secrecy.slice(0, 80))}…</div>`;
    } catch (err) { out.innerHTML = `<span class="chip CRITICAL">failed</span> ${esc(err.message)}`; }
  };
}

/* ----- assistant ----- */

async function renderAssistant() {
  $app.innerHTML = `
    <h1 class="page-title">AI Security Assistant</h1>
    <p class="page-sub">Deterministic reasoning over live platform data — LLM-ready gateway behind the same interface.</p>
    <div class="grid g2">
      <div class="panel"><h3>Ask Q-SHIELD</h3>
        <div class="chat" id="chat"></div>
        <div class="row" style="margin-top:10px">
          <input id="chat-in" style="flex:1" placeholder="e.g. why is our hospital's RSA vulnerable?">
          <button class="btn" id="chat-send">Ask</button>
        </div>
        <div class="suggest">
          ${["Why is our hospital's RSA vulnerable?", "What should replace it?",
             "What's our current risk?", "Explain harvest now decrypt later",
             "How do we migrate?", "How fast is ML-KEM compared to RSA?"]
            .map((s) => `<button data-q="${esc(s)}">${esc(s)}</button>`).join("")}
        </div>
      </div>
      <div class="panel"><h3>AI Security Analyzer <span class="hint">— natural language → security spec</span></h3>
        <textarea id="an-in">I operate a hospital network where doctors access patient records from multiple locations. We use RSA certificates and need protection against future quantum attacks. Patient records require 30 years of confidentiality and we cannot immediately remove our existing RSA infrastructure.</textarea>
        <button class="btn ghost" id="btn-analyze" style="margin-top:10px">Extract security specification</button>
        <div id="an-out" style="margin-top:12px"></div>
      </div>
    </div>`;

  const chat = document.getElementById("chat");
  const addBubble = (cls, html) => {
    const div = document.createElement("div");
    div.className = `bubble ${cls}`;
    div.innerHTML = html;
    chat.appendChild(div);
    chat.scrollTop = chat.scrollHeight;
  };
  addBubble("bot", `<span class="intent">q-shield</span>Hello — ask me about quantum risk, PQC algorithms, your scan results, or the migration plan.`);

  const ask = async (text) => {
    if (!text.trim()) return;
    addBubble("user", esc(text));
    try {
      const res = await api("/assistant", { method: "POST", body: JSON.stringify({ message: text }) });
      addBubble("bot", `<span class="intent">${esc(res.intent)}</span>${esc(res.answer)}`);
    } catch (err) { addBubble("bot", esc("error: " + err.message)); }
  };

  document.getElementById("chat-send").onclick = () => {
    const inp = document.getElementById("chat-in");
    ask(inp.value); inp.value = "";
  };
  document.getElementById("chat-in").addEventListener("keydown", (e) => {
    if (e.key === "Enter") { ask(e.target.value); e.target.value = ""; }
  });
  document.querySelectorAll(".suggest button").forEach((b) => {
    b.onclick = () => ask(b.dataset.q);
  });

  document.getElementById("btn-analyze").onclick = async (e) => {
    const btn = e.target;
    btn.disabled = true;
    try {
      const res = await api("/analyze", { method: "POST", body: JSON.stringify({
        text: document.getElementById("an-in").value })});
      const s = res.spec;
      document.getElementById("an-out").innerHTML = `
        <dl class="kv">
          <dt>Organization</dt><dd>${esc(s.organization)}</dd>
          <dt>Data types</dt><dd>${esc(s.data_types.join(", "))}</dd>
          <dt>Confidentiality</dt><dd>${esc(String(s.confidentiality_duration_years))} years
            <span class="muted">(${esc(s.duration_evidence)})</span></dd>
          <dt>Threat model</dt><dd>${esc(s.threat_model)}</dd>
          <dt>Current crypto</dt><dd>${esc(s.current_crypto.join(", "))}</dd>
          <dt>Requirements</dt><dd>${Object.entries(s.requirements).map(([k, v]) => `${esc(k)}: <b>${esc(v)}</b>`).join("<br>")}</dd>
          <dt>Recommendation</dt><dd>KEM <b>${esc(s.recommendation.kem)}</b> · SIG <b>${esc(s.recommendation.sig)}</b>
            · AEAD ${esc(s.recommendation.aead)}<br>${esc(s.recommendation.deployment)}</dd>
        </dl>`;
    } catch (err) { toast("Analyze failed: " + err.message); }
    btn.disabled = false;
  };
}

/* ---------------- boot ---------------- */

(async function boot() {
  try {
    await api("/overview");
    document.getElementById("status-pill").classList.add("online");
    document.getElementById("status-text").textContent = "PROTECTED · engine online";
  } catch {
    document.getElementById("status-text").textContent = "engine offline";
  }
  route();
})();
