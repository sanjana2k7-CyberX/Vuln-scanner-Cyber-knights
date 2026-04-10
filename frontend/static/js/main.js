/**
 * VulnPlatform — Frontend JS
 * Handles: scan flow, progress animation, results rendering,
 *          finding cards, detail modal, history, auth, export
 */

// ── State ──────────────────────────────────────────────────────────────────
let currentScanData = null;
let authToken = localStorage.getItem("vp_token") || null;
let authUser  = localStorage.getItem("vp_user")  || null;

// ── Init ───────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  setupNav();
  updateAuthUI();
  checkZapStatus();
  loadHistory();

  // Toggle AI key input visibility
  document.getElementById("useAI").addEventListener("change", e => {
    document.getElementById("aiKeyGroup").style.display = e.target.checked ? "flex" : "none";
  });
});

// ── Navigation ─────────────────────────────────────────────────────────────
function setupNav() {
  document.querySelectorAll(".nav-item").forEach(item => {
    item.addEventListener("click", e => {
      e.preventDefault();
      const panel = item.dataset.panel;
      document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
      item.classList.add("active");
      document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
      document.getElementById(`panel-${panel}`).classList.add("active");
      if (panel === "results") renderResultsPanel();
      if (panel === "history") loadHistory();
    });
  });
}

// ── ZAP Status ─────────────────────────────────────────────────────────────
async function checkZapStatus() {
  const dot = document.getElementById("zapStatus");
  const lbl = document.getElementById("zapLabel");
  try {
    const r = await fetch("http://localhost:8080/JSON/core/view/version/", { mode: "no-cors" });
    dot.className = "status-dot online";
    lbl.textContent = "ZAP: Online";
  } catch {
    dot.className = "status-dot offline";
    lbl.textContent = "ZAP: Mock Mode";
  }
}

// ── SCAN ───────────────────────────────────────────────────────────────────
async function startScan() {
  const url = document.getElementById("targetUrl").value.trim();
  if (!url || !url.startsWith("http")) {
    alert("Please enter a valid URL starting with http:// or https://");
    return;
  }

  const scanType = document.getElementById("scanType").value;
  const useAI    = document.getElementById("useAI").checked;
  const aiKey    = document.getElementById("aiKey").value.trim();

  // Disable button
  const btn = document.getElementById("scanBtn");
  btn.disabled = true;
  btn.innerHTML = `<svg class="spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z" opacity="0.2"/><path d="M21 12a9 9 0 0 0-9-9"/></svg> Scanning…`;

  // Show progress
  showProgress();
  await animateProgress(url, useAI);

  try {
    const payload = { url, scan_type: scanType, use_ai: useAI && !!aiKey };
    if (aiKey) {
      payload.openai_key = aiKey;
    }

    const headers = { "Content-Type": "application/json" };
    if (authToken) headers["Authorization"] = `Bearer ${authToken}`;

    const response = await fetch("/api/scan", {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.detail || "Scan failed");
    }

    currentScanData = await response.json();
    finishProgress();
    renderScanResults(currentScanData);

  } catch (err) {
    resetProgress();
    alert(`Scan error: ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/><line x1="11" y1="8" x2="11" y2="14"/><line x1="8" y1="11" x2="14" y2="11"/></svg> Launch Scan`;
  }
}

// ── PROGRESS ANIMATION ─────────────────────────────────────────────────────
function showProgress() {
  document.getElementById("progressWrap").style.display = "block";
  document.getElementById("summaryGrid").style.display = "none";
  document.getElementById("aiSummaryBox").style.display = "none";
  document.getElementById("inlineFindings").innerHTML = "";
  setProgress(0, "Initializing scan engine…");
  resetSteps();
}

function resetProgress() {
  document.getElementById("progressWrap").style.display = "none";
}

function resetSteps() {
  ["spider","active","idor","api","ai","report"].forEach(s => {
    const el = document.getElementById(`step-${s}`);
    el.className = "step";
    el.textContent = `⬡ ${el.textContent.replace(/[✔⬡] /, "")}`;
  });
}

function setProgress(pct, label) {
  document.getElementById("progressFill").style.width = `${pct}%`;
  document.getElementById("progressPct").textContent = `${pct}%`;
  document.getElementById("progressLabel").textContent = label;
}

function activateStep(id) {
  const el = document.getElementById(`step-${id}`);
  el.classList.add("active");
}
function doneStep(id) {
  const el = document.getElementById(`step-${id}`);
  el.classList.remove("active");
  el.classList.add("done");
  el.textContent = `✔ ${el.textContent.replace(/[✔⬡] /, "")}`;
}

async function animateProgress(url, useAI) {
  const steps = [
    { id: "spider",  pct: 15, label: `Spider crawling ${url}…`,          ms: 800 },
    { id: "active",  pct: 35, label: "Running active scan…",             ms: 900 },
    { id: "idor",    pct: 60, label: "Detecting IDOR vulnerabilities…",  ms: 700 },
    { id: "api",     pct: 78, label: "Testing API security…",            ms: 600 },
    { id: "ai",      pct: 90, label: useAI ? "Running AI analysis…" : "Scoring risks…", ms: 500 },
    { id: "report",  pct: 95, label: "Generating report…",              ms: 400 },
  ];
  for (const step of steps) {
    activateStep(step.id);
    setProgress(step.pct, step.label);
    await sleep(step.ms);
    doneStep(step.id);
  }
}

function finishProgress() {
  setProgress(100, "Scan complete!");
}

// ── RENDER RESULTS ─────────────────────────────────────────────────────────
function renderScanResults(data) {
  const s = data.summary;

  // Summary cards
  document.getElementById("sumCritical").textContent  = s.critical;
  document.getElementById("sumHigh").textContent       = s.high;
  document.getElementById("sumMedium").textContent     = s.medium;
  document.getElementById("sumLow").textContent        = s.low;
  document.getElementById("sumEndpoints").textContent  = s.total_endpoints;
  animateNumbers();
  document.getElementById("summaryGrid").style.display = "flex";

  // AI summary
  if (data.ai_summary && Object.keys(data.ai_summary).length > 0) {
    renderAISummary(data.ai_summary);
  }

  // Inline findings
  const container = document.getElementById("inlineFindings");
  container.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem">
      <h3 style="font-family:var(--font-display);font-size:18px;font-weight:700;color:#fff">
        Findings <span style="color:var(--text-dim);font-size:14px">(${data.findings.length})</span>
      </h3>
      <span style="font-size:11px;color:var(--text-dim)">Scan ID: ${data.scan_id}</span>
    </div>
    <div class="findings-list" id="findingsList"></div>
  `;

  renderFindingsList(data.findings, "findingsList");

  // Show export button in results panel
  document.getElementById("exportBtn").style.display = "block";
  document.getElementById("exportBtn").onclick = () => exportReport(data.scan_id);

  // Scroll to results
  document.getElementById("progressWrap").scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderAISummary(ai) {
  const box = document.getElementById("aiSummaryBox");
  const body = document.getElementById("aiSummaryBody");

  let html = "";
  if (ai.executive_summary) {
    html += `<p>${escHtml(ai.executive_summary)}</p>`;
  }
  if (ai.data_exposure_assessment) {
    html += `<h4>DATA EXPOSURE</h4><p>${escHtml(ai.data_exposure_assessment)}</p>`;
  }
  if (ai.critical_attack_scenario) {
    html += `<h4>CRITICAL ATTACK SCENARIO</h4><p>${escHtml(ai.critical_attack_scenario)}</p>`;
  }
  if (ai.attack_chain && ai.attack_chain.length) {
    html += `<h4>ATTACK CHAIN</h4>`;
    ai.attack_chain.forEach((step, i) => {
      html += `<div class="chain-step">
        <span class="chain-step-num">${i + 1}</span>
        <span>${escHtml(step)}</span>
      </div>`;
    });
  }
  if (ai.priority_fixes && ai.priority_fixes.length) {
    html += `<h4>FIX PRIORITY</h4><ul>`;
    ai.priority_fixes.forEach(f => { html += `<li>${escHtml(f)}</li>`; });
    html += `</ul>`;
  }

  body.innerHTML = html || "<p>AI analysis completed.</p>";
  box.style.display = "block";
}

function renderFindingsList(findings, containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  if (!findings || findings.length === 0) {
    container.innerHTML = `
      <div class="empty-state" style="padding:2rem">
        <div class="empty-icon">✓</div>
        <p>No vulnerabilities detected in this scan.</p>
      </div>`;
    return;
  }

  // Sort: Critical → High → Medium → Low
  const order = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  const sorted = [...findings].sort((a, b) =>
    (order[a.severity] ?? 4) - (order[b.severity] ?? 4)
  );

  container.innerHTML = sorted.map((f, i) => `
    <div class="finding-card ${f.severity}" onclick="openDetailModal(${i})" data-idx="${i}">
      <div class="finding-top">
        <div>
          <div class="finding-name">${escHtml(f.name)}</div>
          <div class="finding-type">${escHtml(f.type)} · ${escHtml(f.endpoint || "")}</div>
        </div>
        <div class="finding-badges">
          ${f.type === "IDOR" ? `<span class="badge IDOR">IDOR</span>` : ""}
          <span class="badge ${f.severity}">${f.severity}</span>
          <span class="badge score">⚡ ${f.risk_score}</span>
        </div>
      </div>
      <div class="finding-endpoint">${escHtml(f.endpoint || "")}</div>
      <div class="finding-desc">${escHtml((f.description || "").substring(0, 200))}${(f.description || "").length > 200 ? "…" : ""}</div>
      ${f.type === "IDOR" && f.similarity_score !== undefined ? `
        <div class="sbert-badge">
          🧠 Sentence-BERT similarity: ${(f.similarity_score * 100).toFixed(1)}%
          ${f.evidence?.similarity_method === "sentence-bert" ? "· SBERT" : "· Heuristic"}
        </div>` : ""}
    </div>
  `).join("");

  // Store sorted list for modal
  container._findings = sorted;
}

// ── RESULTS PANEL ──────────────────────────────────────────────────────────
function renderResultsPanel() {
  const panel = document.getElementById("findingsPanel");
  if (!currentScanData) {
    panel.innerHTML = `<div class="empty-state"><div class="empty-icon">⬡</div><p>No scan results yet. Run a scan from the Scan tab.</p></div>`;
    return;
  }
  panel.innerHTML = `
    <div style="margin-bottom:1rem;font-size:12px;color:var(--text-dim)">
      Target: <span style="color:var(--accent)">${escHtml(currentScanData.target_url)}</span>
      · Scan ID: ${currentScanData.scan_id}
      · ${new Date(currentScanData.timestamp).toLocaleString()}
    </div>
    <div class="findings-list" id="findingsListPanel"></div>
  `;
  renderFindingsList(currentScanData.findings, "findingsListPanel");
}

// ── DETAIL MODAL ───────────────────────────────────────────────────────────
function openDetailModal(idx) {
  const container = document.getElementById("findingsList") ||
                    document.getElementById("findingsListPanel");
  const findings = container?._findings || currentScanData?.findings || [];
  const f = findings[idx];
  if (!f) return;

  document.getElementById("detailTitle").textContent = f.name;

  const ev = f.evidence || {};
  const fix = f.fix || {};

  let evHtml = "";
  Object.entries(ev).forEach(([k, v]) => {
    const val = Array.isArray(v) ? v.join(", ") : JSON.stringify(v);
    evHtml += `<div><strong>${escHtml(k)}:</strong> ${escHtml(String(val))}</div>`;
  });

  const stepsHtml = (fix.steps || []).map(s =>
    `<li>${escHtml(s)}</li>`).join("");
  const refsHtml = (fix.references || []).map(r =>
    `<span class="ref-tag">${escHtml(r)}</span>`).join("");

  document.getElementById("detailBody").innerHTML = `
    <div class="detail-section">
      <h4>VULNERABILITY INFO</h4>
      <div style="display:flex;gap:8px;margin-bottom:0.75rem;flex-wrap:wrap">
        <span class="badge ${f.severity}">${f.severity}</span>
        <span class="badge score">Risk Score: ${f.risk_score}</span>
        <span class="badge score">CVSS ~${f.cvss_estimate}</span>
        <span class="badge score">Confidence: ${Math.round((f.confidence || 0) * 100)}%</span>
      </div>
      <div class="finding-endpoint">${escHtml(f.endpoint || "")}</div>
    </div>

    <div class="detail-section">
      <h4>DESCRIPTION</h4>
      <div class="detail-desc">${escHtml(f.description || "")}</div>
    </div>

    ${evHtml ? `<div class="detail-section">
      <h4>EVIDENCE</h4>
      <div class="detail-evidence">${evHtml}</div>
    </div>` : ""}

    ${f.type === "IDOR" ? `<div class="detail-section">
      <h4>IDOR ANALYSIS METHOD</h4>
      <div class="detail-evidence">
        <div><strong>similarity_score:</strong> ${f.similarity_score}</div>
        <div><strong>method:</strong> ${ev.similarity_method || "heuristic"}</div>
        <div><strong>interpretation:</strong> ${interpretSimilarity(f.similarity_score)}</div>
      </div>
      <div class="sbert-badge" style="margin-top:0.5rem">
        🧠 Sentence-BERT compares semantic content of responses across different IDs.
        Low similarity = responses differ = potential unauthorized data access.
      </div>
    </div>` : ""}

    <div class="detail-section">
      <h4>REMEDIATION</h4>
      <div class="fix-card">
        <div class="fix-title">✓ ${escHtml(fix.title || "Review and fix")}</div>
        <div class="fix-desc">${escHtml(fix.description || "")}</div>
        ${stepsHtml ? `<ul class="fix-steps">${stepsHtml}</ul>` : ""}
        ${fix.code_snippet ? `<pre class="code-snippet">${escHtml(fix.code_snippet)}</pre>` : ""}
        ${refsHtml ? `<div class="refs">${refsHtml}</div>` : ""}
      </div>
    </div>
  `;

  document.getElementById("detailModal").style.display = "flex";
}

function closeDetailModal(e) {
  if (!e || e.target.id === "detailModal" || e.currentTarget === undefined) {
    document.getElementById("detailModal").style.display = "none";
  }
}

function interpretSimilarity(score) {
  if (score === undefined) return "N/A";
  if (score < 0.4) return "Very different responses → strong IDOR signal";
  if (score < 0.6) return "Moderately different → likely IDOR";
  if (score < 0.8) return "Somewhat different → weak IDOR signal";
  return "Very similar → low IDOR risk";
}

// ── HISTORY ────────────────────────────────────────────────────────────────
async function loadHistory() {
  const container = document.getElementById("historyList");
  try {
    const r = await fetch("/api/history");
    const history = await r.json();

    if (!history.length) {
      container.innerHTML = `<div class="empty-state"><div class="empty-icon">⬡</div><p>No scan history.</p></div>`;
      return;
    }

    container.innerHTML = `
      <table class="history-table">
        <thead>
          <tr>
            <th>SCAN ID</th><th>URL</th><th>FINDINGS</th><th>CRITICAL</th><th>DATE</th><th>ACTION</th>
          </tr>
        </thead>
        <tbody>
          ${history.map(h => `
            <tr onclick="loadScanFromHistory('${h.scan_id}')">
              <td style="color:var(--accent);font-family:var(--font-mono)">${h.scan_id}</td>
              <td class="history-url">${escHtml(h.url)}</td>
              <td>${h.findings_count}</td>
              <td style="color:var(--sev-critical)">${h.critical}</td>
              <td class="history-date">${new Date(h.timestamp).toLocaleString()}</td>
              <td>
                <button class="btn-outline" onclick="event.stopPropagation();exportReport('${h.scan_id}')">↓ Export</button>
              </td>
            </tr>
          `).join("")}
        </tbody>
      </table>`;
  } catch (err) {
    container.innerHTML = `<div class="empty-state"><p>Error loading history: ${err.message}</p></div>`;
  }
}

async function loadScanFromHistory(scanId) {
  try {
    const r = await fetch(`/api/scan/${scanId}`);
    currentScanData = await r.json();
    // Switch to results panel
    document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
    document.querySelector("[data-panel='results']").classList.add("active");
    document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
    document.getElementById("panel-results").classList.add("active");
    renderResultsPanel();
  } catch {
    alert("Could not load scan data.");
  }
}

// ── EXPORT ─────────────────────────────────────────────────────────────────
async function exportReport(scanId) {
  const id = scanId || currentScanData?.scan_id;
  if (!id) { alert("No scan to export."); return; }

  try {
    const r = await fetch(`/api/export/${id}?fmt=json`);
    const blob = await r.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `vulnscan_${id}.json`;
    a.click();
  } catch {
    alert("Export failed.");
  }
}

// ── AUTH ───────────────────────────────────────────────────────────────────
function openLoginModal() {
  if (authToken) {
    // Already logged in → logout
    authToken = null; authUser = null;
    localStorage.removeItem("vp_token");
    localStorage.removeItem("vp_user");
    updateAuthUI();
    return;
  }
  document.getElementById("loginModal").style.display = "flex";
}

function closeLoginModal(e) {
  if (!e || e.target.id === "loginModal") {
    document.getElementById("loginModal").style.display = "none";
    document.getElementById("loginError").style.display = "none";
  }
}

async function doLogin() {
  const username = document.getElementById("modalUser").value.trim();
  const password = document.getElementById("modalPass").value;
  const errorEl  = document.getElementById("loginError");

  try {
    const r = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (!r.ok) {
      const e = await r.json();
      errorEl.textContent = e.detail || "Login failed";
      errorEl.style.display = "block";
      return;
    }
    const data = await r.json();
    authToken = data.token;
    authUser  = data.username;
    localStorage.setItem("vp_token", authToken);
    localStorage.setItem("vp_user", authUser);
    updateAuthUI();
    closeLoginModal();
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.style.display = "block";
  }
}

function updateAuthUI() {
  const userEl = document.getElementById("authUser");
  const btnEl  = document.getElementById("loginBtn");
  if (authUser) {
    userEl.textContent = authUser;
    btnEl.textContent  = "Logout";
  } else {
    userEl.textContent = "Not logged in";
    btnEl.textContent  = "Login";
  }
}

// ── HELPERS ────────────────────────────────────────────────────────────────
function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function animateNumbers() {
  document.querySelectorAll(".summary-num").forEach(el => {
    const target = parseInt(el.textContent, 10);
    if (!target) return;
    let current = 0;
    const step = Math.ceil(target / 20);
    const timer = setInterval(() => {
      current = Math.min(current + step, target);
      el.textContent = current;
      if (current >= target) clearInterval(timer);
    }, 40);
  });
}

// Add CSS for spin animation dynamically
const style = document.createElement("style");
style.textContent = `
  @keyframes spin { to { transform: rotate(360deg); } }
  .spin { animation: spin 0.8s linear infinite; }
`;
document.head.appendChild(style);