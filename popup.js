// popup.js - Popup UI for Reflex extension

// DOM elements
const hostInfo = document.getElementById("hostInfo");
const passiveIndicator = document.getElementById("passiveIndicator");
const scanBtn = document.getElementById("scanBtn");
const exportBtn = document.getElementById("exportBtn");
const meta = document.getElementById("meta");
const results = document.getElementById("results");

// Current tab info
let currentTabId = null;
let currentHost = null;
let currentUrl = null;

// Store current scan data for export
let currentScanData = null;

// Canary verification state
let canaryEnabled = false;
let canaryIsInScope = false;

// Track verification status per finding (paramName:source -> status)
const verificationStatus = new Map();

// ============================================================
// INITIALIZATION
// ============================================================

init();

async function init() {
  // Get current tab info
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  if (!tab?.url) {
    hostInfo.textContent = "No active tab";
    return;
  }

  currentTabId = tab.id;

  // Display host
  try {
    const url = new URL(tab.url);
    currentHost = url.hostname;
    currentUrl = tab.url;
    hostInfo.textContent = currentHost;
  } catch {
    hostInfo.textContent = tab.url;
    currentUrl = tab.url;
  }

  // Check passive status
  await updatePassiveIndicator();

  // Check canary verification status
  await updateCanaryStatus();

  // Load any existing results for this tab
  await loadExistingResults();

  // Setup event listeners
  scanBtn.addEventListener("click", handleScan);
  exportBtn.addEventListener("click", handleExport);

  // Listen for messages from background (passive scan updates)
  chrome.runtime.onMessage.addListener(handleMessage);
}

// ============================================================
// PASSIVE STATUS
// ============================================================

async function updatePassiveIndicator() {
  try {
    const status = await chrome.runtime.sendMessage({ type: "GET_PASSIVE_STATUS" });
    if (status.passiveEnabled) {
      passiveIndicator.textContent = "Passive On";
      passiveIndicator.classList.add("active");
    } else {
      passiveIndicator.textContent = "Passive Off";
      passiveIndicator.classList.remove("active");
    }
  } catch {
    passiveIndicator.textContent = "Passive Off";
  }
}

// ============================================================
// CANARY VERIFICATION STATUS
// ============================================================

async function updateCanaryStatus() {
  try {
    const status = await chrome.runtime.sendMessage({
      type: "GET_CANARY_STATUS",
      host: currentHost
    });
    canaryEnabled = status.canaryEnabled;
    canaryIsInScope = status.isInScope;
  } catch {
    canaryEnabled = false;
    canaryIsInScope = false;
  }
}

// ============================================================
// AUTO-LOAD RESULTS
// ============================================================

async function loadExistingResults() {
  if (!currentTabId) return;

  try {
    const response = await chrome.runtime.sendMessage({
      type: "GET_TAB_RESULTS",
      tabId: currentTabId
    });

    if (response?.result) {
      displayResults(response.result);
    }
  } catch (err) {
    console.debug("[Reflex] No existing results:", err);
  }
}

// ============================================================
// MESSAGE HANDLING (for live updates)
// ============================================================

function handleMessage(msg, sender) {
  // If passive scan completes on our tab, update the display
  if (msg?.type === "PASSIVE_SCAN_RESULT" && sender?.tab?.id === currentTabId) {
    displayResults(msg.result);
  }
}

// ============================================================
// MANUAL SCANNING
// ============================================================

async function handleScan() {
  meta.textContent = "Scanning...";
  results.innerHTML = "";
  scanBtn.disabled = true;
  exportBtn.disabled = true;

  try {
    const resp = await chrome.runtime.sendMessage({ type: "RUN_SCAN" });

    if (!resp?.ok) {
      meta.textContent = `Error: ${resp?.error || "Unknown error"}`;
      scanBtn.disabled = false;
      return;
    }

    displayResults(resp.result);
  } catch (err) {
    meta.textContent = `Error: ${err.message}`;
    console.error("[Reflex] Scan error:", err);
  }

  scanBtn.disabled = false;
}

// ============================================================
// EXPORT TO JSON
// ============================================================

function handleExport() {
  if (!currentScanData) return;

  // Build export object
  const exportData = {
    exportedAt: new Date().toISOString(),
    ...currentScanData
  };

  // Create blob and download
  const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);

  // Generate filename from host and timestamp
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const safeHost = (currentHost || "unknown").replace(/[^a-z0-9.-]/gi, "_");
  const filename = `reflex-${safeHost}-${timestamp}.json`;

  // Create download link and click it
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ============================================================
// DISPLAY RESULTS
// ============================================================

function displayResults(data) {
  if (!data) {
    meta.textContent = "No scan data available.";
    results.innerHTML = "";
    currentScanData = null;
    exportBtn.disabled = true;
    return;
  }

  // Store for export
  currentScanData = data;

  // Count query vs fragment params
  const queryCount = data.findings?.filter(f => f.source === "query").length || 0;
  const fragCount = data.findings?.filter(f => f.source === "fragment").length || 0;

  const taintCount = data.taint?.findingCount || 0;

  let metaText = `Found reflections for ${data.reflectedParamCount}/${data.candidateParamCount} parameters`;
  if (fragCount > 0) {
    metaText += ` (${queryCount} query, ${fragCount} fragment)`;
  }
  if (taintCount > 0) {
    metaText += ` · ${taintCount} taint flow${taintCount !== 1 ? "s" : ""}`;
  }
  meta.textContent = metaText;

  const hasFindings = data.findings?.length > 0;
  const hasTaint = taintCount > 0;

  if (!hasFindings && !hasTaint) {
    results.innerHTML = '<div class="empty">No reflections or taint flows detected.</div>';
    exportBtn.disabled = true;
    return;
  }

  // Enable export button
  exportBtn.disabled = false;

  if (hasFindings) {
    renderFindings(data.findings);
  } else {
    results.innerHTML = "";
  }

  // Render taint findings if available
  if (hasTaint) {
    renderTaintFindings(data.taint);
  }
}

function renderFindings(findings) {
  results.innerHTML = "";

  for (const f of findings) {
    const div = document.createElement("div");
    div.className = "param";

    const sortedMatches = sortMatchesByInterest(f.matches);

    // Determine the highest interest level across all matches
    const highestInterest = sortedMatches[0]?.interest || "low";

    // Get verification status for this finding
    const verifyKey = `${f.param}:${f.source}`;
    const verifyState = verificationStatus.get(verifyKey);

    // Header row (always visible, clickable to expand)
    const header = document.createElement("div");
    header.className = "param-header";

    const sourceClass = f.source === "fragment" ? "source-pill fragment" : "source-pill";
    const sourceLabel = f.source === "fragment" ? "#" : "?";
    const interestLabel = highestInterest.charAt(0).toUpperCase() + highestInterest.slice(1);

    // Verification status badge
    let verifyBadge = "";
    if (verifyState?.verified === true) {
      verifyBadge = '<span class="verify-badge verified" title="Canary verified">Verified</span>';
    } else if (verifyState?.verified === false) {
      verifyBadge = '<span class="verify-badge not-verified" title="Canary not reflected">Not Verified</span>';
    }

    header.innerHTML = `
      <span class="param-chevron">&#9654;</span>
      <span class="param-name">${escapeHtml(f.param)}</span>
      <span class="${sourceClass}" title="${f.source} parameter">${sourceLabel}</span>
      <span class="pill">${f.matches.length} match${f.matches.length !== 1 ? "es" : ""}</span>
      <span class="highest-interest interest-${highestInterest}">${interestLabel}</span>
      ${verifyBadge}
    `;
    header.addEventListener("click", (e) => {
      // Don't toggle if clicking on verify button
      if (e.target.classList.contains("verify-btn")) return;
      div.classList.toggle("expanded");
    });
    div.appendChild(header);

    // Body (hidden until expanded) - shows all matches, no truncation
    const body = document.createElement("div");
    body.className = "param-body";

    const valueDiv = document.createElement("div");
    valueDiv.className = "param-value";
    valueDiv.textContent = `Value: ${f.original}`;
    body.appendChild(valueDiv);

    // Add verification controls if canary is enabled
    if (canaryEnabled) {
      const verifyDiv = document.createElement("div");
      verifyDiv.className = "verify-controls";

      if (verifyState?.verified !== undefined) {
        // Show verification result
        const statusIcon = verifyState.verified ? "&#10003;" : (verifyState.pendingVerification ? "&#8635;" : "&#10007;");
        let statusText = verifyState.verified ? "Reflection confirmed" : "Not in response";
        let statusClass = verifyState.verified ? "success" : "fail";

        if (verifyState.pendingVerification) {
          statusText = "Page reloaded with canary";
          statusClass = "pending";
        }

        const canaryText = verifyState.canary ? `<code class="canary-value">${escapeHtml(verifyState.canary)}</code>` : "";
        const notesText = verifyState.notes ? `<div class="verify-notes">${escapeHtml(verifyState.notes)}</div>` : "";

        // Show live verify suggestion if fetch didn't find it
        let liveVerifyBtn = "";
        if (verifyState.suggestLiveReload && !verifyState.verified) {
          liveVerifyBtn = `<button class="verify-btn live" data-param="${escapeHtml(f.param)}" data-source="${f.source}" data-live="true">Live Verify</button>`;
        }

        verifyDiv.innerHTML = `
          <div class="verify-result-row">
            <span class="verify-result ${statusClass}">
              ${statusIcon} ${statusText}
            </span>
            ${canaryText}
          </div>
          ${notesText}
          <div class="verify-actions">
            <button class="verify-btn retry" data-param="${escapeHtml(f.param)}" data-source="${f.source}">Re-verify</button>
            ${liveVerifyBtn}
          </div>
        `;
      } else {
        // Show verify buttons - different options for query vs fragment
        const isFragment = f.source === "fragment";
        if (isFragment) {
          // Fragment params need live reload (can't use fetch)
          verifyDiv.innerHTML = `
            <div class="verify-hint">Fragment params require page reload to verify</div>
            <button class="verify-btn live" data-param="${escapeHtml(f.param)}" data-source="${f.source}" data-live="true">Live Verify (reloads page)</button>
          `;
        } else {
          verifyDiv.innerHTML = `
            <button class="verify-btn" data-param="${escapeHtml(f.param)}" data-source="${f.source}">Verify (fetch)</button>
            <button class="verify-btn live" data-param="${escapeHtml(f.param)}" data-source="${f.source}" data-live="true">Live Verify</button>
          `;
        }
      }

      // Add click handler for verify buttons
      verifyDiv.querySelectorAll(".verify-btn").forEach(btn => {
        btn.addEventListener("click", (e) => {
          e.stopPropagation();
          const liveReload = btn.dataset.live === "true";
          handleVerify(btn.dataset.param, btn.dataset.source, btn, liveReload);
        });
      });

      body.appendChild(verifyDiv);
    } else if (canaryIsInScope === false && currentHost) {
      // Show hint about adding to scope
      const scopeHint = document.createElement("div");
      scopeHint.className = "scope-hint";
      scopeHint.textContent = "Enable canary verification in Options and add this host to scope";
      body.appendChild(scopeHint);
    }

    for (const m of sortedMatches) {
      body.appendChild(renderMatch(m));
    }

    div.appendChild(body);
    results.appendChild(div);
  }
}

async function handleVerify(paramName, source, buttonEl, liveReload = false) {
  buttonEl.disabled = true;
  buttonEl.textContent = liveReload ? "Reloading..." : "Verifying...";

  try {
    const result = await chrome.runtime.sendMessage({
      type: "VERIFY_FINDING",
      tabId: currentTabId,
      url: currentUrl,
      param: paramName,
      source: source,
      liveReload: liveReload
    });

    if (result.ok) {
      // Store verification result
      verificationStatus.set(`${paramName}:${source}`, {
        verified: result.verified,
        canary: result.canary,
        notes: result.notes,
        verifiedAt: result.verifiedAt,
        pendingVerification: result.pendingVerification,
        suggestLiveReload: result.suggestLiveReload
      });

      // If live reload was triggered, the popup will close
      // The user needs to re-open it and scan again to see results
      if (result.pendingVerification) {
        // Popup will close when page navigates
        return;
      }
    } else {
      // Store error
      verificationStatus.set(`${paramName}:${source}`, {
        verified: false,
        notes: result.error
      });
    }

    // Re-render findings to show updated status
    if (currentScanData?.findings) {
      renderFindings(currentScanData.findings);
    }
  } catch (err) {
    buttonEl.disabled = false;
    buttonEl.textContent = "Verify (Error)";
    console.error("[Reflex] Verification error:", err);
  }
}

function renderMatch(m) {
  const matchDiv = document.createElement("div");
  matchDiv.className = `match ${m.interest || "low"}`;

  // Kind and subtype
  let kindText = escapeHtml(m.kind);
  if (m.subtype) {
    kindText += ` <span class="subtype">${escapeHtml(m.subtype)}</span>`;
  }
  if (m.location) {
    kindText += ` <span class="subtype">${escapeHtml(m.location)}</span>`;
  }

  // Count badge (for collapsed identical matches)
  const countHtml = m.count > 1 ? `<span class="count-badge">&times;${m.count}</span>` : "";

  // Interest badge
  const interest = m.interest || "low";
  const interestLabel = interest.charAt(0).toUpperCase() + interest.slice(1);

  // Build encoding info HTML
  let encodingHtml = "";
  if (m.encoding) {
    if (m.encoding.tested === false) {
      encodingHtml = '<div class="encoding-info"><span class="encoding-badge encoding-untested" title="Original value lacks special characters (< > &quot; \' &amp;) — encoding behavior unknown. Test with a value containing these chars.">Encoding: ?</span></div>';
    } else if (m.encoding.raw?.length || m.encoding.encoded?.length || m.encoding.stripped?.length) {
      encodingHtml = '<div class="encoding-info">';

      if (m.encoding.raw?.length) {
        const rawChars = m.encoding.raw.map(c => escapeHtml(c)).join(" ");
        encodingHtml += `<span class="encoding-badge encoding-raw" title="These characters reflect unencoded (potential injection)">RAW: ${rawChars}</span>`;
      }

      if (m.encoding.encoded?.length) {
        const encChars = m.encoding.encoded.map(c => escapeHtml(c)).join(" ");
        encodingHtml += `<span class="encoding-badge encoding-encoded" title="These characters are encoded">ENC: ${encChars}</span>`;
      }

      if (m.encoding.stripped?.length) {
        const strippedChars = m.encoding.stripped.map(c => escapeHtml(c)).join(" ");
        encodingHtml += `<span class="encoding-badge encoding-stripped" title="These characters were removed entirely">STRIPPED: ${strippedChars}</span>`;
      }

      encodingHtml += "</div>";
    }
  }

  // Build occurrences section (for collapsed duplicates)
  let occurrencesHtml = "";
  if (m.count > 1 && m.occurrences?.length > 1) {
    const occList = m.occurrences.slice(1).map(o =>
      `<div class="occurrence-snippet">${escapeHtml(o.snippet)}</div>`
    ).join("");
    occurrencesHtml = `
      <div class="occurrences-toggle" onclick="this.parentElement.classList.toggle('show-occurrences')">
        Show ${m.occurrences.length - 1} more occurrence${m.occurrences.length > 2 ? "s" : ""}...
      </div>
      <div class="occurrences-list">${occList}</div>
    `;
  }

  // Build sink hint HTML
  let sinkHintHtml = "";
  if (m.sinkHint) {
    const confClass = `sink-hint-${m.sinkHint.confidence || "low"}`;
    sinkHintHtml = `
      <div class="sink-hint ${confClass}" title="${escapeHtml(m.sinkHint.proximityEvidence || "")}">
        DOM XSS: ${escapeHtml(m.sinkHint.sinkType)}
      </div>
    `;
  }

  matchDiv.innerHTML = `
    <div class="match-kind">
      ${kindText} ${countHtml}
      <span class="interest interest-${interest}">${interestLabel}</span>
    </div>
    ${sinkHintHtml}
    <div class="snippet">${escapeHtml(m.snippet)}</div>
    ${encodingHtml}
    ${occurrencesHtml}
  `;

  return matchDiv;
}

/**
 * Render taint flow findings (source → sink analysis).
 */
function renderTaintFindings(taintData) {
  if (!taintData?.findings?.length) return;

  // Create taint section header
  const taintSection = document.createElement("div");
  taintSection.className = "taint-section";

  const taintHeader = document.createElement("div");
  taintHeader.className = "taint-header";
  taintHeader.innerHTML = `
    <h3>Taint Flow Analysis</h3>
    <span class="taint-count">${taintData.findingCount} potential flow${taintData.findingCount !== 1 ? "s" : ""}</span>
  `;
  taintSection.appendChild(taintHeader);

  // Group findings by category
  const byCategory = {};
  for (const f of taintData.findings) {
    const cat = f.findingType || "Unknown";
    if (!byCategory[cat]) byCategory[cat] = [];
    byCategory[cat].push(f);
  }

  // Render each category
  for (const [category, findings] of Object.entries(byCategory)) {
    const catDiv = document.createElement("div");
    catDiv.className = "taint-category";

    const catHeader = document.createElement("div");
    catHeader.className = "taint-category-header";
    catHeader.innerHTML = `
      <span class="category-name">${escapeHtml(category)}</span>
      <span class="category-count">${findings.length}</span>
    `;
    catHeader.addEventListener("click", () => catDiv.classList.toggle("expanded"));
    catDiv.appendChild(catHeader);

    const catBody = document.createElement("div");
    catBody.className = "taint-category-body";

    for (const f of findings) {
      catBody.appendChild(renderTaintFinding(f));
    }

    catDiv.appendChild(catBody);
    taintSection.appendChild(catDiv);
  }

  results.appendChild(taintSection);
}

/**
 * Render a truncatable value: short preview with expand toggle for full text.
 * If the value is short enough, just renders it inline.
 */
function renderTruncatable(value, previewLen = 80, cssClass = "taint-value") {
  if (!value) return "";
  const escaped = escapeHtml(value);
  if (value.length <= previewLen) {
    return `<span class="${cssClass}">${escaped}</span>`;
  }
  const preview = escapeHtml(value.slice(0, previewLen));
  // Use a <details> for expand/collapse with the full value inside
  return `<details class="${cssClass}-expandable"><summary class="${cssClass}">${preview}…</summary><span class="${cssClass} ${cssClass}-full">${escaped}</span></details>`;
}

/**
 * Render a single taint finding.
 */
function renderTaintFinding(f) {
  const div = document.createElement("div");
  div.className = `taint-finding confidence-${f.confidence || "low"}`;

  const severityClass = {
    critical: "severity-critical",
    high: "severity-high",
    medium: "severity-medium",
    low: "severity-low"
  }[f.sink?.severity] || "severity-low";

  // Source → Sink flow header
  const flowHtml = `
    <div class="taint-flow">
      <span class="taint-source" title="Source: ${escapeHtml(f.source?.type || "")}">
        ${escapeHtml(f.source?.key || "?")}
      </span>
      <span class="taint-arrow">→</span>
      <span class="taint-sink ${severityClass}" title="Sink: ${escapeHtml(f.sink?.name || "")}">
        ${escapeHtml(f.sink?.name || "?")}
      </span>
    </div>
  `;

  // Confidence and match type
  const confidenceHtml = `
    <div class="taint-confidence">
      <span class="confidence-badge confidence-${f.confidence}">${f.confidence?.toUpperCase() || "?"}</span>
      <span class="match-type">${escapeHtml(f.matchType || "")}</span>
    </div>
  `;

  // Source value (expandable)
  let sourceValueHtml = "";
  if (f.source?.value) {
    sourceValueHtml = `
      <div class="taint-detail-row">
        <span class="taint-detail-label">Source value:</span>
        ${renderTruncatable(f.source.value, 80, "taint-value")}
      </div>
    `;
  }

  // Sink value (expandable)
  let sinkValueHtml = "";
  if (f.sink?.value) {
    sinkValueHtml = `
      <div class="taint-detail-row">
        <span class="taint-detail-label">Sink value:</span>
        ${renderTruncatable(f.sink.value, 80, "taint-value")}
      </div>
    `;
  }

  // Evidence (expandable)
  let evidenceHtml = "";
  if (f.evidence) {
    evidenceHtml = `
      <div class="taint-detail-row">
        <span class="taint-detail-label">Evidence:</span>
        ${renderTruncatable(f.evidence, 100, "taint-evidence")}
      </div>
    `;
  }

  // DOM path if available
  const domPathHtml = f.domPath ? `
    <div class="taint-detail-row">
      <span class="taint-detail-label">DOM:</span>
      <span class="taint-dom-path">${escapeHtml(f.domPath)}</span>
    </div>
  ` : "";

  // Selector risk details (for Selector-Injection findings)
  let selectorRisksHtml = "";
  if (f.selectorRisks?.length) {
    const riskItems = f.selectorRisks.map(r => {
      const riskClass = `selector-risk-${r.risk}`;
      return `<span class="selector-risk ${riskClass}" title="${escapeHtml(r.notes)}">${escapeHtml(r.id)}</span>`;
    }).join(" ");
    selectorRisksHtml = `
      <div class="selector-risks">
        <span class="selector-risks-label">Selector risks:</span>
        ${riskItems}
      </div>
    `;
  }

  // Triage hints
  let hintsHtml = "";
  if (f.triageHints?.length) {
    const hintsList = f.triageHints.slice(0, 3).map(h =>
      `<li>${escapeHtml(h)}</li>`
    ).join("");
    hintsHtml = `
      <div class="taint-hints">
        <details>
          <summary>Triage hints</summary>
          <ul>${hintsList}</ul>
        </details>
      </div>
    `;
  }

  div.innerHTML = flowHtml + confidenceHtml + sourceValueHtml + sinkValueHtml + evidenceHtml + selectorRisksHtml + domPathHtml + hintsHtml;
  return div;
}

/**
 * Sort matches by interest level (high first, then medium, then low).
 */
function sortMatchesByInterest(matches) {
  const order = { high: 0, medium: 1, low: 2 };
  return [...matches].sort((a, b) => {
    const orderA = order[a.interest] ?? 2;
    const orderB = order[b.interest] ?? 2;
    return orderA - orderB;
  });
}

// ============================================================
// UTILITIES
// ============================================================

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
