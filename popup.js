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

// Store current scan data for export
let currentScanData = null;

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
    hostInfo.textContent = currentHost;
  } catch {
    hostInfo.textContent = tab.url;
  }

  // Check passive status
  await updatePassiveIndicator();

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

  let metaText = `Found reflections for ${data.reflectedParamCount}/${data.candidateParamCount} parameters`;
  if (fragCount > 0) {
    metaText += ` (${queryCount} query, ${fragCount} fragment)`;
  }
  meta.textContent = metaText;

  if (!data.findings?.length) {
    results.innerHTML = '<div class="empty">No reflections detected.</div>';
    exportBtn.disabled = true;
    return;
  }

  // Enable export button
  exportBtn.disabled = false;

  renderFindings(data.findings);
}

function renderFindings(findings) {
  results.innerHTML = "";

  for (const f of findings) {
    const div = document.createElement("div");
    div.className = "param";

    // Header with param name, source, and match count
    const header = document.createElement("div");
    header.className = "param-header";

    const sourceClass = f.source === "fragment" ? "source-pill fragment" : "source-pill";
    const sourceLabel = f.source === "fragment" ? "#" : "?";

    header.innerHTML = `
      <span class="param-name">${escapeHtml(f.param)}</span>
      <span class="${sourceClass}" title="${f.source} parameter">${sourceLabel}</span>
      <span class="pill">${f.matches.length} match${f.matches.length !== 1 ? "es" : ""}</span>
    `;
    div.appendChild(header);

    // Original value
    const valueDiv = document.createElement("div");
    valueDiv.className = "param-value";
    valueDiv.textContent = `Value: ${f.original}`;
    div.appendChild(valueDiv);

    // Matches (limit to 6 for UI)
    const sortedMatches = sortMatchesByInterest(f.matches);
    for (const m of sortedMatches.slice(0, 6)) {
      div.appendChild(renderMatch(m));
    }

    // Show "and X more" if truncated
    if (f.matches.length > 6) {
      const more = document.createElement("div");
      more.className = "param-value";
      more.textContent = `...and ${f.matches.length - 6} more`;
      div.appendChild(more);
    }

    results.appendChild(div);
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

  // Interest badge
  const interest = m.interest || "low";
  const interestLabel = interest.charAt(0).toUpperCase() + interest.slice(1);

  // Build encoding info HTML
  let encodingHtml = "";
  if (m.encoding && (m.encoding.raw?.length || m.encoding.encoded?.length)) {
    encodingHtml = '<div class="encoding-info">';

    if (m.encoding.raw?.length) {
      const rawChars = m.encoding.raw.map(c => escapeHtml(c)).join(" ");
      encodingHtml += `<span class="encoding-badge encoding-raw" title="These characters reflect unencoded (potential injection)">RAW: ${rawChars}</span>`;
    }

    if (m.encoding.encoded?.length) {
      const encChars = m.encoding.encoded.map(c => escapeHtml(c)).join(" ");
      encodingHtml += `<span class="encoding-badge encoding-encoded" title="These characters are encoded">ENC: ${encChars}</span>`;
    }

    encodingHtml += "</div>";
  }

  matchDiv.innerHTML = `
    <div class="match-kind">
      ${kindText}
      <span class="interest interest-${interest}">${interestLabel}</span>
    </div>
    <div class="snippet">${escapeHtml(m.snippet)}</div>
    ${encodingHtml}
  `;

  return matchDiv;
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
