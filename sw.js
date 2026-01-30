// sw.js - Service worker for Reflex extension
// Orchestrates injection, messaging, passive scanning, and badge updates

// ============================================================
// STATE
// ============================================================

// Per-tab scan results for popup display
// Map<tabId, { result, timestamp }>
const tabResults = new Map();

// Per-tab verification state
// Map<tabId, { verificationCount, lastVerifiedParam, debounceTimestamps }>
const tabVerificationState = new Map();

// Canary verification constants
const CANARY_PREFIX = "rfx";
const CANARY_LENGTH = 12;
const VERIFICATION_DEBOUNCE_MS = 5000; // 5 seconds between same-param verifications

// ============================================================
// MESSAGE HANDLING
// ============================================================

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const type = msg?.type;

  if (type === "RUN_SCAN") {
    // Manual scan from popup
    runScanOnActiveTab()
      .then((result) => sendResponse({ ok: true, result }))
      .catch((err) => sendResponse({ ok: false, error: String(err) }));
    return true;
  }

  if (type === "PASSIVE_SCAN_RESULT") {
    // Passive scan result from content script
    handlePassiveScanResult(sender.tab?.id, msg.result);
    sendResponse({ ok: true });
    return false;
  }

  if (type === "GET_TAB_RESULTS") {
    // Get stored results for a tab (for popup display)
    const data = tabResults.get(msg.tabId);
    sendResponse({ result: data?.result || null });
    return false;
  }

  if (type === "GET_PASSIVE_STATUS") {
    // Check if passive scanning is enabled
    loadSettings()
      .then((settings) => sendResponse({ passiveEnabled: settings.passiveEnabled }))
      .catch(() => sendResponse({ passiveEnabled: false }));
    return true;
  }

  if (type === "GET_CANARY_STATUS") {
    // Check if canary verification is available for current host
    loadSettings()
      .then((settings) => {
        const host = msg.host?.toLowerCase() || "";
        const isInScope = isHostInScope(host, settings.inScopeHosts || []);
        sendResponse({
          canaryEnabled: settings.canaryEnabled && isInScope,
          isInScope,
          maxVerifications: settings.maxCanaryVerifications || 3
        });
      })
      .catch(() => sendResponse({ canaryEnabled: false, isInScope: false }));
    return true;
  }

  if (type === "VERIFY_FINDING") {
    // Run canary verification for a specific finding
    verifyFinding(msg.tabId, msg.url, msg.param, msg.source, msg.liveReload || false)
      .then((result) => sendResponse(result))
      .catch((err) => sendResponse({ ok: false, error: String(err) }));
    return true;
  }
});

// ============================================================
// NAVIGATION LISTENERS FOR PASSIVE SCANNING
// ============================================================

// Listen for completed navigations to trigger passive scans
chrome.webNavigation.onCompleted.addListener(async (details) => {
  // Only handle main frame navigations
  if (details.frameId !== 0) return;

  try {
    await maybeStartPassiveScan(details.tabId, details.url);
  } catch (err) {
    console.error("[Reflex] Error starting passive scan:", err);
  }
});

// Also listen for history state updates (SPA navigation)
chrome.webNavigation.onHistoryStateUpdated.addListener(async (details) => {
  if (details.frameId !== 0) return;

  try {
    await maybeStartPassiveScan(details.tabId, details.url);
  } catch (err) {
    console.error("[Reflex] Error on history update:", err);
  }
});

// Clean up when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  tabResults.delete(tabId);
  tabVerificationState.delete(tabId);
});

// Clear results when navigating away
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    // Reset results when page starts loading
    tabResults.delete(tabId);
    tabVerificationState.delete(tabId);
    updateBadge(tabId, 0);
  }
});

// ============================================================
// PASSIVE SCANNING LOGIC
// ============================================================

/**
 * Check if passive scanning should run and start if enabled.
 * Passive scanning runs on all sites when passiveEnabled is true.
 */
async function maybeStartPassiveScan(tabId, url) {
  const settings = await loadSettings();

  // Check if passive scanning is enabled
  if (!settings.passiveEnabled) {
    return;
  }

  // Skip non-http(s) URLs
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    return;
  }

  // Load scan options
  const options = await loadOptions();

  try {
    // Inject content script
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ["content.js"]
    });

    // Start passive scanning in content script
    await chrome.tabs.sendMessage(tabId, {
      type: "START_PASSIVE",
      options
    });
  } catch (err) {
    // May fail on restricted pages (chrome://, etc.)
    console.debug("[Reflex] Could not start passive scan:", err.message);
  }
}

/**
 * Handle passive scan results from content script.
 * Updates badge and stores results for popup.
 */
function handlePassiveScanResult(tabId, result) {
  if (!tabId) return;

  const count = result?.reflectedParamCount || 0;

  // Store results for popup retrieval
  tabResults.set(tabId, {
    result,
    timestamp: Date.now()
  });

  // Update badge
  updateBadge(tabId, count);
}

/**
 * Update the extension badge for a tab.
 */
function updateBadge(tabId, count) {
  if (count > 0) {
    chrome.action.setBadgeText({ tabId, text: String(count) });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#e53935" }); // Red
  } else {
    chrome.action.setBadgeText({ tabId, text: "" });
  }
}

// ============================================================
// MANUAL SCAN
// ============================================================

/**
 * Run a manual scan on the active tab (triggered from popup).
 */
async function runScanOnActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) throw new Error("No active tab");

  const options = await loadOptions();

  // Inject content script
  await chrome.scripting.executeScript({
    target: { tabId: tab.id },
    files: ["content.js"]
  });

  // Ask the content script to scan
  const response = await chrome.tabs.sendMessage(tab.id, {
    type: "SCAN_PAGE",
    options
  });

  // Store results and update badge
  const count = response?.reflectedParamCount || 0;
  tabResults.set(tab.id, {
    result: response,
    timestamp: Date.now()
  });
  updateBadge(tab.id, count);

  return response;
}

// ============================================================
// SETTINGS & OPTIONS LOADING
// ============================================================

/**
 * Load settings (passive mode, canary settings).
 */
async function loadSettings() {
  const defaults = {
    passiveEnabled: false,
    canaryEnabled: false,
    canaryAutoVerify: false,
    maxCanaryVerifications: 3,
    inScopeHosts: []
  };

  const stored = await chrome.storage.sync.get(Object.keys(defaults));
  return { ...defaults, ...stored };
}

// ============================================================
// CANARY VERIFICATION
// ============================================================

/**
 * Generate a benign canary string.
 * Format: rfx-[random alphanumeric]
 * No special characters that could be interpreted as code.
 */
function generateCanary() {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let canary = CANARY_PREFIX + "-";
  for (let i = 0; i < CANARY_LENGTH; i++) {
    canary += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return canary;
}

/**
 * Check if a hostname matches the in-scope list.
 * Supports wildcard prefix (e.g., *.example.com matches sub.example.com).
 */
function isHostInScope(hostname, scopeList) {
  if (!scopeList || !scopeList.length) return false;

  const host = hostname.toLowerCase();

  for (const pattern of scopeList) {
    const p = pattern.toLowerCase().trim();
    if (!p) continue;

    if (p.startsWith("*.")) {
      // Wildcard: *.example.com matches example.com and sub.example.com
      const domain = p.slice(2);
      if (host === domain || host.endsWith("." + domain)) {
        return true;
      }
    } else {
      // Exact match
      if (host === p) return true;
    }
  }

  return false;
}

/**
 * Verify a finding by sending a canary request.
 * Returns verification result.
 *
 * @param {number} tabId - Tab ID
 * @param {string} urlStr - Current page URL
 * @param {string} paramName - Parameter name to verify
 * @param {string} source - "query" or "fragment"
 * @param {boolean} liveReload - If true, reload the actual page instead of using fetch
 */
async function verifyFinding(tabId, urlStr, paramName, source, liveReload = false) {
  const settings = await loadSettings();

  // Parse URL
  let url;
  try {
    url = new URL(urlStr);
  } catch {
    return { ok: false, error: "Invalid URL" };
  }

  // Check scope
  if (!isHostInScope(url.hostname, settings.inScopeHosts)) {
    return { ok: false, error: "Host not in scope" };
  }

  // Check if canary is enabled
  if (!settings.canaryEnabled) {
    return { ok: false, error: "Canary verification disabled" };
  }

  // Get/initialize tab verification state
  let state = tabVerificationState.get(tabId);
  if (!state) {
    state = { verificationCount: 0, debounceTimestamps: new Map(), pendingCanary: null };
    tabVerificationState.set(tabId, state);
  }

  // Check verification limit
  const maxVerifications = settings.maxCanaryVerifications || 3;
  if (state.verificationCount >= maxVerifications) {
    return { ok: false, error: `Max verifications (${maxVerifications}) reached for this page` };
  }

  // Check debounce for this param
  const debounceKey = `${paramName}:${source}`;
  const lastVerified = state.debounceTimestamps.get(debounceKey) || 0;
  if (Date.now() - lastVerified < VERIFICATION_DEBOUNCE_MS) {
    return { ok: false, error: "Please wait before re-verifying this parameter" };
  }

  // Generate canary
  const canary = generateCanary();

  // Build verification URL
  const verifyUrl = new URL(urlStr);
  if (source === "query") {
    verifyUrl.searchParams.set(paramName, canary);
  } else if (source === "fragment") {
    // Handle fragment parameters
    let hash = verifyUrl.hash.slice(1);
    try {
      const hashParams = new URLSearchParams(hash.includes("?") ? hash.split("?")[1] : hash);
      hashParams.set(paramName, canary);
      if (hash.includes("?")) {
        verifyUrl.hash = hash.split("?")[0] + "?" + hashParams.toString();
      } else {
        verifyUrl.hash = hashParams.toString();
      }
    } catch {
      return { ok: false, error: "Could not modify fragment parameter" };
    }
  } else {
    return { ok: false, error: "Unsupported parameter source" };
  }

  // Update state
  state.verificationCount++;
  state.debounceTimestamps.set(debounceKey, Date.now());

  // For fragment parameters or live reload requests, we need to actually navigate
  // because fetch() doesn't send fragments to the server and won't execute JS
  if (source === "fragment" || liveReload) {
    // Store the canary so we can check for it after page loads
    state.pendingCanary = {
      canary,
      paramName,
      source,
      timestamp: Date.now()
    };

    // Navigate the tab to the verification URL
    try {
      await chrome.tabs.update(tabId, { url: verifyUrl.toString() });

      return {
        ok: true,
        verified: null, // Unknown until page reloads
        canary,
        verifiedAt: new Date().toISOString(),
        verificationMethod: "live-reload",
        notes: "Page reloading with canary. Re-scan to check reflection.",
        pendingVerification: true
      };
    } catch (err) {
      return {
        ok: false,
        error: `Navigation failed: ${err.message}`
      };
    }
  }

  // For query parameters, try fetch first (non-disruptive)
  try {
    const response = await fetch(verifyUrl.toString(), {
      method: "GET",
      credentials: "include", // Include cookies for auth
      redirect: "follow"
    });

    if (!response.ok) {
      return {
        ok: true,
        verified: false,
        canary,
        verifiedAt: new Date().toISOString(),
        verificationMethod: "canary-fetch",
        notes: `HTTP ${response.status} ${response.statusText}`
      };
    }

    const text = await response.text();
    const reflected = text.includes(canary);

    // If not found in raw HTML, suggest live reload for JS-rendered content
    if (!reflected) {
      return {
        ok: true,
        verified: false,
        canary,
        verifiedAt: new Date().toISOString(),
        verificationMethod: "canary-fetch",
        notes: "Not in raw HTML. Try 'Live Verify' for JS-rendered content.",
        suggestLiveReload: true
      };
    }

    return {
      ok: true,
      verified: true,
      canary,
      verifiedAt: new Date().toISOString(),
      verificationMethod: "canary-fetch",
      notes: "Canary found in server response"
    };
  } catch (err) {
    return {
      ok: true,
      verified: false,
      canary,
      verifiedAt: new Date().toISOString(),
      verificationMethod: "canary-fetch",
      notes: `Fetch failed: ${err.message}`
    };
  }
}

/**
 * Load scan options.
 */
async function loadOptions() {
  const defaults = {
    minLen: 4,
    ignoreParams: ["utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "gclid", "fbclid"],
    decodeDepth: 1,
    scanDomText: true,
    scanHtml: true,
    scanAttrs: true,
    scanInlineScripts: true,
    maxFindingsPerParam: 20,
    // Taint detection
    enableTaintAnalysis: true,
    enableInstrumentation: false,
    minTokenLength: 6
  };

  const stored = await chrome.storage.sync.get(Object.keys(defaults));
  return { ...defaults, ...stored };
}
