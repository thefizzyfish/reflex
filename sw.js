// sw.js - Service worker for Reflex extension
// Orchestrates injection, messaging, passive scanning, and badge updates

// ============================================================
// STATE
// ============================================================

// Per-tab scan results for popup display
// Map<tabId, { result, timestamp }>
const tabResults = new Map();

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
});

// Clear results when navigating away
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    // Reset results when page starts loading
    tabResults.delete(tabId);
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
 * Load settings (passive mode).
 */
async function loadSettings() {
  const defaults = {
    passiveEnabled: false
  };

  const stored = await chrome.storage.sync.get(Object.keys(defaults));
  return { ...defaults, ...stored };
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
    maxFindingsPerParam: 20
  };

  const stored = await chrome.storage.sync.get(Object.keys(defaults));
  return { ...defaults, ...stored };
}
