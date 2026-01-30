// options.js - Options page for Reflex extension

// ============================================================
// DOM ELEMENTS
// ============================================================

const els = {
  // Passive scanning
  passiveEnabled: document.getElementById("passiveEnabled"),

  // Scan options
  minLen: document.getElementById("minLen"),
  decodeDepth: document.getElementById("decodeDepth"),
  maxFindingsPerParam: document.getElementById("maxFindingsPerParam"),

  // Scan targets
  scanDomText: document.getElementById("scanDomText"),
  scanHtml: document.getElementById("scanHtml"),
  scanAttrs: document.getElementById("scanAttrs"),
  scanInlineScripts: document.getElementById("scanInlineScripts"),

  // Ignored params
  ignoreParams: document.getElementById("ignoreParams"),

  // Scope (for canary verification)
  inScopeHosts: document.getElementById("inScopeHosts"),

  // Canary verification
  canaryEnabled: document.getElementById("canaryEnabled"),
  canaryAutoVerify: document.getElementById("canaryAutoVerify"),
  maxCanaryVerifications: document.getElementById("maxCanaryVerifications"),

  // Taint detection
  enableTaintAnalysis: document.getElementById("enableTaintAnalysis"),
  enableInstrumentation: document.getElementById("enableInstrumentation"),
  minTokenLength: document.getElementById("minTokenLength"),

  // Save
  saveBtn: document.getElementById("saveBtn"),
  status: document.getElementById("status")
};

// ============================================================
// DEFAULTS
// ============================================================

const defaults = {
  // Passive scanning
  passiveEnabled: false,

  // Scan options
  minLen: 4,
  decodeDepth: 1,
  maxFindingsPerParam: 20,

  // Scan targets
  scanDomText: true,
  scanHtml: true,
  scanAttrs: true,
  scanInlineScripts: true,

  // Ignored params
  ignoreParams: [
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "gclid",
    "fbclid"
  ],

  // Scope (for canary verification)
  inScopeHosts: [],

  // Canary verification (active testing)
  canaryEnabled: false,
  canaryAutoVerify: false,
  maxCanaryVerifications: 3,

  // Taint detection
  enableTaintAnalysis: true,
  enableInstrumentation: false, // Runtime sink monitoring (off by default)
  minTokenLength: 6
};

// ============================================================
// INITIALIZATION
// ============================================================

init();

async function init() {
  // Load stored settings
  const stored = await chrome.storage.sync.get(Object.keys(defaults));
  const opts = { ...defaults, ...stored };

  // Populate passive scanning toggle
  els.passiveEnabled.checked = opts.passiveEnabled;

  // Populate scan options
  els.minLen.value = opts.minLen;
  els.decodeDepth.value = opts.decodeDepth;
  els.maxFindingsPerParam.value = opts.maxFindingsPerParam;

  // Populate scan targets
  els.scanDomText.checked = opts.scanDomText;
  els.scanHtml.checked = opts.scanHtml;
  els.scanAttrs.checked = opts.scanAttrs;
  els.scanInlineScripts.checked = opts.scanInlineScripts;

  // Populate ignored params
  els.ignoreParams.value = (opts.ignoreParams || []).join("\n");

  // Populate scope hosts
  els.inScopeHosts.value = (opts.inScopeHosts || []).join("\n");

  // Populate canary verification settings
  els.canaryEnabled.checked = opts.canaryEnabled;
  els.canaryAutoVerify.checked = opts.canaryAutoVerify;
  els.maxCanaryVerifications.value = opts.maxCanaryVerifications;

  // Populate taint detection settings
  els.enableTaintAnalysis.checked = opts.enableTaintAnalysis;
  els.enableInstrumentation.checked = opts.enableInstrumentation;
  els.minTokenLength.value = opts.minTokenLength;

  // Update UI state based on canary enabled
  updateCanaryUI();

  // Setup event listeners
  els.saveBtn.addEventListener("click", save);
  els.canaryEnabled.addEventListener("change", updateCanaryUI);
}

function updateCanaryUI() {
  const enabled = els.canaryEnabled.checked;
  els.canaryAutoVerify.disabled = !enabled;
  els.maxCanaryVerifications.disabled = !enabled;
  els.inScopeHosts.disabled = !enabled;
}

// ============================================================
// SAVE SETTINGS
// ============================================================

async function save() {
  // Parse ignored params
  const ignoreParams = els.ignoreParams.value
    .split("\n")
    .map(s => s.trim())
    .filter(Boolean);

  // Parse in-scope hosts (normalize to lowercase)
  const inScopeHosts = els.inScopeHosts.value
    .split("\n")
    .map(s => s.trim().toLowerCase())
    .filter(Boolean);

  // Build options object
  const opts = {
    // Passive scanning
    passiveEnabled: els.passiveEnabled.checked,

    // Scan options
    minLen: Number(els.minLen.value) || defaults.minLen,
    decodeDepth: Number(els.decodeDepth.value) || defaults.decodeDepth,
    maxFindingsPerParam: Number(els.maxFindingsPerParam.value) || defaults.maxFindingsPerParam,

    // Scan targets
    scanDomText: els.scanDomText.checked,
    scanHtml: els.scanHtml.checked,
    scanAttrs: els.scanAttrs.checked,
    scanInlineScripts: els.scanInlineScripts.checked,

    // Ignored params
    ignoreParams,

    // Scope
    inScopeHosts,

    // Canary verification
    canaryEnabled: els.canaryEnabled.checked,
    canaryAutoVerify: els.canaryAutoVerify.checked,
    maxCanaryVerifications: Number(els.maxCanaryVerifications.value) || defaults.maxCanaryVerifications,

    // Taint detection
    enableTaintAnalysis: els.enableTaintAnalysis.checked,
    enableInstrumentation: els.enableInstrumentation.checked,
    minTokenLength: Number(els.minTokenLength.value) || defaults.minTokenLength
  };

  try {
    await chrome.storage.sync.set(opts);
    showStatus("Settings saved");
  } catch (err) {
    console.error("[Reflex] Error saving settings:", err);
    showStatus("Error saving settings", true);
  }
}

// ============================================================
// UTILITIES
// ============================================================

function showStatus(message, isError = false) {
  els.status.textContent = message;
  els.status.style.color = isError ? "#e53935" : "#4caf50";
  setTimeout(() => {
    els.status.textContent = "";
  }, 2000);
}
