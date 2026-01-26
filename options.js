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
  ]
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

  // Setup event listeners
  els.saveBtn.addEventListener("click", save);
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
    ignoreParams
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
