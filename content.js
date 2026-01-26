// content.js - Runs in page context, scans for reflections
// Supports both on-demand scanning and passive (auto) scanning with SPA support

(() => {
  // Prevent multiple injections
  if (window.__reflexInjected) return;
  window.__reflexInjected = true;

  // ============================================================
  // CLASSIFICATION CONSTANTS
  // ============================================================

  // Interest levels for security relevance:
  //   HIGH: Direct code execution risk (event handlers, inline scripts, javascript: URLs, unquoted attrs)
  //   MEDIUM: Indirect risk (URLs in href/src, style injection)
  //   LOW: Display only, minimal direct risk (plain text)
  const INTEREST = { HIGH: "high", MEDIUM: "medium", LOW: "low" };

  // Characters to check for encoding - these are the key XSS breakout chars
  const ENCODING_TEST_CHARS = ["<", ">", '"', "'", "&"];

  // Attribute classification
  const EVENT_HANDLER_ATTRS = new Set([
    "onabort", "onafterprint", "onbeforeprint", "onbeforeunload", "onblur",
    "oncanplay", "oncanplaythrough", "onchange", "onclick", "oncontextmenu",
    "oncopy", "oncuechange", "oncut", "ondblclick", "ondrag", "ondragend",
    "ondragenter", "ondragleave", "ondragover", "ondragstart", "ondrop",
    "ondurationchange", "onemptied", "onended", "onerror", "onfocus",
    "onhashchange", "oninput", "oninvalid", "onkeydown", "onkeypress",
    "onkeyup", "onload", "onloadeddata", "onloadedmetadata", "onloadstart",
    "onmessage", "onmousedown", "onmousemove", "onmouseout", "onmouseover",
    "onmouseup", "onmousewheel", "onoffline", "ononline", "onpagehide",
    "onpageshow", "onpaste", "onpause", "onplay", "onplaying", "onpopstate",
    "onprogress", "onratechange", "onreset", "onresize", "onscroll",
    "onsearch", "onseeked", "onseeking", "onselect", "onstalled", "onstorage",
    "onsubmit", "onsuspend", "ontimeupdate", "ontoggle", "onunload",
    "onvolumechange", "onwaiting", "onwheel"
  ]);

  const URL_ATTRS = new Set(["href", "src", "action", "formaction", "data", "poster", "srcset"]);
  const STYLE_ATTRS = new Set(["style"]);

  // ============================================================
  // PASSIVE SCAN STATE
  // ============================================================

  let passiveOptions = null;
  let lastScanSignature = null;
  let rescanCount = 0;
  const MAX_RESCANS = 10; // Max SPA rescans per page load
  const DEBOUNCE_MS = 750;
  let debounceTimer = null;
  let observer = null;

  // ============================================================
  // MESSAGE HANDLING
  // ============================================================

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg?.type === "SCAN_PAGE") {
      // On-demand scan from popup
      const options = msg.options || {};
      const result = scanPage(options);
      sendResponse(result);
    } else if (msg?.type === "START_PASSIVE") {
      // Start passive scanning for this page
      passiveOptions = msg.options || {};
      startPassiveScanning();
      sendResponse({ ok: true });
    } else if (msg?.type === "STOP_PASSIVE") {
      // Stop passive scanning
      stopPassiveScanning();
      sendResponse({ ok: true });
    }
  });

  // ============================================================
  // PASSIVE SCANNING
  // ============================================================

  function startPassiveScanning() {
    if (observer) return; // Already running

    rescanCount = 0;
    lastScanSignature = null;

    // Initial scan after short delay (let page settle)
    setTimeout(() => {
      runPassiveScan();
      setupMutationObserver();
    }, 300);
  }

  function stopPassiveScanning() {
    if (observer) {
      observer.disconnect();
      observer = null;
    }
    if (debounceTimer) {
      clearTimeout(debounceTimer);
      debounceTimer = null;
    }
    passiveOptions = null;
  }

  function setupMutationObserver() {
    if (observer) return;

    observer = new MutationObserver(() => {
      // Debounce: wait for DOM to settle before rescanning
      if (debounceTimer) clearTimeout(debounceTimer);

      debounceTimer = setTimeout(() => {
        if (rescanCount < MAX_RESCANS) {
          rescanCount++;
          runPassiveScan();
        }
      }, DEBOUNCE_MS);
    });

    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      characterData: true
    });
  }

  function runPassiveScan() {
    if (!passiveOptions) return;

    const result = scanPage(passiveOptions);
    const signature = computeSignature(result.findings);

    // Only notify if findings changed
    if (signature !== lastScanSignature) {
      const isNew = lastScanSignature !== null;
      lastScanSignature = signature;

      // Send findings to service worker for badge update
      chrome.runtime.sendMessage({
        type: "PASSIVE_SCAN_RESULT",
        result,
        isNewFindings: isNew && result.reflectedParamCount > 0
      }).catch(() => {
        // Tab might be closing, ignore
      });
    }
  }

  function computeSignature(findings) {
    // Create a deterministic signature of findings to detect changes
    if (!findings || !findings.length) return "empty";

    const parts = findings.map(f => {
      const matchSigs = f.matches.map(m => `${m.kind}:${m.subtype || ""}:${m.match}`).sort();
      return `${f.param}=${f.original}:[${matchSigs.join(",")}]`;
    }).sort();

    return parts.join("|");
  }

  // ============================================================
  // MAIN SCAN LOGIC
  // ============================================================

  function scanPage(options) {
    const url = new URL(window.location.href);

    const ignored = new Set((options.ignoreParams || []).map(s => s.toLowerCase()));
    const minLen = Number(options.minLen ?? 4);
    const maxFindingsPerParam = Number(options.maxFindingsPerParam ?? 20);

    // Build candidate list from URL query parameters
    const candidates = [];
    for (const [k, v] of url.searchParams.entries()) {
      if (!k) continue;
      if (ignored.has(k.toLowerCase())) continue;
      if (!v) continue;
      if (v.length < minLen) continue;
      candidates.push({ key: k, value: v, source: "query" });
    }

    // Also extract fragment (#) parameters for DOM XSS detection
    // Supports formats: #foo=bar&baz=qux or #!/path?foo=bar
    const hashParams = parseHashParams(window.location.hash);
    for (const [k, v] of hashParams) {
      if (!k) continue;
      if (ignored.has(k.toLowerCase())) continue;
      if (!v) continue;
      if (v.length < minLen) continue;
      candidates.push({ key: k, value: v, source: "fragment" });
    }

    const findings = [];

    // Collect scan targets based on options
    const html = document.documentElement?.outerHTML || "";
    const inlineScripts = options.scanInlineScripts ? collectInlineScripts() : [];
    const attrsIndex = options.scanAttrs ? collectAttributesIndex() : [];
    const textIndex = options.scanDomText ? collectTextNodesIndex() : [];

    for (const c of candidates) {
      const variants = makeVariants(c.value, options.decodeDepth ?? 1);
      const perParam = [];

      // Scan inline scripts
      if (options.scanInlineScripts && inlineScripts.length) {
        for (const s of inlineScripts) {
          perParam.push(...findInScript(s.content, s.type, variants, c.value));
        }
      }

      // Scan attributes with classification
      if (options.scanAttrs && attrsIndex.length) {
        for (const a of attrsIndex) {
          perParam.push(...findInAttribute(a, variants, c.value));
        }
      }

      // Scan text nodes
      if (options.scanDomText && textIndex.length) {
        for (const t of textIndex) {
          perParam.push(...findInText(t.text, variants, c.value));
        }
      }

      // Scan raw HTML (generic fallback)
      if (options.scanHtml) {
        perParam.push(...findInHtml(html, variants, c.value));
      }

      // De-dupe and limit
      const deduped = dedupeFindings(perParam).slice(0, maxFindingsPerParam);

      if (deduped.length) {
        findings.push({
          param: c.key,
          source: c.source, // "query" or "fragment"
          original: c.value,
          variants,
          matches: deduped
        });
      }
    }

    return {
      url: window.location.href,
      scannedAt: new Date().toISOString(),
      candidateParamCount: candidates.length,
      reflectedParamCount: findings.length,
      findings
    };
  }

  // ============================================================
  // FRAGMENT PARAMETER PARSING
  // ============================================================

  /**
   * Parse parameters from URL fragment/hash.
   * Supports multiple formats common in SPAs:
   *   - #foo=bar&baz=qux (query-string style)
   *   - #!/path?foo=bar (hashbang with query)
   *   - #/path?foo=bar (path with query)
   * Returns array of [key, value] pairs.
   */
  function parseHashParams(hash) {
    if (!hash || hash.length < 2) return [];

    // Remove leading #
    let fragment = hash.slice(1);

    // Handle hashbang: #!/path?params or #!params
    if (fragment.startsWith("!")) {
      fragment = fragment.slice(1);
    }

    // If there's a ? in the fragment, parse everything after it
    const queryIdx = fragment.indexOf("?");
    if (queryIdx !== -1) {
      fragment = fragment.slice(queryIdx + 1);
    } else if (fragment.startsWith("/")) {
      // Path-style fragment without query params, skip
      // Unless it contains = which suggests params
      if (!fragment.includes("=")) return [];
    }

    // Parse as query string
    const params = [];
    try {
      const searchParams = new URLSearchParams(fragment);
      for (const [k, v] of searchParams.entries()) {
        params.push([k, v]);
      }
    } catch {
      // If URLSearchParams fails, try manual parsing
      const pairs = fragment.split("&");
      for (const pair of pairs) {
        const eqIdx = pair.indexOf("=");
        if (eqIdx > 0) {
          const key = decodeURIComponent(pair.slice(0, eqIdx));
          const val = decodeURIComponent(pair.slice(eqIdx + 1));
          params.push([key, val]);
        }
      }
    }

    return params;
  }

  // ============================================================
  // VARIANT GENERATION
  // ============================================================

  function makeVariants(value, decodeDepth) {
    const variants = new Set();
    const trimmed = value.trim();
    variants.add(trimmed);

    // Replace + with space (common in query encoding)
    variants.add(trimmed.replace(/\+/g, " "));

    // URL decoding up to decodeDepth
    let cur = trimmed;
    for (let i = 0; i < Math.max(0, Number(decodeDepth)); i++) {
      try {
        const decoded = decodeURIComponent(cur);
        variants.add(decoded);
        variants.add(decoded.replace(/\+/g, " "));
        cur = decoded;
      } catch {
        break;
      }
    }

    // HTML entity decoding (basic)
    variants.add(htmlDecode(trimmed));

    // Remove very short variants / duplicates
    return [...variants].filter(v => typeof v === "string" && v.length > 0);
  }

  function htmlDecode(str) {
    const el = document.createElement("textarea");
    el.innerHTML = str;
    return el.value;
  }

  // ============================================================
  // ENCODING DETECTION
  // ============================================================

  /**
   * Detect which XSS-relevant characters are reflected raw (unencoded) in the snippet.
   * Returns an object like: { raw: ["<", ">"], encoded: ["\"", "'"] }
   *
   * This helps determine exploitability:
   * - If < and > are raw in HTML context, tag injection may be possible
   * - If " or ' are raw in attribute context, attribute breakout may be possible
   */
  function detectEncoding(originalValue, snippet) {
    const raw = [];
    const encoded = [];

    for (const char of ENCODING_TEST_CHARS) {
      // Check if this char exists in the original value
      if (!originalValue.includes(char)) continue;

      // Check if it appears raw in the snippet
      if (snippet.includes(char)) {
        raw.push(char);
      } else {
        // Check for common encoded forms
        const encodedForms = getEncodedForms(char);
        const isEncoded = encodedForms.some(enc =>
          snippet.toLowerCase().includes(enc.toLowerCase())
        );
        if (isEncoded) {
          encoded.push(char);
        }
        // If neither raw nor encoded found, the char might have been stripped
      }
    }

    return { raw, encoded };
  }

  /**
   * Get common encoded representations of a character.
   */
  function getEncodedForms(char) {
    const forms = {
      "<": ["&lt;", "&#60;", "&#x3c;", "%3C", "\\u003c", "\\x3c"],
      ">": ["&gt;", "&#62;", "&#x3e;", "%3E", "\\u003e", "\\x3e"],
      '"': ["&quot;", "&#34;", "&#x22;", "%22", "\\u0022", "\\x22"],
      "'": ["&#39;", "&#x27;", "%27", "\\u0027", "\\x27", "&apos;"],
      "&": ["&amp;", "&#38;", "&#x26;", "%26"]
    };
    return forms[char] || [];
  }

  // ============================================================
  // CLASSIFICATION HELPERS
  // ============================================================

  /**
   * Classify an attribute and return its subtype and interest level.
   */
  function classifyAttribute(attrName, attrValue) {
    const lower = attrName.toLowerCase();

    if (EVENT_HANDLER_ATTRS.has(lower) || lower.startsWith("on")) {
      return { subtype: "EVENT_HANDLER", interest: INTEREST.HIGH };
    }

    if (URL_ATTRS.has(lower)) {
      if (attrValue && /^\s*javascript:/i.test(attrValue)) {
        return { subtype: "URL_ATTR", interest: INTEREST.HIGH };
      }
      return { subtype: "URL_ATTR", interest: INTEREST.MEDIUM };
    }

    if (STYLE_ATTRS.has(lower)) {
      return { subtype: "STYLE", interest: INTEREST.MEDIUM };
    }

    if (lower.startsWith("data-")) {
      return { subtype: "DATA_ATTR", interest: INTEREST.LOW };
    }

    return { subtype: "OTHER_ATTR", interest: INTEREST.LOW };
  }

  /**
   * Classify script content.
   */
  function classifyScript(scriptType) {
    const lower = (scriptType || "").toLowerCase();

    if (lower.includes("json") || lower.includes("ld+json") || lower.includes("importmap")) {
      return { subtype: "JSON_SCRIPT", interest: INTEREST.MEDIUM };
    }

    return { subtype: "INLINE_SCRIPT", interest: INTEREST.HIGH };
  }

  /**
   * Detect quote context for attribute values.
   */
  function detectQuotedContext(tag, attr, value, matchIdx) {
    try {
      const el = document.querySelector(`${tag}[${attr}]`);
      if (!el) return "unknown";

      const outer = el.outerHTML;
      const attrPattern = new RegExp(`${attr}\\s*=\\s*(['"]?)`, "i");
      const match = outer.match(attrPattern);

      if (match) {
        if (match[1] === '"' || match[1] === "'") return "quoted";
        return "unquoted";
      }
    } catch {
      // Ignore errors
    }

    return "unknown";
  }

  // ============================================================
  // FINDING FUNCTIONS
  // ============================================================

  function findInScript(content, scriptType, variants, originalValue) {
    const out = [];
    if (!content) return out;

    const { subtype, interest } = classifyScript(scriptType);

    for (const v of variants) {
      if (!v || v.length < 2) continue;

      let idx = 0;
      while (true) {
        const found = content.indexOf(v, idx);
        if (found === -1) break;

        const snippet = snippetAround(content, found, v.length);
        const encoding = detectEncoding(originalValue, snippet);

        out.push({
          kind: "SCRIPT",
          subtype,
          interest,
          match: v,
          location: scriptType ? `script[type="${scriptType}"]` : "script",
          snippet,
          encoding
        });

        idx = found + v.length;
        if (out.length > 100) break;
      }
    }

    return out;
  }

  function findInAttribute(attrInfo, variants, originalValue) {
    const out = [];
    const { tag, attr, value } = attrInfo;
    if (!value) return out;

    const { subtype, interest: baseInterest } = classifyAttribute(attr, value);

    for (const v of variants) {
      if (!v || v.length < 2) continue;

      let idx = 0;
      while (true) {
        const found = value.indexOf(v, idx);
        if (found === -1) break;

        const quoteContext = detectQuotedContext(tag, attr, value, found);
        let interest = baseInterest;

        if (quoteContext === "unquoted" && interest !== INTEREST.HIGH) {
          interest = INTEREST.HIGH;
        }

        const snippet = snippetAround(value, found, v.length);
        const encoding = detectEncoding(originalValue, snippet);

        out.push({
          kind: "ATTRIBUTE",
          subtype,
          interest,
          match: v,
          location: `${tag}[${attr}]`,
          snippet,
          quoteContext,
          encoding
        });

        idx = found + v.length;
        if (out.length > 100) break;
      }
    }

    return out;
  }

  function findInText(text, variants, originalValue) {
    const out = [];
    if (!text) return out;

    for (const v of variants) {
      if (!v || v.length < 2) continue;

      let idx = 0;
      while (true) {
        const found = text.indexOf(v, idx);
        if (found === -1) break;

        const snippet = snippetAround(text, found, v.length);
        const encoding = detectEncoding(originalValue, snippet);

        out.push({
          kind: "TEXT",
          subtype: null,
          interest: INTEREST.LOW,
          match: v,
          location: null,
          snippet,
          encoding
        });

        idx = found + v.length;
        if (out.length > 100) break;
      }
    }

    return out;
  }

  function findInHtml(html, variants, originalValue) {
    const out = [];
    if (!html) return out;

    for (const v of variants) {
      if (!v || v.length < 2) continue;

      let idx = 0;
      while (true) {
        const found = html.indexOf(v, idx);
        if (found === -1) break;

        const context = detectHtmlContext(html, found);
        const snippet = snippetAround(html, found, v.length);
        const encoding = detectEncoding(originalValue, snippet);

        out.push({
          kind: "HTML",
          subtype: context.subtype,
          interest: context.interest,
          match: v,
          location: context.location,
          snippet,
          encoding
        });

        idx = found + v.length;
        if (out.length > 200) break;
      }
    }

    return out;
  }

  /**
   * Analyze raw HTML position to determine context.
   */
  function detectHtmlContext(html, position) {
    let tagStart = -1;
    for (let i = position - 1; i >= 0 && i > position - 500; i--) {
      if (html[i] === "<") {
        tagStart = i;
        break;
      }
      if (html[i] === ">") break;
    }

    if (tagStart === -1) {
      return { subtype: "BETWEEN_TAGS", interest: INTEREST.LOW, location: null };
    }

    const tagContent = html.slice(tagStart, position);
    const attrMatch = tagContent.match(/(\w+)\s*=\s*(['"])[^'"]*$/);

    if (attrMatch) {
      const attrName = attrMatch[1].toLowerCase();
      if (EVENT_HANDLER_ATTRS.has(attrName) || attrName.startsWith("on")) {
        return { subtype: "IN_EVENT_HANDLER", interest: INTEREST.HIGH, location: attrName };
      }
      if (URL_ATTRS.has(attrName)) {
        return { subtype: "IN_URL_ATTR", interest: INTEREST.MEDIUM, location: attrName };
      }
      return { subtype: "IN_ATTR_VALUE", interest: INTEREST.LOW, location: attrName };
    }

    return { subtype: "IN_TAG", interest: INTEREST.MEDIUM, location: null };
  }

  // ============================================================
  // COLLECTION HELPERS
  // ============================================================

  function collectInlineScripts() {
    const scripts = [...document.querySelectorAll("script")];
    const inline = [];
    for (const s of scripts) {
      if (!s.src && s.textContent) {
        inline.push({
          content: s.textContent,
          type: s.type || ""
        });
      }
      if (inline.length > 100) break;
    }
    return inline;
  }

  function collectAttributesIndex() {
    const els = [...document.querySelectorAll("*")];
    const attrs = [];
    for (const el of els) {
      for (const attr of el.getAttributeNames()) {
        const val = el.getAttribute(attr);
        if (val && val.length) {
          attrs.push({
            tag: el.tagName.toLowerCase(),
            attr,
            value: val
          });
        }
        if (attrs.length > 5000) return attrs;
      }
    }
    return attrs;
  }

  function collectTextNodesIndex() {
    const walker = document.createTreeWalker(
      document.body || document.documentElement,
      NodeFilter.SHOW_TEXT
    );
    const nodes = [];
    let n;
    while ((n = walker.nextNode())) {
      const txt = n.nodeValue;
      if (txt && txt.trim().length) {
        nodes.push({ text: txt });
      }
      if (nodes.length > 5000) break;
    }
    return nodes;
  }

  // ============================================================
  // UTILITY FUNCTIONS
  // ============================================================

  function snippetAround(text, startIdx, matchLen) {
    const left = Math.max(0, startIdx - 40);
    const right = Math.min(text.length, startIdx + matchLen + 40);
    const snippet = text.slice(left, right);
    return (left > 0 ? "..." : "") + snippet + (right < text.length ? "..." : "");
  }

  function dedupeFindings(items) {
    const seen = new Set();
    const out = [];
    for (const it of items) {
      const key = `${it.kind}|${it.subtype || ""}|${it.location || ""}|${it.match}|${it.snippet}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(it);
    }
    return out;
  }
})();
