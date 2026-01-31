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
  // SINK REGISTRY (PortSwigger-derived canonical list)
  // ============================================================

  const SINK_REGISTRY = {
    // DOM XSS - HTML/Markup injection
    "innerHTML": { category: "DOM-XSS", severity: "high", context: "html", notes: "Direct HTML injection" },
    "outerHTML": { category: "DOM-XSS", severity: "high", context: "html", notes: "Direct HTML injection" },
    "insertAdjacentHTML": { category: "DOM-XSS", severity: "high", context: "html", notes: "HTML injection via position" },
    "document.write": { category: "DOM-XSS", severity: "high", context: "html", notes: "Document-level HTML injection" },
    "document.writeln": { category: "DOM-XSS", severity: "high", context: "html", notes: "Document-level HTML injection" },

    // DOM XSS - Code execution
    "eval": { category: "DOM-XSS", severity: "critical", context: "js", notes: "Direct code execution" },
    "Function": { category: "DOM-XSS", severity: "critical", context: "js", notes: "Dynamic function creation" },
    "setTimeout": { category: "DOM-XSS", severity: "high", context: "js", notes: "Delayed code execution (string arg)" },
    "setInterval": { category: "DOM-XSS", severity: "high", context: "js", notes: "Repeated code execution (string arg)" },
    "execScript": { category: "DOM-XSS", severity: "critical", context: "js", notes: "Legacy IE code execution" },

    // Open Redirect / URL manipulation
    "location": { category: "Open-Redirect", severity: "medium", context: "url", notes: "Location object assignment" },
    "location.href": { category: "Open-Redirect", severity: "medium", context: "url", notes: "URL navigation" },
    "location.assign": { category: "Open-Redirect", severity: "medium", context: "url", notes: "URL navigation method" },
    "location.replace": { category: "Open-Redirect", severity: "medium", context: "url", notes: "URL navigation (no history)" },
    "window.open": { category: "Open-Redirect", severity: "medium", context: "url", notes: "New window/tab navigation" },

    // Attribute sinks (context-dependent)
    "setAttribute": { category: "DOM-XSS", severity: "medium", context: "attr", notes: "Attribute injection - severity depends on attr name" },
    "setAttributeNS": { category: "DOM-XSS", severity: "medium", context: "attr", notes: "Namespaced attribute injection" },

    // Request manipulation
    "XMLHttpRequest.open": { category: "Request-Forgery", severity: "medium", context: "url", notes: "XHR URL manipulation" },
    "XMLHttpRequest.setRequestHeader": { category: "Header-Injection", severity: "medium", context: "header", notes: "XHR header injection" },
    "fetch": { category: "Request-Forgery", severity: "medium", context: "url", notes: "Fetch URL manipulation" },
    "WebSocket": { category: "WebSocket-Hijack", severity: "medium", context: "url", notes: "WebSocket URL poisoning" },

    // Data parsing
    "JSON.parse": { category: "JSON-Injection", severity: "low", context: "json", notes: "JSON parsing - may enable prototype pollution" },
    "document.evaluate": { category: "XPath-Injection", severity: "medium", context: "xpath", notes: "XPath query injection" },

    // History manipulation
    "history.pushState": { category: "History-Manipulation", severity: "low", context: "url", notes: "History state injection" },
    "history.replaceState": { category: "History-Manipulation", severity: "low", context: "url", notes: "History state replacement" },

    // jQuery sinks (common library)
    "$.html": { category: "DOM-XSS", severity: "high", context: "html", notes: "jQuery HTML injection" },
    "$.append": { category: "DOM-XSS", severity: "high", context: "html", notes: "jQuery append HTML" },
    "$.prepend": { category: "DOM-XSS", severity: "high", context: "html", notes: "jQuery prepend HTML" },
    "$.after": { category: "DOM-XSS", severity: "high", context: "html", notes: "jQuery after HTML" },
    "$.before": { category: "DOM-XSS", severity: "high", context: "html", notes: "jQuery before HTML" },
    "$.replaceWith": { category: "DOM-XSS", severity: "high", context: "html", notes: "jQuery replace HTML" },
    "$.parseHTML": { category: "DOM-XSS", severity: "high", context: "html", notes: "jQuery HTML parsing" },
    "$.globalEval": { category: "DOM-XSS", severity: "critical", context: "js", notes: "jQuery global eval" },
    "$.ajax": { category: "Request-Forgery", severity: "medium", context: "url", notes: "jQuery AJAX request" },

    // Selector injection sinks
    "$.selector": { category: "Selector-Injection", severity: "medium", context: "selector", notes: "jQuery $() with user-controlled selector" },
    "jQuery.selector": { category: "Selector-Injection", severity: "medium", context: "selector", notes: "jQuery() with user-controlled selector" },
    "$.find": { category: "Selector-Injection", severity: "medium", context: "selector", notes: "jQuery find() with user-controlled selector" },
    "$.filter": { category: "Selector-Injection", severity: "medium", context: "selector", notes: "jQuery filter() with user-controlled selector" },
    "$.is": { category: "Selector-Injection", severity: "low", context: "selector", notes: "jQuery is() with user-controlled selector" },
    "$.has": { category: "Selector-Injection", severity: "low", context: "selector", notes: "jQuery has() with user-controlled selector" },
    "$.closest": { category: "Selector-Injection", severity: "low", context: "selector", notes: "jQuery closest() with user-controlled selector" },
    "$.not": { category: "Selector-Injection", severity: "low", context: "selector", notes: "jQuery not() with user-controlled selector" },
    "document.querySelector": { category: "Selector-Injection", severity: "medium", context: "selector", notes: "querySelector with user-controlled selector" },
    "document.querySelectorAll": { category: "Selector-Injection", severity: "medium", context: "selector", notes: "querySelectorAll with user-controlled selector" }
  };

  // High-risk attribute names that elevate setAttribute severity
  const HIGH_RISK_ATTRS = new Set([
    "href", "src", "action", "formaction", "data", "srcdoc", "style",
    ...Array.from(EVENT_HANDLER_ATTRS)
  ]);

  // ============================================================
  // SOURCE REGISTRY (attacker-controlled inputs)
  // ============================================================

  const SOURCE_TYPES = {
    QUERY_PARAM: "query",
    FRAGMENT: "fragment",
    PATH: "path",
    REFERRER: "referrer",
    COOKIE: "cookie",
    STORAGE: "storage",
    MESSAGE: "message",
    WINDOW_NAME: "window.name",
    DOCUMENT_URL: "document.url"
  };

  // ============================================================
  // TAINT TRACKING STATE
  // ============================================================

  // Collected sources for correlation
  let collectedSources = [];
  let taintFindings = [];
  let sinkInstrumentationEnabled = false;
  const MIN_TOKEN_LENGTH = 6; // Minimum length for substring matches

  // Patterns that suggest value flows to a dangerous sink (regex patterns)
  const SINK_PROXIMITY_PATTERNS = [
    // innerHTML/outerHTML assignments
    { pattern: /\.innerHTML\s*[=+]/, sinkType: "innerHTML", confidence: "high" },
    { pattern: /\.outerHTML\s*[=+]/, sinkType: "outerHTML", confidence: "high" },
    // document.write
    { pattern: /document\.write(ln)?\s*\(/, sinkType: "document.write", confidence: "high" },
    // eval and similar
    { pattern: /\beval\s*\(/, sinkType: "eval", confidence: "high" },
    { pattern: /\bFunction\s*\(/, sinkType: "Function", confidence: "high" },
    { pattern: /setTimeout\s*\(\s*['"`]/, sinkType: "setTimeout-string", confidence: "high" },
    { pattern: /setInterval\s*\(\s*['"`]/, sinkType: "setInterval-string", confidence: "high" },
    // Location manipulation (writes only — exclude object property assignments like e.location=)
    { pattern: /(?:^|[;\s{(,!])location\s*=\s*[^=]/, sinkType: "location", confidence: "medium" },
    { pattern: /(?:window|document|self)\.location\s*=\s*[^=]/, sinkType: "location", confidence: "medium" },
    { pattern: /location\.href\s*=\s*[^=]/, sinkType: "location.href", confidence: "medium" },
    { pattern: /(?:window\.)?location\.assign\s*\(/, sinkType: "location.assign", confidence: "medium" },
    { pattern: /(?:window\.)?location\.replace\s*\(/, sinkType: "location.replace", confidence: "medium" },
    { pattern: /\.href\s*=\s*[^=]/, sinkType: "href-assignment", confidence: "medium" },
    { pattern: /\.src\s*=\s*[^=]/, sinkType: "src-assignment", confidence: "medium" },
    // jQuery-style HTML insertion
    { pattern: /\$\([^)]*\)\.html\s*\(/, sinkType: "jQuery.html", confidence: "medium" },
    { pattern: /\$\([^)]*\)\.append\s*\(/, sinkType: "jQuery.append", confidence: "medium" },
    // insertAdjacentHTML
    { pattern: /insertAdjacentHTML\s*\(/, sinkType: "insertAdjacentHTML", confidence: "high" }
  ];

  // ============================================================
  // RISKY SELECTOR PATTERNS (Selector Injection detection)
  // ============================================================

  /**
   * Patterns in CSS/jQuery selectors that indicate exploitability when
   * user-controlled input flows into them.
   *
   * jQuery-specific pseudo-selectors like :contains(), :has() (jQuery's version),
   * :eq(), :lt(), :gt() can leak DOM content or probe structure.
   * Attribute selectors with user input can probe for attribute values.
   * Raw HTML-like strings in $() create elements (XSS via selector).
   */
  const RISKY_SELECTOR_PATTERNS = [
    // jQuery HTML creation via $("<tag>") - escalates to DOM-XSS
    { pattern: /^\s*</, risk: "critical", id: "html-creation", notes: "jQuery $() with HTML string creates DOM elements (XSS)" },
    // jQuery :contains() can exfiltrate page text content via CSS injection / timing
    { pattern: /:contains\s*\(/i, risk: "high", id: "contains", notes: ":contains() can leak page text content" },
    // :has() (jQuery pseudo) can probe DOM structure
    { pattern: /:has\s*\(/i, risk: "medium", id: "has-pseudo", notes: ":has() can probe DOM structure" },
    // Positional pseudos (:eq, :lt, :gt, :first, :last, :even, :odd)
    { pattern: /:eq\s*\(/i, risk: "low", id: "eq", notes: ":eq() positional selector" },
    { pattern: /:lt\s*\(/i, risk: "low", id: "lt", notes: ":lt() positional selector" },
    { pattern: /:gt\s*\(/i, risk: "low", id: "gt", notes: ":gt() positional selector" },
    { pattern: /:nth/, risk: "low", id: "nth", notes: ":nth-*() positional selector" },
    // Attribute selectors with user-controlled values
    { pattern: /\[\s*\w+\s*[\^$*|~]?=/, risk: "medium", id: "attr-selector", notes: "Attribute selector can probe attribute values" },
    // Unescaped quotes/brackets that could break out of selector context
    { pattern: /['"]/, risk: "medium", id: "unescaped-quotes", notes: "Unescaped quotes in selector may break context" },
    // Expression/script pseudo (very old jQuery / IE)
    { pattern: /:expression\s*\(/i, risk: "critical", id: "expression", notes: ":expression() executes code (legacy IE)" }
  ];

  // ============================================================
  // SOURCE CODE REFERENCE PATTERNS (for code-flow analysis)
  // ============================================================

  /**
   * Regex patterns that match JS code references to attacker-controlled sources.
   * Used by analyzeScriptForCodeFlows() to detect source-to-sink patterns
   * where the source is referenced programmatically (e.g., window.location.hash)
   * rather than containing a literal runtime value.
   */
  const SOURCE_CODE_PATTERNS = [
    // URL / Location sources
    { pattern: /location\.hash/g, sourceType: SOURCE_TYPES.FRAGMENT, sourceKey: "location.hash", notes: "Fragment/hash value" },
    { pattern: /location\.search/g, sourceType: SOURCE_TYPES.QUERY_PARAM, sourceKey: "location.search", notes: "Query string" },
    { pattern: /location\.href/g, sourceType: SOURCE_TYPES.DOCUMENT_URL, sourceKey: "location.href", notes: "Full URL" },
    { pattern: /location\.pathname/g, sourceType: SOURCE_TYPES.PATH, sourceKey: "location.pathname", notes: "URL path" },
    { pattern: /document\.URL/g, sourceType: SOURCE_TYPES.DOCUMENT_URL, sourceKey: "document.URL", notes: "Document URL" },
    { pattern: /document\.documentURI/g, sourceType: SOURCE_TYPES.DOCUMENT_URL, sourceKey: "document.documentURI", notes: "Document URI" },
    { pattern: /document\.baseURI/g, sourceType: SOURCE_TYPES.DOCUMENT_URL, sourceKey: "document.baseURI", notes: "Base URI" },
    { pattern: /document\.referrer/g, sourceType: SOURCE_TYPES.REFERRER, sourceKey: "document.referrer", notes: "Referrer URL" },
    { pattern: /document\.cookie/g, sourceType: SOURCE_TYPES.COOKIE, sourceKey: "document.cookie", notes: "Cookie string" },
    { pattern: /window\.name/g, sourceType: SOURCE_TYPES.WINDOW_NAME, sourceKey: "window.name", notes: "Window name" },
    // URLSearchParams from location
    { pattern: /new\s+URLSearchParams\s*\(\s*(?:location\.search|window\.location\.search|location\.hash)/g, sourceType: SOURCE_TYPES.QUERY_PARAM, sourceKey: "URLSearchParams(location)", notes: "Parsed URL params" },
    { pattern: /\.searchParams\.get\s*\(/g, sourceType: SOURCE_TYPES.QUERY_PARAM, sourceKey: "searchParams.get()", notes: "URL search param" },
    // postMessage
    { pattern: /(?:event|e|evt|msg)\.data/g, sourceType: SOURCE_TYPES.MESSAGE, sourceKey: "message.data", notes: "postMessage data" },
    // Storage
    { pattern: /localStorage\.getItem\s*\(/g, sourceType: SOURCE_TYPES.STORAGE, sourceKey: "localStorage.getItem()", notes: "localStorage read" },
    { pattern: /sessionStorage\.getItem\s*\(/g, sourceType: SOURCE_TYPES.STORAGE, sourceKey: "sessionStorage.getItem()", notes: "sessionStorage read" },
    // decodeURIComponent wrapping a source (common pattern)
    { pattern: /decodeURIComponent\s*\(\s*(?:location\.hash|location\.search|window\.location\.hash|window\.location\.search)/g, sourceType: SOURCE_TYPES.FRAGMENT, sourceKey: "decodeURIComponent(location)", notes: "Decoded URL component" }
  ];

  /**
   * Sink code patterns for code-flow analysis.
   * These match sink calls/assignments in JS code. Each entry has a regex
   * and metadata about the sink.
   */
  const SINK_CODE_PATTERNS = [
    // DOM XSS sinks
    { pattern: /\.innerHTML\s*[=+]/, sinkName: "innerHTML", category: "DOM-XSS", severity: "high" },
    { pattern: /\.outerHTML\s*[=+]/, sinkName: "outerHTML", category: "DOM-XSS", severity: "high" },
    { pattern: /document\.write(ln)?\s*\(/, sinkName: "document.write", category: "DOM-XSS", severity: "high" },
    { pattern: /\beval\s*\(/, sinkName: "eval", category: "DOM-XSS", severity: "critical" },
    { pattern: /\bFunction\s*\(/, sinkName: "Function", category: "DOM-XSS", severity: "critical" },
    { pattern: /insertAdjacentHTML\s*\(/, sinkName: "insertAdjacentHTML", category: "DOM-XSS", severity: "high" },
    // jQuery HTML sinks
    { pattern: /\)\.html\s*\(/, sinkName: "$.html", category: "DOM-XSS", severity: "high" },
    { pattern: /\)\.append\s*\(/, sinkName: "$.append", category: "DOM-XSS", severity: "high" },
    { pattern: /\)\.prepend\s*\(/, sinkName: "$.prepend", category: "DOM-XSS", severity: "high" },
    // Open redirect sinks
    // Use negative lookbehind to exclude object property assignments like e.location=, this.location=, t.location=
    // Only match bare `location =` or `window.location =` or `document.location =` or `self.location =`
    { pattern: /(?:^|[;\s{(,!])location\s*=\s*/, sinkName: "location", category: "Open-Redirect", severity: "medium" },
    { pattern: /(?:window|document|self)\.location\s*=\s*/, sinkName: "location", category: "Open-Redirect", severity: "medium" },
    { pattern: /(?:window\.)?location\.assign\s*\(/, sinkName: "location.assign", category: "Open-Redirect", severity: "medium" },
    { pattern: /(?:window\.)?location\.replace\s*\(/, sinkName: "location.replace", category: "Open-Redirect", severity: "medium" },
    { pattern: /window\.open\s*\(/, sinkName: "window.open", category: "Open-Redirect", severity: "medium" },
    // Selector injection sinks
    { pattern: /\$\(\s*['"`]?[^)]*:contains\s*\(/, sinkName: "$.selector:contains", category: "Selector-Injection", severity: "high", selectorRisk: "contains" },
    { pattern: /\$\(\s*['"`]?[^)]*:has\s*\(/, sinkName: "$.selector:has", category: "Selector-Injection", severity: "medium", selectorRisk: "has-pseudo" },
    { pattern: /\$\(\s*[^)]*\+/, sinkName: "$.selector", category: "Selector-Injection", severity: "medium", selectorRisk: "concatenation" },
    { pattern: /jQuery\(\s*[^)]*\+/, sinkName: "jQuery.selector", category: "Selector-Injection", severity: "medium", selectorRisk: "concatenation" },
    { pattern: /\.find\(\s*[^)]*\+/, sinkName: "$.find", category: "Selector-Injection", severity: "medium", selectorRisk: "concatenation" },
    { pattern: /\.filter\(\s*[^)]*\+/, sinkName: "$.filter", category: "Selector-Injection", severity: "medium", selectorRisk: "concatenation" },
    { pattern: /querySelector\(\s*[^)]*\+/, sinkName: "document.querySelector", category: "Selector-Injection", severity: "medium", selectorRisk: "concatenation" },
    { pattern: /querySelectorAll\(\s*[^)]*\+/, sinkName: "document.querySelectorAll", category: "Selector-Injection", severity: "medium", selectorRisk: "concatenation" }
  ];

  // Static selector patterns for inline script analysis
  const SELECTOR_SINK_PATTERNS = [
    { pattern: /\$\(\s*['"`]?\s*[^)]*/, sinkType: "$.selector", confidence: "medium" },
    { pattern: /jQuery\(\s*['"`]?\s*[^)]*/, sinkType: "jQuery.selector", confidence: "medium" },
    { pattern: /\.find\(\s*['"`]/, sinkType: "$.find", confidence: "medium" },
    { pattern: /\.filter\(\s*['"`]/, sinkType: "$.filter", confidence: "medium" },
    { pattern: /\.is\(\s*['"`]/, sinkType: "$.is", confidence: "low" },
    { pattern: /\.has\(\s*['"`]/, sinkType: "$.has", confidence: "low" },
    { pattern: /\.closest\(\s*['"`]/, sinkType: "$.closest", confidence: "low" },
    { pattern: /\.not\(\s*['"`]/, sinkType: "$.not", confidence: "low" },
    { pattern: /querySelector\(\s*['"`]/, sinkType: "document.querySelector", confidence: "medium" },
    { pattern: /querySelectorAll\(\s*['"`]/, sinkType: "document.querySelectorAll", confidence: "medium" }
  ];

  // ============================================================
  // SOURCE COLLECTION (SourceTagger)
  // ============================================================

  /**
   * Collect all potential attacker-controlled sources from the current page.
   * Each source has: type, key (param name, cookie name, etc.), value, raw, normalized
   */
  function collectSources(options) {
    const sources = [];
    const minLen = options?.minLen ?? 4;
    const decodeDepth = options?.decodeDepth ?? 1;
    const ignored = new Set((options?.ignoreParams || []).map(s => s.toLowerCase()));

    // Query parameters
    const url = new URL(window.location.href);
    for (const [k, v] of url.searchParams.entries()) {
      if (!k || !v || v.length < minLen) continue;
      if (ignored.has(k.toLowerCase())) continue;
      sources.push(createSource(SOURCE_TYPES.QUERY_PARAM, k, v, decodeDepth));
    }

    // Fragment parameters
    const hashParams = parseHashParams(window.location.hash);
    for (const [k, v] of hashParams) {
      if (!k || !v || v.length < minLen) continue;
      if (ignored.has(k.toLowerCase())) continue;
      sources.push(createSource(SOURCE_TYPES.FRAGMENT, k, v, decodeDepth));
    }

    // Path segments (only if they look like user-supplied values, not route parts)
    // Path segments are high-FP sources: common words like "post", "search", "page"
    // appear as coincidental substrings in script code constantly.
    // Only include segments that are long enough and look like actual values.
    const PATH_MIN_LEN = 8; // Stricter minimum for path segments
    const COMMON_ROUTE_WORDS = new Set([
      "api", "static", "assets", "images", "js", "css", "fonts", "media",
      "resources", "public", "dist", "build", "lib", "vendor", "node_modules",
      "post", "posts", "page", "pages", "blog", "home", "index", "login",
      "logout", "signup", "register", "admin", "dashboard", "settings",
      "profile", "user", "users", "account", "search", "help", "about",
      "contact", "terms", "privacy", "error", "404", "500", "new", "edit",
      "delete", "create", "update", "view", "list", "detail", "item",
      "category", "categories", "tag", "tags", "comment", "comments",
      "image", "file", "files", "upload", "download", "data", "json",
      "xml", "html", "feed", "rss", "sitemap", "robots", "favicon"
    ]);
    const pathParts = url.pathname.split("/").filter(p => p && p.length >= PATH_MIN_LEN);
    for (let i = 0; i < pathParts.length; i++) {
      const p = pathParts[i];
      // Skip common route words and version patterns
      if (COMMON_ROUTE_WORDS.has(p.toLowerCase())) continue;
      if (/^v\d+$/i.test(p)) continue;
      // Skip segments that look like purely numeric IDs (not interesting as reflected values)
      if (/^\d+$/.test(p)) continue;
      sources.push(createSource(SOURCE_TYPES.PATH, `path[${i}]`, p, decodeDepth));
    }

    // Document referrer
    if (document.referrer && document.referrer.length >= minLen) {
      try {
        const refUrl = new URL(document.referrer);
        // Extract referrer query params as potential sources
        for (const [k, v] of refUrl.searchParams.entries()) {
          if (v && v.length >= minLen) {
            sources.push(createSource(SOURCE_TYPES.REFERRER, `referrer:${k}`, v, decodeDepth));
          }
        }
      } catch {
        // Invalid referrer URL
      }
    }

    // Document URL / baseURI
    // Mark as runtimeOnly — useful for runtime sink correlation (e.g., location.href = document.URL)
    // but not for static script analysis (URL substrings match too many code identifiers)
    const docUrlSource = createSource(SOURCE_TYPES.DOCUMENT_URL, "document.URL", document.URL, decodeDepth);
    docUrlSource.runtimeOnly = true;
    sources.push(docUrlSource);

    // Window name (classic DOM XSS vector)
    if (window.name && window.name.length >= minLen) {
      sources.push(createSource(SOURCE_TYPES.WINDOW_NAME, "window.name", window.name, decodeDepth));
    }

    // Cookies (with key attribution)
    try {
      const cookies = document.cookie.split(";");
      for (const c of cookies) {
        const [name, ...valueParts] = c.split("=");
        const value = valueParts.join("=").trim();
        if (name && value && value.length >= minLen) {
          sources.push(createSource(SOURCE_TYPES.COOKIE, name.trim(), value, decodeDepth));
        }
      }
    } catch {
      // Cookie access may be restricted
    }

    // LocalStorage
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        const value = localStorage.getItem(key);
        if (value && value.length >= minLen) {
          sources.push(createSource(SOURCE_TYPES.STORAGE, `localStorage:${key}`, value, decodeDepth));
        }
      }
    } catch {
      // Storage access may be restricted
    }

    // SessionStorage
    try {
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        const value = sessionStorage.getItem(key);
        if (value && value.length >= minLen) {
          sources.push(createSource(SOURCE_TYPES.STORAGE, `sessionStorage:${key}`, value, decodeDepth));
        }
      }
    } catch {
      // Storage access may be restricted
    }

    return sources;
  }

  /**
   * Create a source entry with normalized variants.
   */
  function createSource(type, key, rawValue, decodeDepth) {
    const variants = makeVariants(rawValue, decodeDepth);
    return {
      type,
      key,
      raw: rawValue,
      normalized: variants[0] || rawValue,
      variants,
      tokens: tokenize(rawValue)
    };
  }

  /**
   * Tokenize a value for partial matching.
   */
  function tokenize(value) {
    if (!value || typeof value !== "string") return [];
    // Split on common delimiters
    return value.split(/[\s\-_=&?#/\\:;,."'`<>[\]{}()|+*]+/)
      .filter(t => t.length >= MIN_TOKEN_LENGTH);
  }

  // ============================================================
  // TAINT CORRELATION
  // ============================================================

  /**
   * Check if a sink value correlates with any known source.
   * Returns correlation result with confidence.
   */
  function correlateTaint(sinkValue, sources) {
    if (!sinkValue || typeof sinkValue !== "string") return null;
    if (sinkValue.length < MIN_TOKEN_LENGTH) return null;

    const sinkNormalized = sinkValue.toLowerCase().trim();
    const sinkTokens = tokenize(sinkValue);

    let bestMatch = null;

    for (const src of sources) {
      // Exact match (highest confidence)
      if (src.raw === sinkValue || src.normalized === sinkNormalized) {
        return {
          confidence: "high",
          source: src,
          matchType: "exact",
          evidence: `Exact match: "${sinkValue}"`
        };
      }

      // Check variants
      for (const v of src.variants) {
        if (v === sinkValue || v.toLowerCase() === sinkNormalized) {
          return {
            confidence: "high",
            source: src,
            matchType: "variant",
            evidence: `Variant match: "${v}"`
          };
        }
      }

      // Substring match (with length check)
      if (src.raw.length >= MIN_TOKEN_LENGTH && sinkValue.includes(src.raw)) {
        if (!bestMatch || bestMatch.confidence !== "high") {
          bestMatch = {
            confidence: "medium",
            source: src,
            matchType: "substring",
            evidence: `Substring match: source in sink`
          };
        }
      }

      if (sinkValue.length >= MIN_TOKEN_LENGTH && src.raw.includes(sinkValue)) {
        if (!bestMatch || bestMatch.confidence !== "high") {
          bestMatch = {
            confidence: "medium",
            source: src,
            matchType: "substring",
            evidence: `Substring match: sink in source`
          };
        }
      }

      // Token match
      for (const srcToken of src.tokens) {
        for (const sinkToken of sinkTokens) {
          if (srcToken.toLowerCase() === sinkToken.toLowerCase()) {
            if (!bestMatch) {
              bestMatch = {
                confidence: "low",
                source: src,
                matchType: "token",
                evidence: `Token match: "${srcToken}"`
              };
            }
          }
        }
      }
    }

    return bestMatch;
  }

  // Source types that are generally NOT attacker-controlled on first-party sites.
  // Cookies (SID, APISID) and localStorage/sessionStorage are set by the app itself.
  // Downgrade confidence for these since they produce high FP rates on complex apps.
  const LOW_CONTROL_SOURCE_TYPES = new Set([
    SOURCE_TYPES.COOKIE,
    SOURCE_TYPES.STORAGE
  ]);

  /**
   * Record a taint finding when source flows to sink.
   */
  function recordTaintFinding(sinkName, sinkValue, correlation, context) {
    if (!correlation) return;

    // Downgrade confidence for sources that are typically not attacker-controlled
    // (first-party cookies, app-internal localStorage/sessionStorage)
    let effectiveConfidence = correlation.confidence;
    if (LOW_CONTROL_SOURCE_TYPES.has(correlation.source.type)) {
      if (effectiveConfidence === "high") effectiveConfidence = "medium";
      else if (effectiveConfidence === "medium") effectiveConfidence = "low";
    }

    const sinkInfo = SINK_REGISTRY[sinkName] || {
      category: "Unknown",
      severity: "low",
      context: "unknown"
    };

    const finding = {
      findingType: sinkInfo.category,
      source: {
        type: correlation.source.type,
        key: correlation.source.key,
        value: truncateEvidence(correlation.source.raw)
      },
      sink: {
        name: sinkName,
        category: sinkInfo.category,
        severity: sinkInfo.severity,
        context: sinkInfo.context,
        value: truncateEvidence(sinkValue)
      },
      confidence: effectiveConfidence,
      matchType: correlation.matchType,
      evidence: correlation.evidence,
      domPath: context?.domPath || null,
      timestamp: new Date().toISOString(),
      pageUrl: window.location.href,
      triageHints: generateTriageHints(sinkInfo, correlation)
    };

    // Deduplicate by source+sink+value
    const dedupKey = `${correlation.source.key}|${sinkName}|${sinkValue.slice(0, 50)}`;
    if (!taintFindings.some(f =>
      f.source.key === finding.source.key &&
      f.sink.name === finding.sink.name &&
      f.sink.value === finding.sink.value
    )) {
      taintFindings.push(finding);
    }
  }

  /**
   * Generate triage hints based on sink type.
   */
  function generateTriageHints(sinkInfo, correlation) {
    const hints = [];

    if (sinkInfo.category === "DOM-XSS") {
      hints.push("Check if value is HTML-escaped for this context");
      if (sinkInfo.context === "html") {
        hints.push("Test with unique marker containing < > characters");
      }
      if (sinkInfo.context === "js") {
        hints.push("Test if JS string escaping is applied");
      }
    }

    if (sinkInfo.category === "Open-Redirect") {
      hints.push("Check if URL scheme is restricted (javascript:, data:)");
      hints.push("Test with external URL to confirm redirect");
    }

    if (sinkInfo.category === "Selector-Injection") {
      hints.push("Check if user input flows into CSS/jQuery selector argument");
      hints.push("Test with :contains('secret') to check data exfiltration");
      if (sinkInfo.context === "selector") {
        hints.push("Try attribute selectors like [value^='a'] for character extraction");
      }
    }

    if (correlation.source.type === SOURCE_TYPES.FRAGMENT) {
      hints.push("Fragment-based source: likely client-side only (DOM XSS)");
    }

    if (correlation.confidence === "low") {
      hints.push("Low confidence match - verify source-sink relationship manually");
    }

    return hints;
  }

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
  // SINK INSTRUMENTATION (Runtime monitoring)
  // ============================================================

  /**
   * Install sink instrumentation to observe dangerous operations.
   * This wraps native APIs to detect when tainted data flows to sinks.
   */
  function installSinkInstrumentation(sources) {
    if (sinkInstrumentationEnabled) return;
    sinkInstrumentationEnabled = true;
    collectedSources = sources;

    try {
      // Wrap innerHTML/outerHTML
      instrumentProperty(Element.prototype, "innerHTML", "innerHTML");
      instrumentProperty(Element.prototype, "outerHTML", "outerHTML");

      // Wrap document.write/writeln
      instrumentMethod(Document.prototype, "write", "document.write");
      instrumentMethod(Document.prototype, "writeln", "document.writeln");

      // Wrap setAttribute
      instrumentSetAttribute();

      // Wrap eval (window.eval)
      instrumentMethod(window, "eval", "eval");

      // Wrap setTimeout/setInterval (string argument only)
      instrumentTimerMethod("setTimeout");
      instrumentTimerMethod("setInterval");

      // Wrap location assignments
      instrumentLocationSinks();

      // Wrap insertAdjacentHTML
      instrumentMethod(Element.prototype, "insertAdjacentHTML", "insertAdjacentHTML", 1);

      // querySelector / querySelectorAll instrumentation
      instrumentQuerySelector();

      // jQuery instrumentation (if available)
      if (typeof jQuery !== "undefined" || typeof $ !== "undefined") {
        instrumentJQuery();
      }

    } catch (err) {
      console.debug("[Reflex] Sink instrumentation error:", err.message);
    }
  }

  /**
   * Instrument document.querySelector and document.querySelectorAll
   * to detect selector injection.
   */
  function instrumentQuerySelector() {
    const originalQS = Document.prototype.querySelector;
    const originalQSA = Document.prototype.querySelectorAll;
    const originalElemQS = Element.prototype.querySelector;
    const originalElemQSA = Element.prototype.querySelectorAll;

    if (typeof originalQS === "function") {
      Document.prototype.querySelector = function(selector) {
        if (typeof selector === "string") {
          checkSelectorValue("document.querySelector", selector, null);
        }
        return originalQS.call(this, selector);
      };
    }

    if (typeof originalQSA === "function") {
      Document.prototype.querySelectorAll = function(selector) {
        if (typeof selector === "string") {
          checkSelectorValue("document.querySelectorAll", selector, null);
        }
        return originalQSA.call(this, selector);
      };
    }

    // Also wrap Element versions
    if (typeof originalElemQS === "function") {
      Element.prototype.querySelector = function(selector) {
        if (typeof selector === "string") {
          checkSelectorValue("document.querySelector", selector, this);
        }
        return originalElemQS.call(this, selector);
      };
    }

    if (typeof originalElemQSA === "function") {
      Element.prototype.querySelectorAll = function(selector) {
        if (typeof selector === "string") {
          checkSelectorValue("document.querySelectorAll", selector, this);
        }
        return originalElemQSA.call(this, selector);
      };
    }
  }

  /**
   * Instrument a property setter (like innerHTML).
   */
  function instrumentProperty(obj, propName, sinkName) {
    const originalDescriptor = Object.getOwnPropertyDescriptor(obj, propName);
    if (!originalDescriptor || !originalDescriptor.set) return;

    const originalSetter = originalDescriptor.set;

    Object.defineProperty(obj, propName, {
      ...originalDescriptor,
      set: function(value) {
        checkSinkValue(sinkName, value, this);
        return originalSetter.call(this, value);
      }
    });
  }

  /**
   * Instrument a method (like document.write).
   */
  function instrumentMethod(obj, methodName, sinkName, argIndex = 0) {
    const original = obj[methodName];
    if (typeof original !== "function") return;

    obj[methodName] = function(...args) {
      const value = args[argIndex];
      if (value !== undefined) {
        checkSinkValue(sinkName, String(value), this);
      }
      return original.apply(this, args);
    };
  }

  /**
   * Instrument setAttribute with attribute-aware severity.
   */
  function instrumentSetAttribute() {
    const original = Element.prototype.setAttribute;

    Element.prototype.setAttribute = function(name, value) {
      const lowerName = name.toLowerCase();
      let sinkName = "setAttribute";

      // Elevate severity for high-risk attributes
      if (HIGH_RISK_ATTRS.has(lowerName) || lowerName.startsWith("on")) {
        sinkName = `setAttribute:${lowerName}`;

        // Register dynamic sink info
        if (!SINK_REGISTRY[sinkName]) {
          const isEventHandler = lowerName.startsWith("on");
          SINK_REGISTRY[sinkName] = {
            category: isEventHandler ? "DOM-XSS" : "DOM-XSS",
            severity: isEventHandler ? "high" : "medium",
            context: isEventHandler ? "js" : "attr",
            notes: `setAttribute with ${lowerName}`
          };
        }
      }

      checkSinkValue(sinkName, String(value), this);
      return original.call(this, name, value);
    };
  }

  /**
   * Instrument timer methods (setTimeout/setInterval) - only string arguments.
   */
  function instrumentTimerMethod(methodName) {
    const original = window[methodName];
    if (typeof original !== "function") return;

    window[methodName] = function(handler, ...args) {
      // Only check if first argument is a string (code execution)
      if (typeof handler === "string") {
        checkSinkValue(methodName, handler, null);
      }
      return original.call(this, handler, ...args);
    };
  }

  /**
   * Instrument location-based sinks.
   */
  function instrumentLocationSinks() {
    // location.assign and location.replace
    const originalAssign = location.assign;
    const originalReplace = location.replace;

    if (typeof originalAssign === "function") {
      location.assign = function(url) {
        checkSinkValue("location.assign", String(url), null);
        return originalAssign.call(this, url);
      };
    }

    if (typeof originalReplace === "function") {
      location.replace = function(url) {
        checkSinkValue("location.replace", String(url), null);
        return originalReplace.call(this, url);
      };
    }

    // Note: location.href direct assignment is harder to intercept reliably
    // We rely on static analysis for that case
  }

  /**
   * Instrument jQuery methods if jQuery is present.
   * Covers both HTML injection sinks and selector injection sinks.
   */
  function instrumentJQuery() {
    const jq = window.jQuery || window.$;
    if (!jq || !jq.fn) return;

    // HTML injection methods
    const htmlMethods = ["html", "append", "prepend", "after", "before", "replaceWith"];

    for (const method of htmlMethods) {
      if (typeof jq.fn[method] === "function") {
        const original = jq.fn[method];
        jq.fn[method] = function(content) {
          if (typeof content === "string") {
            checkSinkValue(`$.${method}`, content, this[0]);
          }
          return original.apply(this, arguments);
        };
      }
    }

    // Selector methods (selector injection sinks)
    const selectorMethods = ["find", "filter", "is", "has", "closest", "not"];

    for (const method of selectorMethods) {
      if (typeof jq.fn[method] === "function") {
        const original = jq.fn[method];
        jq.fn[method] = function(selector) {
          if (typeof selector === "string") {
            checkSelectorValue(`$.${method}`, selector, this[0]);
          }
          return original.apply(this, arguments);
        };
      }
    }

    // Wrap the jQuery constructor itself: $() / jQuery()
    // This is the main entry point for selector injection
    instrumentJQueryConstructor(jq);
  }

  /**
   * Instrument the jQuery/$ constructor to detect selector injection.
   * jQuery(selector) where selector is a string is the primary vector.
   */
  function instrumentJQueryConstructor(jq) {
    // We need to wrap both window.jQuery and window.$
    const names = [];
    if (window.jQuery === jq) names.push("jQuery");
    if (window.$ === jq) names.push("$");

    for (const name of names) {
      const original = window[name];

      const wrapper = function(selector, context) {
        // Only check when first argument is a string (selector or HTML)
        if (typeof selector === "string" && selector.length >= MIN_TOKEN_LENGTH) {
          // Determine sink name based on whether it looks like HTML or selector
          if (/^\s*</.test(selector)) {
            // HTML creation: $("<div>...</div>") - this is a DOM XSS sink
            checkSelectorValue("$.selector", selector, null);
          } else {
            // Selector: $(".class") or $("[attr=val]")
            checkSelectorValue("$.selector", selector, null);
          }
        }
        return original.apply(this, arguments);
      };

      // Copy all static properties and prototype
      try {
        Object.setPrototypeOf(wrapper, original);
        for (const prop of Object.getOwnPropertyNames(original)) {
          if (prop !== "length" && prop !== "name" && prop !== "prototype") {
            try {
              const desc = Object.getOwnPropertyDescriptor(original, prop);
              if (desc) Object.defineProperty(wrapper, prop, desc);
            } catch { /* skip non-configurable */ }
          }
        }
        wrapper.fn = original.fn;
        wrapper.prototype = original.prototype;
        window[name] = wrapper;
      } catch (err) {
        console.debug(`[Reflex] Could not wrap ${name}():`, err.message);
      }
    }
  }

  // Elements where innerHTML/outerHTML content is treated as text, not rendered HTML.
  // Writing to these is not exploitable for XSS.
  const SAFE_INNERHTML_TAGS = new Set(["textarea", "title", "style", "script", "noscript"]);

  /**
   * Check if a value flowing to a sink correlates with a source.
   */
  function checkSinkValue(sinkName, value, element) {
    if (!value || typeof value !== "string") return;
    if (value.length < MIN_TOKEN_LENGTH) return;

    // Skip innerHTML/outerHTML writes to safe elements (textarea, title, etc.)
    // Content in these elements is treated as text, not rendered as HTML
    if ((sinkName === "innerHTML" || sinkName === "outerHTML") && element) {
      const tag = element.tagName?.toLowerCase();
      if (tag && SAFE_INNERHTML_TAGS.has(tag)) return;
    }

    // Skip if this looks like a template or framework binding
    if (isFrameworkTemplate(value)) return;

    const correlation = correlateTaint(value, collectedSources);

    if (correlation) {
      const domPath = element ? getDomPath(element) : null;
      recordTaintFinding(sinkName, value, correlation, { domPath });
    }
  }

  /**
   * Check if a selector string flowing to a selector sink contains user-controlled input.
   * Performs deeper analysis than generic checkSinkValue by evaluating risky selector patterns.
   *
   * @param {string} sinkName - The sink identifier (e.g., "$.selector", "$.find")
   * @param {string} selectorStr - The selector string argument
   * @param {Element|null} element - The DOM element context (if any)
   */
  function checkSelectorValue(sinkName, selectorStr, element) {
    if (!selectorStr || typeof selectorStr !== "string") return;
    if (selectorStr.length < MIN_TOKEN_LENGTH) return;

    // Skip obviously static selectors (simple tag/class/id without user data)
    if (isStaticSelector(selectorStr)) return;

    const correlation = correlateTaint(selectorStr, collectedSources);
    if (!correlation) return;

    // Analyze which risky patterns are present in the selector
    const riskyMatches = [];
    for (const rp of RISKY_SELECTOR_PATTERNS) {
      if (rp.pattern.test(selectorStr)) {
        riskyMatches.push(rp);
      }
    }

    // Determine effective severity: if HTML creation detected, escalate to DOM-XSS
    let effectiveSinkName = sinkName;
    let effectiveCategory = "Selector-Injection";
    let effectiveSeverity = "medium";

    const htmlCreation = riskyMatches.find(r => r.id === "html-creation");
    if (htmlCreation) {
      // $("<div>user input</div>") is actually DOM XSS, not just selector injection
      effectiveCategory = "DOM-XSS";
      effectiveSeverity = "high";
      effectiveSinkName = `${sinkName}:html-creation`;
      // Register dynamic sink
      if (!SINK_REGISTRY[effectiveSinkName]) {
        SINK_REGISTRY[effectiveSinkName] = {
          category: "DOM-XSS",
          severity: "high",
          context: "html",
          notes: "jQuery $() creating HTML elements from user input"
        };
      }
    } else if (riskyMatches.some(r => r.risk === "critical")) {
      effectiveSeverity = "critical";
    } else if (riskyMatches.some(r => r.risk === "high")) {
      effectiveSeverity = "high";
    }

    const sinkInfo = SINK_REGISTRY[effectiveSinkName] || SINK_REGISTRY[sinkName] || {
      category: effectiveCategory,
      severity: effectiveSeverity,
      context: "selector"
    };

    // Build evidence including risky patterns found
    let evidence = correlation.evidence;
    if (riskyMatches.length > 0) {
      const riskyList = riskyMatches.map(r => r.id).join(", ");
      evidence += ` | Risky patterns: ${riskyList}`;
    }

    const domPath = element ? getDomPath(element) : null;

    const finding = {
      findingType: effectiveCategory,
      source: {
        type: correlation.source.type,
        key: correlation.source.key,
        value: truncateEvidence(correlation.source.raw)
      },
      sink: {
        name: effectiveSinkName,
        category: effectiveCategory,
        severity: effectiveSeverity,
        context: "selector",
        value: truncateEvidence(selectorStr)
      },
      confidence: correlation.confidence,
      matchType: correlation.matchType,
      evidence,
      domPath,
      timestamp: new Date().toISOString(),
      pageUrl: window.location.href,
      triageHints: generateSelectorTriageHints(sinkName, riskyMatches, correlation),
      selectorRisks: riskyMatches.map(r => ({
        id: r.id,
        risk: r.risk,
        notes: r.notes
      }))
    };

    // Deduplicate
    if (!taintFindings.some(f =>
      f.source.key === finding.source.key &&
      f.sink.name === finding.sink.name &&
      f.sink.value === finding.sink.value
    )) {
      taintFindings.push(finding);
    }
  }

  /**
   * Check if a selector is clearly static (no dynamic content).
   * Static selectors: simple tag names, #ids, .classes, and basic combinations.
   * Returns true if the selector is definitely safe to skip.
   */
  function isStaticSelector(selector) {
    // Trim whitespace
    const s = selector.trim();

    // Very short selectors are likely static
    if (s.length < MIN_TOKEN_LENGTH) return true;

    // Simple static patterns: tag, #id, .class, tag.class, tag#id, combinations with spaces/commas/>
    // These never contain user data worth flagging
    if (/^[a-zA-Z#.\-_\s,>+~\[\]=*|^$"':()]+$/.test(s)) {
      // But check if it contains risky pseudo-selectors
      for (const rp of RISKY_SELECTOR_PATTERNS) {
        if (rp.pattern.test(s)) return false;
      }
      // No user-like data, no risky patterns
      return true;
    }

    return false;
  }

  /**
   * Generate triage hints specific to selector injection findings.
   */
  function generateSelectorTriageHints(sinkName, riskyMatches, correlation) {
    const hints = [];

    const hasHtmlCreation = riskyMatches.some(r => r.id === "html-creation");
    const hasContains = riskyMatches.some(r => r.id === "contains");
    const hasAttrSelector = riskyMatches.some(r => r.id === "attr-selector");
    const hasQuotes = riskyMatches.some(r => r.id === "unescaped-quotes");

    if (hasHtmlCreation) {
      hints.push("CRITICAL: jQuery $() with HTML string creates elements — test for XSS");
      hints.push("Check if < > characters in source value are passed through unescaped");
    } else {
      hints.push("DOM Selector Injection precursor — not directly exploitable but may enable:");
    }

    if (hasContains) {
      hints.push(":contains() can leak text content via timing or CSS-based exfiltration");
      hints.push("Test if attacker can extract secrets from page via :contains('secret')");
    }

    if (hasAttrSelector) {
      hints.push("Attribute selector can probe element attributes (e.g., CSRF tokens)");
      hints.push("Test with [value^='a'], [value^='b'], etc. for character-by-character extraction");
    }

    if (hasQuotes) {
      hints.push("Unescaped quotes may allow breaking out of selector context");
    }

    if (riskyMatches.length === 0) {
      hints.push("No risky selector patterns detected — low exploitability");
      hints.push("Verify source value actually flows into the selector string");
    }

    if (correlation.source.type === SOURCE_TYPES.FRAGMENT) {
      hints.push("Fragment-based source: client-side only, no server interaction needed");
    }

    if (correlation.confidence === "low") {
      hints.push("Low confidence — verify the source-sink relationship manually");
    }

    return hints;
  }

  /**
   * Check if value looks like a framework template (reduce false positives).
   */
  function isFrameworkTemplate(value) {
    // Angular, Vue, React-like patterns
    return /\{\{.*\}\}/.test(value) ||
           /\$\{.*\}/.test(value) ||
           /<\/?[a-z]+-[a-z]+/i.test(value); // Custom elements
  }

  /**
   * Get a CSS-like path to a DOM element.
   */
  function getDomPath(element) {
    if (!element || !element.tagName) return null;

    const parts = [];
    let el = element;
    let depth = 0;

    while (el && el.tagName && depth < 5) {
      let selector = el.tagName.toLowerCase();
      if (el.id) {
        selector += `#${el.id}`;
      } else if (el.className && typeof el.className === "string") {
        const classes = el.className.split(/\s+/).slice(0, 2).join(".");
        if (classes) selector += `.${classes}`;
      }
      parts.unshift(selector);
      el = el.parentElement;
      depth++;
    }

    return parts.join(" > ");
  }

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
    } else if (msg?.type === "ENABLE_TAINT_DETECTION") {
      // Enable runtime sink instrumentation
      const options = msg.options || {};
      const sources = collectSources(options);
      collectedSources = sources;
      if (options.enableInstrumentation) {
        installSinkInstrumentation(sources);
      }
      sendResponse({ ok: true, sourceCount: sources.length });
    } else if (msg?.type === "GET_TAINT_FINDINGS") {
      // Return collected taint findings
      sendResponse({ findings: taintFindings });
    } else if (msg?.type === "CLEAR_TAINT_FINDINGS") {
      // Clear taint findings
      taintFindings = [];
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

      // De-dupe, suppress TEXT/SCRIPT overlaps, collapse identical contexts, and limit
      const deduped = dedupeFindings(perParam);
      const pruned = suppressTextScriptOverlaps(deduped);
      const collapsed = collapseIdentical(pruned).slice(0, maxFindingsPerParam);

      if (collapsed.length) {
        findings.push({
          param: c.key,
          source: c.source, // "query" or "fragment"
          original: c.value,
          variants,
          matches: collapsed
        });
      }
    }

    // Collect sources and perform taint analysis
    const sources = collectSources(options);
    collectedSources = sources;

    // Perform static taint analysis on script content
    const staticTaintFindings = [];
    if (options.enableTaintAnalysis) {
      for (const s of inlineScripts) {
        // Value-based taint analysis (source values in script text)
        const scriptTaints = analyzeScriptForTaint(s.content, sources);
        staticTaintFindings.push(...scriptTaints);

        // Code-flow analysis (source code references near sink patterns)
        const codeFlowTaints = analyzeScriptForCodeFlows(s.content);
        staticTaintFindings.push(...codeFlowTaints);
      }
    }

    // Enable runtime instrumentation if requested
    if (options.enableInstrumentation && !sinkInstrumentationEnabled) {
      installSinkInstrumentation(sources);
    }

    // Combine runtime taint findings with static analysis
    const allTaintFindings = [...taintFindings, ...staticTaintFindings];

    // Deduplicate taint findings
    const dedupedTaint = deduplicateTaintFindings(allTaintFindings);

    return {
      url: window.location.href,
      scannedAt: new Date().toISOString(),
      candidateParamCount: candidates.length,
      reflectedParamCount: findings.length,
      findings,
      // New taint analysis data
      taint: {
        sourceCount: sources.length,
        findingCount: dedupedTaint.length,
        findings: dedupedTaint.slice(0, 50), // Cap for performance
        sources: sources.map(s => ({
          type: s.type,
          key: s.key,
          preview: truncateEvidence(s.raw, 80)
        }))
      }
    };
  }

  /**
   * Analyze script content for static taint patterns.
   */
  function analyzeScriptForTaint(scriptContent, sources) {
    const findings = [];
    if (!scriptContent || scriptContent.length > 500000) return findings; // Skip huge scripts

    // Look for sink patterns with source values
    for (const src of sources) {
      if (src.raw.length < MIN_TOKEN_LENGTH) continue;

      // Skip sources marked as runtime-only (e.g., document.URL) — their values
      // are too broad for static substring matching in script code
      if (src.runtimeOnly) continue;

      // Check if source value appears in script
      if (!scriptContent.includes(src.raw)) continue;

      // Check for dangerous patterns near the source value (DOM XSS sinks)
      for (const { pattern, sinkType, confidence } of SINK_PROXIMITY_PATTERNS) {
        findStaticSinkPattern(scriptContent, src, pattern, sinkType, confidence, findings);
      }

      // Check for selector sink patterns near the source value
      for (const { pattern, sinkType, confidence } of SELECTOR_SINK_PATTERNS) {
        findStaticSelectorPattern(scriptContent, src, pattern, sinkType, confidence, findings);
      }
    }

    return findings;
  }

  /**
   * Check if a source value match in script text looks like a standalone value
   * (e.g., in a string literal or data structure) vs. part of a code identifier
   * or property access.
   *
   * Returns false for matches embedded in identifiers like "searchParams", "postMessage",
   * "hostname", or property accesses like "t.search", "location.pathname".
   */
  function isLikelyValueMatch(scriptContent, matchIdx, matchLen) {
    const charBefore = matchIdx > 0 ? scriptContent[matchIdx - 1] : "";
    const charAfter = matchIdx + matchLen < scriptContent.length ? scriptContent[matchIdx + matchLen] : "";

    // Characters that indicate the match is part of a code construct:
    // \w = identifier chars (a-z, A-Z, 0-9, _)
    // .  = property access (t.search, location.pathname)
    const isCodeChar = c => /[\w.]/.test(c);

    if (isCodeChar(charBefore) || isCodeChar(charAfter)) {
      return false;
    }

    return true;
  }

  /**
   * Find a static sink pattern near a source value in script content.
   */
  function findStaticSinkPattern(scriptContent, src, pattern, sinkType, confidence, findings) {
    let idx = 0;
    while ((idx = scriptContent.indexOf(src.raw, idx)) !== -1) {
      // Skip matches that are part of larger identifiers (e.g., "search" in "searchParams")
      if (!isLikelyValueMatch(scriptContent, idx, src.raw.length)) {
        idx += src.raw.length;
        continue;
      }

      const contextStart = Math.max(0, idx - 150);
      const contextEnd = Math.min(scriptContent.length, idx + src.raw.length + 150);
      const context = scriptContent.slice(contextStart, contextEnd);

      if (pattern.test(context)) {
        const sinkInfo = SINK_REGISTRY[sinkType] || {
          category: "DOM-XSS",
          severity: "medium"
        };

        findings.push({
          findingType: sinkInfo.category,
          source: {
            type: src.type,
            key: src.key,
            value: truncateEvidence(src.raw)
          },
          sink: {
            name: sinkType,
            category: sinkInfo.category,
            severity: sinkInfo.severity,
            context: "script",
            value: truncateEvidence(context)
          },
          confidence: confidence,
          matchType: "static-pattern",
          evidence: `Source "${src.key}" found near ${sinkType} in script`,
          timestamp: new Date().toISOString(),
          pageUrl: window.location.href,
          triageHints: generateTriageHints(sinkInfo, { source: src, confidence })
        });
      }

      idx += src.raw.length;
      if (findings.length > 20) break;
    }
  }

  /**
   * Find a static selector sink pattern near a source value in script content.
   * Performs additional analysis for risky selector patterns in the context.
   */
  function findStaticSelectorPattern(scriptContent, src, pattern, sinkType, confidence, findings) {
    let idx = 0;
    while ((idx = scriptContent.indexOf(src.raw, idx)) !== -1) {
      // Skip matches that are part of larger identifiers
      if (!isLikelyValueMatch(scriptContent, idx, src.raw.length)) {
        idx += src.raw.length;
        continue;
      }

      const contextStart = Math.max(0, idx - 200);
      const contextEnd = Math.min(scriptContent.length, idx + src.raw.length + 200);
      const context = scriptContent.slice(contextStart, contextEnd);

      if (pattern.test(context)) {
        const sinkInfo = SINK_REGISTRY[sinkType] || {
          category: "Selector-Injection",
          severity: "medium",
          context: "selector"
        };

        // Check for risky selector patterns in the context
        const riskyMatches = [];
        for (const rp of RISKY_SELECTOR_PATTERNS) {
          if (rp.pattern.test(context)) {
            riskyMatches.push(rp);
          }
        }

        // Determine effective category/severity based on risky patterns
        let effectiveCategory = "Selector-Injection";
        let effectiveSeverity = sinkInfo.severity || "medium";
        if (riskyMatches.some(r => r.id === "html-creation")) {
          effectiveCategory = "DOM-XSS";
          effectiveSeverity = "high";
        } else if (riskyMatches.some(r => r.risk === "critical")) {
          effectiveSeverity = "critical";
        } else if (riskyMatches.some(r => r.risk === "high")) {
          effectiveSeverity = "high";
        }

        let evidence = `Source "${src.key}" found near ${sinkType} in script`;
        if (riskyMatches.length > 0) {
          evidence += ` (risky: ${riskyMatches.map(r => r.id).join(", ")})`;
        }

        findings.push({
          findingType: effectiveCategory,
          source: {
            type: src.type,
            key: src.key,
            value: truncateEvidence(src.raw)
          },
          sink: {
            name: sinkType,
            category: effectiveCategory,
            severity: effectiveSeverity,
            context: "selector",
            value: truncateEvidence(context)
          },
          confidence,
          matchType: "static-selector-pattern",
          evidence,
          timestamp: new Date().toISOString(),
          pageUrl: window.location.href,
          triageHints: generateSelectorTriageHints(sinkType, riskyMatches, { source: src, confidence }),
          selectorRisks: riskyMatches.map(r => ({
            id: r.id,
            risk: r.risk,
            notes: r.notes
          }))
        });
      }

      idx += src.raw.length;
      if (findings.length > 20) break;
    }
  }

  /**
   * Analyze script content for source-to-sink CODE FLOW patterns.
   *
   * Unlike analyzeScriptForTaint() which looks for runtime source VALUES in scripts,
   * this function detects when source CODE REFERENCES (e.g., location.hash,
   * document.referrer) appear in proximity to sink code patterns (e.g., $(':contains(' + ...)).
   *
   * This catches patterns like:
   *   $('h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')')
   * where the hash value is read programmatically and flows into a selector sink.
   */
  function analyzeScriptForCodeFlows(scriptContent) {
    const findings = [];
    if (!scriptContent || scriptContent.length > 500000) return findings;

    // For each source code pattern, check if it appears in the script
    for (const srcPattern of SOURCE_CODE_PATTERNS) {
      // Reset regex lastIndex
      srcPattern.pattern.lastIndex = 0;

      let srcMatch;
      while ((srcMatch = srcPattern.pattern.exec(scriptContent)) !== null) {
        const srcIdx = srcMatch.index;

        // Get a wide context window around the source reference (500 chars each way)
        const contextStart = Math.max(0, srcIdx - 500);
        const contextEnd = Math.min(scriptContent.length, srcIdx + srcMatch[0].length + 500);
        const context = scriptContent.slice(contextStart, contextEnd);

        // Check if any sink pattern is in this context
        for (const sinkPattern of SINK_CODE_PATTERNS) {
          if (sinkPattern.pattern.test(context)) {
            // Determine if this is a selector injection with risky patterns
            const selectorRisks = [];
            if (sinkPattern.category === "Selector-Injection") {
              // Check for risky selector patterns in the context
              for (const rp of RISKY_SELECTOR_PATTERNS) {
                if (rp.pattern.test(context)) {
                  selectorRisks.push({ id: rp.id, risk: rp.risk, notes: rp.notes });
                }
              }

              // Also add the concatenation risk if applicable
              if (sinkPattern.selectorRisk === "concatenation") {
                selectorRisks.push({
                  id: "concatenation",
                  risk: "medium",
                  notes: "User input concatenated into selector string"
                });
              }
            }

            // Determine effective severity
            let effectiveSeverity = sinkPattern.severity;
            if (selectorRisks.some(r => r.risk === "critical")) {
              effectiveSeverity = "critical";
            } else if (selectorRisks.some(r => r.risk === "high") && effectiveSeverity !== "critical") {
              effectiveSeverity = "high";
            }

            // Narrow the snippet for display
            const snippetStart = Math.max(0, srcIdx - 80);
            const snippetEnd = Math.min(scriptContent.length, srcIdx + srcMatch[0].length + 80);
            const snippet = scriptContent.slice(snippetStart, snippetEnd);

            const finding = {
              findingType: sinkPattern.category,
              source: {
                type: srcPattern.sourceType,
                key: srcPattern.sourceKey,
                value: srcPattern.notes
              },
              sink: {
                name: sinkPattern.sinkName,
                category: sinkPattern.category,
                severity: effectiveSeverity,
                context: sinkPattern.category === "Selector-Injection" ? "selector" : "script",
                value: truncateEvidence(snippet)
              },
              confidence: "high",
              matchType: "code-flow",
              evidence: `Code ref "${srcPattern.sourceKey}" flows to ${sinkPattern.sinkName}`,
              timestamp: new Date().toISOString(),
              pageUrl: window.location.href,
              triageHints: sinkPattern.category === "Selector-Injection"
                ? generateSelectorTriageHints(sinkPattern.sinkName, selectorRisks, {
                    source: { type: srcPattern.sourceType }, confidence: "high"
                  })
                : generateTriageHints(
                    SINK_REGISTRY[sinkPattern.sinkName] || { category: sinkPattern.category, severity: effectiveSeverity },
                    { source: { type: srcPattern.sourceType }, confidence: "high" }
                  )
            };

            if (selectorRisks.length > 0) {
              finding.selectorRisks = selectorRisks;
            }

            findings.push(finding);

            // Only one sink match per source occurrence to avoid duplicates
            break;
          }
        }

        if (findings.length > 30) break;
      }
    }

    return findings;
  }

  /**
   * Deduplicate taint findings.
   */
  function deduplicateTaintFindings(findings) {
    const seen = new Map();

    for (const f of findings) {
      const key = `${f.source.key}|${f.sink.name}|${f.confidence}`;
      const existing = seen.get(key);

      if (!existing || getConfidenceScore(f.confidence) > getConfidenceScore(existing.confidence)) {
        seen.set(key, f);
      }
    }

    return Array.from(seen.values());
  }

  function getConfidenceScore(conf) {
    return { high: 3, medium: 2, low: 1 }[conf] || 0;
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
   *
   * Returns an object with:
   *   tested: boolean - whether the original value contained any test chars
   *   raw: string[]   - chars that reflect unencoded (exploitable)
   *   encoded: string[] - chars that are encoded (safer)
   *   stripped: string[] - chars that were removed entirely
   *
   * When tested=false, the original value contained none of < > " ' &
   * so encoding behavior is UNKNOWN (not safe). The user would need to
   * test with a canary value containing these chars to determine behavior.
   */
  function detectEncoding(originalValue, snippet) {
    const raw = [];
    const encoded = [];
    const stripped = [];

    // Check if any test chars are present in the original value
    const hasTestChars = ENCODING_TEST_CHARS.some(c => originalValue.includes(c));

    if (!hasTestChars) {
      return { tested: false, raw, encoded, stripped };
    }

    for (const char of ENCODING_TEST_CHARS) {
      // Only check chars that exist in the original value
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
        } else {
          // Character was present in input but absent from output entirely
          stripped.push(char);
        }
      }
    }

    return { tested: true, raw, encoded, stripped };
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
  // SINK HINT DETECTION
  // ============================================================

  /**
   * Detect if a reflection is near a dangerous DOM XSS sink.
   * Returns a sinkHint object if detected, null otherwise.
   *
   * @param {string} context - The surrounding code/content (wider snippet)
   * @param {string} kind - The match kind (SCRIPT, ATTRIBUTE, etc.)
   * @param {string} subtype - The match subtype
   * @param {string} location - The match location (e.g., "script", "a[href]")
   * @returns {object|null} - { sinkType, proximityEvidence, confidence } or null
   */
  function detectSinkHint(context, kind, subtype, location) {
    // For script contexts, look for sink patterns in the surrounding code
    if (kind === "SCRIPT" && subtype === "INLINE_SCRIPT") {
      for (const { pattern, sinkType, confidence } of SINK_PROXIMITY_PATTERNS) {
        const match = context.match(pattern);
        if (match) {
          return {
            sinkType,
            proximityEvidence: truncateEvidence(match[0]),
            confidence
          };
        }
      }
    }

    // For JSON scripts, check if the data might be used unsafely
    if (kind === "SCRIPT" && subtype === "JSON_SCRIPT") {
      // JSON data that gets inserted via innerHTML is common
      if (context.includes("innerHTML") || context.includes("document.write")) {
        return {
          sinkType: "JSON-to-DOM",
          proximityEvidence: "JSON data may flow to innerHTML/document.write",
          confidence: "low"
        };
      }
    }

    // For event handler attributes, they execute JS directly
    if (kind === "ATTRIBUTE" && subtype === "EVENT_HANDLER") {
      return {
        sinkType: "event-handler",
        proximityEvidence: `Reflected in ${location} event handler`,
        confidence: "high"
      };
    }

    // For URL attributes, check for javascript: potential
    if (kind === "ATTRIBUTE" && subtype === "URL_ATTR") {
      const attrName = location?.split("[")[1]?.replace("]", "") || "";
      if (["href", "src", "action"].includes(attrName)) {
        return {
          sinkType: "url-injection",
          proximityEvidence: `Reflected in ${attrName} URL attribute`,
          confidence: "medium"
        };
      }
    }

    // For HTML context, check for direct tag injection potential
    if (kind === "HTML") {
      if (subtype === "IN_EVENT_HANDLER") {
        return {
          sinkType: "event-handler",
          proximityEvidence: "Reflected in event handler context",
          confidence: "high"
        };
      }
      if (subtype === "BETWEEN_TAGS") {
        // If encoding check shows raw < or >, high risk
        return {
          sinkType: "html-injection",
          proximityEvidence: "Reflected between HTML tags",
          confidence: "medium"
        };
      }
    }

    return null;
  }

  /**
   * Cap a string to a maximum length for storage.
   * Uses a generous default (500) to preserve investigative detail.
   * Display-time truncation happens separately in popup.js.
   */
  function truncateEvidence(str, maxLen = 500) {
    if (!str || typeof str !== "string") return "";
    if (str.length <= maxLen) return str;
    return str.slice(0, maxLen) + "…[" + (str.length - maxLen) + " more chars]";
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
    const location = scriptType ? `script[type="${scriptType}"]` : "script";

    for (const v of variants) {
      if (!v || v.length < 2) continue;

      let idx = 0;
      while (true) {
        const found = content.indexOf(v, idx);
        if (found === -1) break;

        const snippet = snippetAround(content, found, v.length);
        const encoding = detectEncoding(originalValue, snippet);

        // Get wider context for sink detection (200 chars around)
        const wideContext = content.slice(Math.max(0, found - 100), Math.min(content.length, found + v.length + 100));
        const sinkHint = detectSinkHint(wideContext, "SCRIPT", subtype, location);

        const match = {
          kind: "SCRIPT",
          subtype,
          interest,
          match: v,
          location,
          snippet,
          encoding
        };

        if (sinkHint) match.sinkHint = sinkHint;
        out.push(match);

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
    const location = `${tag}[${attr}]`;

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
        const sinkHint = detectSinkHint(value, "ATTRIBUTE", subtype, location);

        const match = {
          kind: "ATTRIBUTE",
          subtype,
          interest,
          match: v,
          location,
          snippet,
          quoteContext,
          encoding
        };

        if (sinkHint) match.sinkHint = sinkHint;
        out.push(match);

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
        const sinkHint = detectSinkHint(snippet, "HTML", context.subtype, context.location);

        const match = {
          kind: "HTML",
          subtype: context.subtype,
          interest: context.interest,
          match: v,
          location: context.location,
          snippet,
          encoding
        };

        if (sinkHint) match.sinkHint = sinkHint;
        out.push(match);

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

  /**
   * Suppress TEXT matches whose snippets overlap with SCRIPT findings.
   * TEXT nodes inside <script> tags produce duplicate noise.
   */
  function suppressTextScriptOverlaps(items) {
    const scriptSnippets = new Set();
    for (const it of items) {
      if (it.kind === "SCRIPT") {
        scriptSnippets.add(it.snippet);
      }
    }
    if (scriptSnippets.size === 0) return items;

    return items.filter(it => {
      if (it.kind !== "TEXT") return true;
      // Suppress if the TEXT snippet is contained in any SCRIPT snippet or vice versa
      for (const ss of scriptSnippets) {
        if (ss.includes(it.snippet) || it.snippet.includes(ss)) return false;
      }
      return true;
    });
  }

  /**
   * Generate a stable sink identifier for deduplication.
   * Format: kind|subtype|normalizedLocation
   */
  function generateSinkId(match) {
    const kind = match.kind || "UNKNOWN";
    const subtype = match.subtype || "";
    // Normalize location to remove dynamic indices
    let location = match.location || "";
    // Strip array indices and dynamic parts: foo[0] -> foo[], script[type="..."] -> script[type]
    location = location.replace(/\[\d+\]/g, "[]").replace(/="[^"]*"/g, "");
    return `${kind}|${subtype}|${location}`;
  }

  /**
   * Collapse identical reflections by sink + value into a single entry.
   * Dedup key = sinkId|normalizedMatch
   * Stores count and capped occurrences array (max 5 snippets).
   */
  function collapseIdentical(items) {
    const MAX_OCCURRENCES = 5;
    const groups = new Map();

    for (const it of items) {
      const sinkId = generateSinkId(it);
      const normalizedMatch = (it.match || "").toLowerCase().trim();
      const key = `${sinkId}|${normalizedMatch}`;

      if (!groups.has(key)) {
        groups.set(key, {
          representative: { ...it, sinkId },
          count: 1,
          occurrences: [{ snippet: it.snippet, match: it.match }]
        });
      } else {
        const group = groups.get(key);
        group.count++;
        // Cap occurrences to avoid bloat
        if (group.occurrences.length < MAX_OCCURRENCES) {
          // Only add if snippet is meaningfully different
          const snippetExists = group.occurrences.some(o => o.snippet === it.snippet);
          if (!snippetExists) {
            group.occurrences.push({ snippet: it.snippet, match: it.match });
          }
        }
      }
    }

    return [...groups.values()].map(g => {
      const result = { ...g.representative, count: g.count };
      if (g.count > 1) {
        result.occurrences = g.occurrences;
      }
      return result;
    });
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
