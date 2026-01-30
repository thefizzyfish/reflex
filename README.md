# Reflex - Reflection Finder

A Chrome extension that detects reflected URL parameter values in web pages. Useful for identifying potential XSS (Cross-Site Scripting) injection points during security testing.

## What It Does

Reflex scans the current page for URL query and fragment parameters that are reflected in:
- HTML content
- Element attributes (with classification: event handlers, URLs, styles, etc.)
- Inline scripts
- Text nodes

Each finding is classified by risk level (high/medium/low) based on context, and shows whether critical characters (`< > " ' &`) are encoded or reflected raw.

## Installation

1. Open `chrome://extensions`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select the `reflex` folder

## Usage

**Manual Scan**: Click the extension icon, then "Scan Page" to analyze the current page.

**Passive Scan**: Enable in Options to automatically scan all pages as you browse. The badge shows the count of reflected parameters.

**Export**: Click "Export JSON" to download findings for documentation.

## Options

- **Passive Scanning**: Toggle automatic scanning on/off
- **Minimum Length**: Ignore short parameter values (reduces noise)
- **Decode Depth**: Number of URL decoding passes
- **Scan Targets**: Choose what to scan (HTML, attributes, scripts, text)
- **Ignored Parameters**: Skip common tracking params (utm_*, gclid, etc.)
- **Canary Verification**: Active testing mode (see below)

## Understanding Results

- **Source**: `?` = query parameter, `#` = fragment parameter (DOM XSS relevant)
- **Interest Level**: High (red) = direct execution context, Medium (orange) = indirect risk, Low (green) = display only
- **Encoding**: RAW = character reflects unencoded (potential injection), ENC = character is encoded, STRIPPED = character removed
- **Occurrences**: When multiple identical reflections exist, they are collapsed with a count (click to expand)
- **DOM XSS Hints**: Heuristic indicators when a reflection is near dangerous sinks

## Deduplication

Reflex automatically deduplicates findings to reduce noise:

- Findings with the same sink location and value are collapsed into a single entry
- A count shows how many occurrences exist (e.g., "x8")
- Click "Show N more occurrences" to view additional snippets
- TEXT node matches that overlap with SCRIPT matches are suppressed

The dedup key is: `sinkId | normalized value`, where sinkId is derived from `kind | subtype | normalized location`.

## Taint Flow Analysis (Source-to-Sink Detection)

Reflex performs heuristic taint flow analysis to detect when attacker-controlled input reaches dangerous sinks.

### Sources (Attacker-Controlled Input)

- **URL sources**: Query parameters, fragment/hash, path segments
- **Document sources**: document.URL, document.referrer, document.cookie
- **Storage sources**: localStorage, sessionStorage (with key attribution)
- **Other sources**: window.name, postMessage data

### Sinks (Dangerous Operations)

| Category | Sinks | Severity |
|----------|-------|----------|
| DOM XSS | innerHTML, outerHTML, document.write, eval, Function, setTimeout(string) | Critical/High |
| Open Redirect | location.assign, location.replace, location.href | Medium |
| Request Forgery | fetch, XMLHttpRequest.open, WebSocket | Medium |
| Header Injection | XMLHttpRequest.setRequestHeader | Medium |
| XPath Injection | document.evaluate | Medium |
| JSON Injection | JSON.parse (prototype pollution risk) | Low |
| Selector Injection | $(), jQuery(), .find(), .filter(), querySelector() | Medium |

### Confidence Levels

- **HIGH**: Exact match between source value and sink argument
- **MEDIUM**: Variant match (decoded) or substring containment
- **LOW**: Token match or weak correlation

### Triage Hints

Each finding includes actionable hints:
- Encoding verification suggestions
- URL scheme restriction checks
- Context-specific testing recommendations

### Enabling Runtime Instrumentation

By default, Reflex uses static pattern analysis. For more thorough detection, enable runtime instrumentation in Options:

1. Check "Enable runtime instrumentation"
2. This wraps dangerous APIs (innerHTML, eval, etc.) to observe values at call-time
3. Note: May impact page performance on complex sites

### Privacy & Performance

- All analysis happens locally (no data leaves your browser)
- Static analysis caps at 500KB script size
- Runtime instrumentation uses minimal overhead
- Findings are capped to prevent memory bloat

## DOM Selector Injection Detection

Reflex detects when user-controlled input flows into jQuery selectors or `querySelector`/`querySelectorAll` calls. This class of vulnerability is a precursor to data exfiltration and, in some cases, full DOM XSS.

### Detected Selector Sinks

| Sink | Notes |
|------|-------|
| `$()` / `jQuery()` | Main jQuery constructor — HTML creation (`$("<div>")`) escalates to DOM XSS |
| `.find()` | jQuery DOM traversal with user selector |
| `.filter()` / `.is()` / `.has()` / `.not()` / `.closest()` | jQuery filtering with user selector |
| `document.querySelector()` / `querySelectorAll()` | Native selector APIs |

### Risky Selector Patterns

When user input reaches a selector sink, Reflex checks for these exploitable patterns:

| Pattern | Risk | Impact |
|---------|------|--------|
| `$("<tag>")` (HTML creation) | Critical | Full XSS — jQuery creates DOM elements from HTML strings |
| `:contains()` | High | Text content exfiltration via timing or CSS side-channels |
| `:expression()` | Critical | Code execution (legacy IE) |
| `[attr^=val]` (attribute selectors) | Medium | Attribute value probing (e.g., CSRF token extraction) |
| Unescaped quotes | Medium | Selector context breakout |
| `:has()` | Medium | DOM structure probing |
| `:eq()`, `:lt()`, `:gt()`, `:nth-*` | Low | Positional selectors (limited impact) |

### False Positive Reduction

- Static selectors (simple tag, class, ID patterns) are automatically skipped
- Minimum token length prevents short-string false matches
- Only flags selectors that correlate with known attacker-controlled sources

### Detection Modes

- **Static analysis**: Scans inline scripts for selector sink patterns near source values (always active when taint analysis is enabled)
- **Runtime instrumentation**: Wraps `$()`, `jQuery()`, `.find()`, `.filter()`, `.is()`, `querySelector()`, etc. to observe selector arguments at call-time (requires enabling instrumentation in Options)

## DOM XSS Sink Hints

Reflex provides heuristic hints when a reflected value appears near dangerous DOM XSS sinks:

- **innerHTML/outerHTML**: Value near HTML injection points
- **document.write**: Value in document.write context
- **eval/Function**: Value near code execution sinks
- **location/href**: Value in URL assignment context
- **Event handlers**: Value in onclick, onerror, etc.

These are triage hints only, not confirmed vulnerabilities. Confidence levels (high/medium/low) indicate proximity strength.

## Canary Verification (Active Testing)

Canary verification is an optional active testing mode that confirms reflections by sending a unique canary value and checking if it appears in the response.

### Safety Features

- **Disabled by default**: Must be explicitly enabled in Options
- **Scope-restricted**: Only runs on hosts you explicitly add to the in-scope list
- **Benign canaries**: Uses inert strings (rfx-xxxxxxxxxxxx) with no special characters
- **Rate limited**: Maximum 3 verifications per page scan (configurable)
- **Debounced**: 5-second cooldown between re-verifying the same parameter
- **No data exfiltration**: All processing happens locally

### How to Use

1. Open Options and enable "Canary Verification"
2. Add target hosts to "In-Scope Hosts" (e.g., `example.com`, `*.test.local`)
3. Run a manual scan on an in-scope page
4. Click "Verify with Canary" on any finding to confirm the reflection

### Verification Results

- **Verified**: Canary string was reflected in the response
- **Not Verified**: Canary was not found (may indicate filtering, WAF, or dynamic rendering)
- **Error**: Request failed (CORS, auth, network issues)

### Scope Format

- Exact match: `example.com`
- Wildcard subdomain: `*.example.com` (matches example.com and any subdomain)

## Export Format

The JSON export includes:

```json
{
  "exportedAt": "2024-01-15T12:00:00.000Z",
  "url": "https://example.com/?q=test",
  "scannedAt": "2024-01-15T11:59:50.000Z",
  "candidateParamCount": 1,
  "reflectedParamCount": 1,
  "findings": [{
    "param": "q",
    "source": "query",
    "original": "test",
    "matches": [{
      "kind": "SCRIPT",
      "subtype": "INLINE_SCRIPT",
      "interest": "high",
      "sinkId": "SCRIPT|INLINE_SCRIPT|script",
      "count": 3,
      "occurrences": [...],
      "sinkHint": {
        "sinkType": "innerHTML",
        "proximityEvidence": ".innerHTML =",
        "confidence": "high"
      },
      "encoding": { "tested": true, "raw": [], "encoded": ["<"], "stripped": [] }
    }]
  }]
}
```

## Permissions

- `activeTab` / `scripting`: Inject scanner into pages
- `storage`: Save settings
- `tabs` / `webNavigation`: Passive scanning support
- `<all_urls>`: Required for passive scanning and canary verification
