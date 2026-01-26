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

## Understanding Results

- **Source**: `?` = query parameter, `#` = fragment parameter (DOM XSS relevant)
- **Interest Level**: High (red) = direct execution context, Medium (orange) = indirect risk, Low (green) = display only
- **Encoding**: RAW = character reflects unencoded (potential injection), ENC = character is encoded

## Permissions

- `activeTab` / `scripting`: Inject scanner into pages
- `storage`: Save settings
- `tabs` / `webNavigation`: Passive scanning support
- `<all_urls>`: Required for passive scanning on any site
