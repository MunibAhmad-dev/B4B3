#!/usr/bin/env python3
"""
ext_auditor.py — Standalone Browser Extension Security Auditor
stdlib only (zipfile, json, re, os, sys, pathlib, struct, html, io)

Usage:
  python ext_auditor.py <dir_or_crx_or_zip>
  python ext_auditor.py --format json <ext>
  python ext_auditor.py --format html -o report.html <ext>
"""

import sys
import os
import re
import json
import zipfile
import struct
import io
import base64
import html as html_module
from pathlib import Path
from collections import defaultdict

# ─────────────────────────────────────────────────────────────────────────────
# 1. LOADER
# ─────────────────────────────────────────────────────────────────────────────

def load_extension(path):
    """Return {filename: bytes} for directory, .zip, .crx (v2/v3), .xpi."""
    path = Path(path)
    if not path.exists():
        sys.exit(f"[!] Not found: {path}")

    if path.is_dir():
        out = {}
        for f in path.rglob("*"):
            if f.is_file():
                rel = str(f.relative_to(path)).replace("\\", "/")
                out[rel] = f.read_bytes()
        return out

    raw = path.read_bytes()

    # CRX2 / CRX3: magic = b'Cr24'
    if raw[:4] == b'Cr24':
        version = struct.unpack_from('<I', raw, 4)[0]
        if version == 2:
            pubkey_len = struct.unpack_from('<I', raw, 8)[0]
            sig_len    = struct.unpack_from('<I', raw, 12)[0]
            zip_start  = 16 + pubkey_len + sig_len
        elif version == 3:
            header_size = struct.unpack_from('<I', raw, 8)[0]
            zip_start   = 12 + header_size
        else:
            zip_start = 16
        raw = raw[zip_start:]

    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            return {name: zf.read(name) for name in zf.namelist()}
    except zipfile.BadZipFile:
        sys.exit(f"[!] Cannot open as zip/crx: {path}")


# ─────────────────────────────────────────────────────────────────────────────
# 2. MANIFEST PARSER
# ─────────────────────────────────────────────────────────────────────────────

def parse_manifest(files):
    if "manifest.json" not in files:
        sys.exit("[!] No manifest.json found.")
    try:
        return json.loads(files["manifest.json"].decode("utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        sys.exit(f"[!] manifest.json parse error: {e}")


def extract_info(manifest):
    """Extract name, version, description, permissions, host_permissions, scripts."""
    info = {
        "name":              manifest.get("name", "Unknown"),
        "version":           manifest.get("version", "?"),
        "description":       manifest.get("description", ""),
        "manifest_version":  manifest.get("manifest_version", "?"),
        "permissions":       [],
        "host_permissions":  [],
        "content_scripts":   [],
        "background_scripts":[],
        "web_accessible":    [],
    }

    # permissions (MV2 includes host patterns here; MV3 separates them)
    for p in manifest.get("permissions", []):
        if isinstance(p, str):
            info["permissions"].append(p)

    # host_permissions (MV3)
    for p in manifest.get("host_permissions", []):
        if isinstance(p, str):
            info["host_permissions"].append(p)

    # content_scripts
    for cs in manifest.get("content_scripts", []):
        for js in cs.get("js", []):
            info["content_scripts"].append(js.lstrip("/"))

    # background
    bg = manifest.get("background", {})
    for js in bg.get("scripts", []):
        info["background_scripts"].append(js.lstrip("/"))
    if "service_worker" in bg:
        info["background_scripts"].append(bg["service_worker"].lstrip("/"))

    # popup
    for key in ("browser_action", "page_action", "action"):
        popup = manifest.get(key, {}).get("default_popup", "")
        if popup:
            info["background_scripts"].append(popup.lstrip("/"))

    # web_accessible_resources (MV2: list of strings; MV3: list of dicts)
    war = manifest.get("web_accessible_resources", [])
    if war and isinstance(war[0], dict):
        for entry in war:
            info["web_accessible"].extend(entry.get("resources", []))
    else:
        info["web_accessible"].extend(war)

    return info


# ─────────────────────────────────────────────────────────────────────────────
# 3. PERMISSION RISK TABLE  (60+ entries)
# ─────────────────────────────────────────────────────────────────────────────

PERM_RISK = {
    # name: (severity, explanation)
    # --- CRITICAL ---
    "debugger":                ("CRITICAL", "Attaches debugger to any tab; full JS access, network interception"),
    "nativeMessaging":         ("CRITICAL", "Communicates with native host applications on the OS"),
    "proxy":                   ("CRITICAL", "Redirects all browser traffic through attacker-controlled proxy"),
    "webRequestBlocking":      ("CRITICAL", "Blocks or modifies any HTTP request before it is sent"),
    "<all_urls>":              ("CRITICAL", "Matches every URL — unrestricted cross-origin access"),
    "*://*/*":                 ("CRITICAL", "Matches all http/https/ws/wss URLs — unrestricted access"),
    "http://*/*":              ("CRITICAL", "Unrestricted HTTP access to all sites"),
    "https://*/*":             ("CRITICAL", "Unrestricted HTTPS access to all sites"),

    # --- HIGH ---
    "webRequest":              ("HIGH",     "Intercepts all HTTP/HTTPS requests and responses"),
    "cookies":                 ("HIGH",     "Read/write cookies for any domain matched by host permissions"),
    "downloads":               ("HIGH",     "Create and manage file downloads"),
    "history":                 ("HIGH",     "Read and modify full browsing history"),
    "tabs":                    ("HIGH",     "Access URL, title, favicons of all tabs; duplicate/move/close"),
    "bookmarks":               ("HIGH",     "Read, create, and delete bookmarks"),
    "management":              ("HIGH",     "List, enable, disable, or uninstall other extensions"),
    "clipboardRead":           ("HIGH",     "Read the system clipboard at any time"),
    "clipboardWrite":          ("HIGH",     "Write arbitrary content to the system clipboard"),
    "privacy":                 ("HIGH",     "Control privacy settings: tracking protection, referrer, etc."),
    "system.display":          ("HIGH",     "Read and modify display configuration"),
    "tts":                     ("HIGH",     "Use text-to-speech — can read page content aloud"),
    "contentSettings":         ("HIGH",     "Override per-site content settings (JS, plugins, cookies)"),
    "declarativeNetRequest":   ("HIGH",     "Block/redirect/modify network requests via rules"),
    "declarativeNetRequestWithHostAccess": ("HIGH", "Block/redirect/modify network requests (with host access)"),
    "pageCapture":             ("HIGH",     "Save an entire page as MHTML"),
    "browsingData":            ("HIGH",     "Clear browsing data: history, cookies, cache, passwords"),
    "fileBrowserHandler":      ("HIGH",     "Handle files from the ChromeOS file browser"),
    "fileSystem":              ("HIGH",     "Read and write files on user's filesystem (Chrome Apps)"),
    "desktopCapture":          ("HIGH",     "Capture screen, window, or tab video"),
    "tabCapture":              ("HIGH",     "Capture audio/video of a tab"),

    # --- MEDIUM ---
    "activeTab":               ("MEDIUM",   "Access URL/DOM of the active tab when user invokes extension"),
    "alarms":                  ("MEDIUM",   "Schedule code to run at a future time or periodically"),
    "background":              ("MEDIUM",   "Keep extension alive as a background process"),
    "contextMenus":            ("MEDIUM",   "Add items to the browser right-click context menu"),
    "declarativeContent":      ("MEDIUM",   "Show/hide page action based on page content"),
    "geolocation":             ("MEDIUM",   "Request user's geographic location"),
    "identity":                ("MEDIUM",   "Get OAuth2 tokens for signed-in Google account"),
    "idle":                    ("MEDIUM",   "Detect when user is idle"),
    "notifications":           ("MEDIUM",   "Display desktop notifications"),
    "sessions":                ("MEDIUM",   "Query and restore recently closed tabs and windows"),
    "storage":                 ("MEDIUM",   "Store and retrieve extension data (local and sync)"),
    "unlimitedStorage":        ("MEDIUM",   "No quota limit on extension storage"),
    "webNavigation":           ("MEDIUM",   "Monitor navigation events for all tabs"),
    "windows":                 ("MEDIUM",   "Create, modify, and rearrange browser windows"),
    "fontSettings":            ("MEDIUM",   "Read and modify browser font settings"),
    "inputIme":                ("MEDIUM",   "Implement custom IME — intercepts all typed text"),
    "platformKeys":            ("MEDIUM",   "Access platform key store for client certificates"),
    "topSites":                ("MEDIUM",   "Read the user's most visited sites"),
    "ttsEngine":               ("MEDIUM",   "Implement a TTS engine — receives all text to be spoken"),

    # --- LOW ---
    "contextMenus":            ("LOW",      "Add items to right-click context menu"),
    "i18n":                    ("LOW",      "Internationalize the extension"),
    "runtime":                 ("LOW",      "Access extension runtime info; message passing within extension"),
    "scripting":               ("LOW",      "Inject scripts/CSS into pages (requires host permission)"),
    "action":                  ("LOW",      "Control the extension toolbar button"),
    "sidePanel":               ("LOW",      "Show content in the browser side panel"),
    "offscreen":               ("LOW",      "Create hidden offscreen documents"),
    "commands":                ("LOW",      "Register keyboard shortcuts"),
}


def score_permission(perm):
    """Return (severity, explanation) for a permission string."""
    # Direct lookup
    if perm in PERM_RISK:
        return PERM_RISK[perm]

    # Host permission patterns
    if perm.startswith("http://") or perm.startswith("https://") or perm.startswith("*://"):
        if perm in ("<all_urls>", "*://*/*", "http://*/*", "https://*/*"):
            return ("CRITICAL", "Unrestricted cross-origin access")
        if "/*" in perm:
            return ("HIGH", f"Cross-origin access to all paths on {perm}")
        return ("MEDIUM", f"Cross-origin access to specific origin: {perm}")

    if perm.startswith("file://"):
        return ("HIGH", "Access to local files via file:// — reads user filesystem")

    # Unknown
    return ("INFO", "Unknown permission — review manually")


# ─────────────────────────────────────────────────────────────────────────────
# 4. HOST PERMISSION SCORING
# ─────────────────────────────────────────────────────────────────────────────

def score_host_permissions(host_perms):
    """Return list of (perm, severity, explanation)."""
    results = []
    for hp in host_perms:
        sev, expl = score_permission(hp)
        results.append((hp, sev, expl))
    return results


# ─────────────────────────────────────────────────────────────────────────────
# 5. CONTENT SCRIPT / JS FILE AUDIT
# ─────────────────────────────────────────────────────────────────────────────

CODE_PATTERNS = [
    ("eval_usage",          "HIGH",     re.compile(r'\beval\s*\('),                                           "eval() — dynamic code execution"),
    ("new_function",        "HIGH",     re.compile(r'\bnew\s+Function\s*\('),                                 "new Function() — dynamic code execution"),
    ("document_write",      "MEDIUM",   re.compile(r'\bdocument\.write\s*\('),                                "document.write() — DOM injection"),
    ("innerHTML_assign",    "HIGH",     re.compile(r'\.innerHTML\s*[+]?=\s*(?![\s]*["\'](?:[^"\'<>]{0,120})["\'])'), "innerHTML = (non-const) — DOM injection"),
    ("outerHTML_assign",    "HIGH",     re.compile(r'\.outerHTML\s*[+]?=\s*(?![\s]*["\'](?:[^"\'<>]{0,120})["\'])'), "outerHTML = (non-const) — DOM injection"),
    ("insertAdjacentHTML",  "HIGH",     re.compile(r'\.insertAdjacentHTML\s*\('),                             "insertAdjacentHTML() — DOM injection"),
    ("fetch_external",      "MEDIUM",   re.compile(r'\bfetch\s*\(\s*["\']https?://'),                         "fetch() to hardcoded external URL"),
    ("xhr_open_external",   "MEDIUM",   re.compile(r'\.open\s*\(\s*["\'][A-Z]+["\'],\s*["\']https?://'),      "XHR.open() to external URL"),
    ("password_query",      "HIGH",     re.compile(r'querySelectorAll?\s*\(\s*["\']input\[type=["\']?password', re.I), "Password field query — credential theft"),
    ("password_value",      "HIGH",     re.compile(r'(?:password|pwd|passwd)\w*\s*\.value\b', re.I),          "Reading password field .value"),
    ("exec_script_tabs",    "HIGH",     re.compile(r'chrome\.tabs\.executeScript\s*\('),                      "chrome.tabs.executeScript() — script injection"),
    ("exec_script_api",     "HIGH",     re.compile(r'chrome\.scripting\.executeScript\s*\('),                 "chrome.scripting.executeScript() — script injection"),
    ("mining_coinhive",     "CRITICAL", re.compile(r'CoinHive|coinhive', re.I),                               "CoinHive crypto mining library"),
    ("mining_cryptonight",  "CRITICAL", re.compile(r'cryptonight|wasm_miner', re.I),                         "cryptonight / wasm_miner mining pattern"),
    ("mining_api",          "CRITICAL", re.compile(r'\.mine\(\)|startMining\b|hashesPerSecond', re.I),        "Mining API call"),
    ("keylogging_keydown",  "HIGH",     re.compile(r'addEventListener\s*\(\s*["\']keydown["\']'),             "addEventListener('keydown') — keylogger"),
    ("keylogging_keypress", "HIGH",     re.compile(r'addEventListener\s*\(\s*["\']keypress["\']'),            "addEventListener('keypress') — keylogger"),
    ("beaconing_interval",  "MEDIUM",   re.compile(r'setInterval\s*\([^;]{0,200}(?:fetch\s*\(|XMLHttpRequest|\.send\s*\()', re.S), "setInterval + network call — beaconing"),
    ("beaconing_timeout",   "MEDIUM",   re.compile(r'setTimeout\s*\([^;]{0,200}(?:fetch\s*\(|XMLHttpRequest|\.send\s*\()', re.S),  "setTimeout + network call — beaconing"),
    ("atob_exec",           "HIGH",     re.compile(r'atob\s*\('),                                             "atob() base64 decode — possible obfuscated payload"),
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def collect_all_js(files, manifest):
    """Return set of JS filenames to audit."""
    scripts = set()
    for cs in manifest.get("content_scripts", []):
        for js in cs.get("js", []):
            scripts.add(js.lstrip("/"))
    bg = manifest.get("background", {})
    for js in bg.get("scripts", []):
        scripts.add(js.lstrip("/"))
    if "service_worker" in bg:
        scripts.add(bg["service_worker"].lstrip("/"))
    for key in ("browser_action", "page_action", "action"):
        popup = manifest.get(key, {}).get("default_popup", "")
        if popup:
            popup = popup.lstrip("/")
            if popup.endswith(".html") and popup in files:
                html_src = files[popup].decode("utf-8", errors="replace")
                for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js)["\']', html_src, re.I):
                    scripts.add(m.group(1).lstrip("/"))
            elif popup in files:
                scripts.add(popup)
    return {s for s in scripts if s in files}


def scan_js_files(files, manifest):
    """Return list of finding dicts."""
    findings = []
    for script in sorted(collect_all_js(files, manifest)):
        content = files[script].decode("utf-8", errors="replace")
        for lineno, line in enumerate(content.splitlines(), 1):
            for name, severity, regex, description in CODE_PATTERNS:
                if regex.search(line):
                    findings.append({
                        "file":     script,
                        "line":     lineno,
                        "severity": severity,
                        "pattern":  name,
                        "snippet":  line.strip()[:120],
                        "description": description,
                    })
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# 6. NETWORK ENDPOINT INVENTORY
# ─────────────────────────────────────────────────────────────────────────────

URL_RE     = re.compile(r'["\']((https?|ftp|wss?)://[^\s"\'<>\\]{5,})["\']')
B64_RE     = re.compile(r'["\']([A-Za-z0-9+/]{24,}={0,2})["\']')
IP_ONLY_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

TRUSTED_SUFFIXES = (
    ".googleapis.com", ".gstatic.com", ".google.com", ".google-analytics.com",
    ".mozilla.org", ".firefox.com", ".microsoft.com",
    "cdnjs.cloudflare.com", ".jquery.com", ".jsdelivr.net", ".unpkg.com", ".w3.org",
)
SUSPICIOUS_TLDS = {
    ".xyz",".tk",".pw",".ml",".ga",".cf",".gq",
    ".top",".work",".click",".bid",".stream",".racing",".download",
    ".accountant",".loan",".win",".trade",".party",".science",
}


def _hostname(url):
    try:
        after = url.split("://",1)[1]
        return after.split("/")[0].split("?")[0].split(":")[0].lower()
    except Exception:
        return url.lower()


def classify_url(url):
    if url.startswith(("chrome-extension://","moz-extension://")):
        return "INTERNAL"
    host = _hostname(url)
    for s in TRUSTED_SUFFIXES:
        if host == s.lstrip(".") or host.endswith(s):
            return "TRUSTED"
    if re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', host):
        return "SUSPICIOUS_IP"
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            return "SUSPICIOUS_TLD"
    return "EXTERNAL"


def extract_network_endpoints(files):
    """Return list of {url, category, file, line}."""
    endpoints = {}
    for filename, data in files.items():
        if not (filename.endswith(".js") or filename.endswith(".json")):
            continue
        content = data.decode("utf-8", errors="replace")
        lines   = content.splitlines()
        for lineno, line in enumerate(lines, 1):
            for m in URL_RE.finditer(line):
                url = m.group(1)
                if url not in endpoints:
                    endpoints[url] = {"url": url, "category": classify_url(url),
                                      "sources": []}
                endpoints[url]["sources"].append(f"{filename}:{lineno}")
        # b64 pass
        for m in B64_RE.finditer(content):
            try:
                decoded = base64.b64decode(m.group(1)+"==").decode("utf-8", errors="strict")
                for um in URL_RE.finditer(f'"{decoded}"'):
                    url = um.group(1)
                    if url not in endpoints:
                        endpoints[url] = {"url": url, "category": "SUSPICIOUS_B64",
                                          "sources": [f"{filename}:b64"]}
            except Exception:
                pass
    return list(endpoints.values())


# ─────────────────────────────────────────────────────────────────────────────
# 7. OVERALL RISK SCORE
# ─────────────────────────────────────────────────────────────────────────────

def compute_risk(perm_results, host_results, code_findings, endpoints):
    """Return (score_label, reasoning)."""
    sev_counts = defaultdict(int)
    for _, sev, _ in perm_results:
        sev_counts[sev] += 1
    for _, sev, _ in host_results:
        sev_counts[sev] += 1
    for f in code_findings:
        sev_counts[f["severity"]] += 1
    for ep in endpoints:
        if "SUSPICIOUS" in ep["category"]:
            sev_counts["HIGH"] += 1

    reasons = []
    if sev_counts["CRITICAL"]:
        reasons.append(f"{sev_counts['CRITICAL']} CRITICAL finding(s) (crypto miner, debugger, proxy, or unrestricted host access)")
    if sev_counts["HIGH"]:
        reasons.append(f"{sev_counts['HIGH']} HIGH finding(s) (script injection, credential access, data exfil patterns)")
    if sev_counts["MEDIUM"]:
        reasons.append(f"{sev_counts['MEDIUM']} MEDIUM finding(s) (external fetches, broad permissions)")

    if sev_counts["CRITICAL"]:
        label = "CRITICAL"
    elif sev_counts["HIGH"] >= 3:
        label = "HIGH"
    elif sev_counts["HIGH"] >= 1:
        label = "MEDIUM-HIGH"
    elif sev_counts["MEDIUM"] >= 3:
        label = "MEDIUM"
    elif sev_counts["MEDIUM"] >= 1:
        label = "LOW-MEDIUM"
    else:
        label = "LOW"

    recommendation = (
        "CRITICAL: Do NOT install or use this extension. Remove immediately if installed. "
        "Report to browser vendor." if label == "CRITICAL" else
        "HIGH: Exercise extreme caution. Review all high-severity findings before use." if label == "HIGH" else
        "MEDIUM-HIGH: Multiple elevated findings. Requires thorough code review." if label == "MEDIUM-HIGH" else
        "MEDIUM: Some findings require attention. Review before using in sensitive contexts." if label == "MEDIUM" else
        "LOW-MEDIUM: Minor findings detected. Low overall risk but confirm intent." if label == "LOW-MEDIUM" else
        "LOW: No significant security concerns detected."
    )

    return label, "; ".join(reasons) if reasons else "No significant issues found.", recommendation


# ─────────────────────────────────────────────────────────────────────────────
# 8. TEXT OUTPUT (colored ANSI)
# ─────────────────────────────────────────────────────────────────────────────

USE_COLOR = sys.stdout.isatty()
_C = {
    "CRITICAL":    "\033[1;91m",
    "HIGH":        "\033[91m",
    "MEDIUM-HIGH": "\033[91m",
    "MEDIUM":      "\033[93m",
    "LOW-MEDIUM":  "\033[93m",
    "LOW":         "\033[92m",
    "TRUSTED":     "\033[92m",
    "EXTERNAL":    "\033[93m",
    "SUSPICIOUS_IP":  "\033[1;91m",
    "SUSPICIOUS_TLD": "\033[1;91m",
    "SUSPICIOUS_B64": "\033[1;91m",
    "INTERNAL":    "\033[96m",
    "INFO":        "\033[96m",
}
_R = "\033[0m"


def _col(key, text):
    return f"{_C.get(key,'')}{text}{_R}" if USE_COLOR else text


def print_text_report(info, perm_results, host_results, code_findings, endpoints, risk_label, risk_reason, recommendation):
    W = 72
    print(f"\n{'='*W}")
    print(f"  Browser Extension Security Report")
    print(f"{'='*W}")
    print(f"  Name             : {info['name']}")
    print(f"  Version          : {info['version']}")
    print(f"  Manifest version : {info['manifest_version']}")
    if info["description"]:
        print(f"  Description      : {info['description'][:80]}")
    print(f"  Risk Score       : {_col(risk_label, risk_label)}")
    print(f"  Reason           : {risk_reason}")
    print(f"  Recommendation   : {recommendation}")

    # Permissions
    print(f"\n{'─'*W}")
    print("  PERMISSIONS")
    print(f"{'─'*W}")
    if not perm_results and not host_results:
        print("  (none)")
    for perm, sev, expl in sorted(perm_results, key=lambda x: SEVERITY_ORDER.get(x[1], 9)):
        print(f"  {_col(sev, f'[{sev}]'):<30} {perm}")
        print(f"    {expl}")
    if host_results:
        print(f"\n  Host Permissions:")
        for hp, sev, expl in sorted(host_results, key=lambda x: SEVERITY_ORDER.get(x[1], 9)):
            print(f"  {_col(sev, f'[{sev}]'):<30} {hp}")
            print(f"    {expl}")

    # Code findings
    print(f"\n{'─'*W}")
    print("  CODE FINDINGS")
    print(f"{'─'*W}")
    if not code_findings:
        print(f"  {_col('TRUSTED','[+] No dangerous patterns detected.')}")
    else:
        for f in sorted(code_findings, key=lambda x: SEVERITY_ORDER.get(x["severity"], 9)):
            sev = f["severity"]
            print(f"  {f['file']}:{f['line']}: {_col(sev, '['+sev+']')} {f['pattern']}")
            print(f"    {f['description']}")
            print(f"    ↳ {f['snippet']}")

    # Network endpoints
    print(f"\n{'─'*W}")
    print("  NETWORK ENDPOINTS")
    print(f"{'─'*W}")
    if not endpoints:
        print("  (none found)")
    else:
        print(f"  {'URL':<52} {'CATEGORY':<20} SOURCE")
        print(f"  {'─'*52} {'─'*20} {'─'*20}")
        for ep in sorted(endpoints, key=lambda x: x["category"]):
            url = ep["url"][:50] + ".." if len(ep["url"]) > 52 else ep["url"]
            cat = ep["category"]
            src = ep["sources"][0] if ep["sources"] else ""
            print(f"  {url:<52} {_col(cat, cat):<20} {src}")

    # Severity summary
    sev_counts = defaultdict(int)
    for f in code_findings:
        sev_counts[f["severity"]] += 1
    for _, sev, _ in perm_results:
        sev_counts[sev] += 1
    print(f"\n{'─'*W}")
    print("  SUMMARY")
    print(f"{'─'*W}")
    for sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
        if sev_counts[sev]:
            print(f"  {_col(sev, sev):<40} {sev_counts[sev]}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# 9. JSON OUTPUT
# ─────────────────────────────────────────────────────────────────────────────

def build_json_report(info, perm_results, host_results, code_findings, endpoints, risk_label, risk_reason, recommendation):
    return {
        "name":             info["name"],
        "version":          info["version"],
        "manifest_version": info["manifest_version"],
        "description":      info["description"],
        "permissions": [
            {"name": p, "risk": s, "explanation": e}
            for p, s, e in perm_results
        ],
        "host_permissions": [
            {"pattern": p, "risk": s, "explanation": e}
            for p, s, e in host_results
        ],
        "findings": [
            {
                "file":        f["file"],
                "line":        f["line"],
                "severity":    f["severity"],
                "pattern":     f["pattern"],
                "description": f["description"],
                "snippet":     f["snippet"],
            }
            for f in code_findings
        ],
        "network_endpoints": endpoints,
        "score":          risk_label,
        "score_reason":   risk_reason,
        "recommendation": recommendation,
    }


# ─────────────────────────────────────────────────────────────────────────────
# 10. HTML OUTPUT
# ─────────────────────────────────────────────────────────────────────────────

_SEV_HTML_COLOR = {
    "CRITICAL":    "#e53935",
    "HIGH":        "#e65100",
    "MEDIUM-HIGH": "#f57c00",
    "MEDIUM":      "#f9a825",
    "LOW-MEDIUM":  "#9e9d24",
    "LOW":         "#2e7d32",
    "TRUSTED":     "#2e7d32",
    "EXTERNAL":    "#f9a825",
    "SUSPICIOUS_IP":  "#e53935",
    "SUSPICIOUS_TLD": "#e53935",
    "SUSPICIOUS_B64": "#e53935",
    "INTERNAL":    "#0277bd",
    "INFO":        "#0277bd",
}


def _esc(s):
    return html_module.escape(str(s))


def build_html_report(info, perm_results, host_results, code_findings, endpoints, risk_label, risk_reason, recommendation):
    risk_color  = _SEV_HTML_COLOR.get(risk_label, "#555")

    perm_rows = "".join(
        f"<tr><td><span class='badge' style='background:{_SEV_HTML_COLOR.get(s,'#888')}'>{_esc(s)}</span></td>"
        f"<td><code>{_esc(p)}</code></td><td>{_esc(e)}</td></tr>"
        for p, s, e in sorted(perm_results, key=lambda x: SEVERITY_ORDER.get(x[1], 9))
    )
    host_rows = "".join(
        f"<tr><td><span class='badge' style='background:{_SEV_HTML_COLOR.get(s,'#888')}'>{_esc(s)}</span></td>"
        f"<td><code>{_esc(p)}</code></td><td>{_esc(e)}</td></tr>"
        for p, s, e in sorted(host_results, key=lambda x: SEVERITY_ORDER.get(x[1], 9))
    )

    finding_cards = ""
    for f in sorted(code_findings, key=lambda x: SEVERITY_ORDER.get(x["severity"], 9)):
        color = _SEV_HTML_COLOR.get(f["severity"], "#888")
        finding_cards += (
            f"<div class='finding' style='border-left:4px solid {color}'>"
            f"<div class='finding-header'>"
            f"<span class='badge' style='background:{color}'>{_esc(f['severity'])}</span>"
            f" <strong>{_esc(f['pattern'])}</strong>"
            f" — <em>{_esc(f['file'])}:{f['line']}</em></div>"
            f"<div class='finding-desc'>{_esc(f['description'])}</div>"
            f"<pre class='snippet'>{_esc(f['snippet'])}</pre>"
            f"</div>"
        )

    ep_rows = "".join(
        f"<tr><td style='color:{_SEV_HTML_COLOR.get(ep[\"category\"],\"#333\")}'><code>{_esc(ep['url'][:80])}</code></td>"
        f"<td><span class='badge' style='background:{_SEV_HTML_COLOR.get(ep[\"category\"],\"#888\")}'>{_esc(ep['category'])}</span></td>"
        f"<td><small>{_esc(ep['sources'][0] if ep['sources'] else '')}</small></td></tr>"
        for ep in sorted(endpoints, key=lambda x: x["category"])
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Extension Audit: {_esc(info['name'])}</title>
<style>
  body{{font-family:system-ui,sans-serif;max-width:960px;margin:0 auto;padding:24px;background:#f5f5f5;color:#212121}}
  h1{{color:#1a237e;border-bottom:3px solid #1a237e;padding-bottom:8px}}
  h2{{color:#1a237e;margin-top:32px;border-bottom:1px solid #9fa8da}}
  .score-badge{{display:inline-block;padding:6px 18px;border-radius:4px;color:#fff;font-weight:bold;font-size:1.1em;background:{risk_color}}}
  .card{{background:#fff;border-radius:6px;padding:16px 20px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,.15)}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:3px;color:#fff;font-size:.75em;font-weight:bold;vertical-align:middle}}
  table{{width:100%;border-collapse:collapse;margin-top:8px}}
  th{{background:#1a237e;color:#fff;padding:6px 10px;text-align:left;font-size:.85em}}
  td{{padding:5px 10px;border-bottom:1px solid #e0e0e0;font-size:.85em;vertical-align:top}}
  tr:hover td{{background:#e8eaf6}}
  .finding{{background:#fff;border-radius:4px;padding:12px 16px;margin-bottom:10px;box-shadow:0 1px 2px rgba(0,0,0,.1)}}
  .finding-header{{margin-bottom:4px}}
  .finding-desc{{color:#555;font-size:.85em;margin:4px 0}}
  pre.snippet{{background:#212121;color:#80cbc4;padding:8px 12px;border-radius:3px;font-size:.8em;overflow-x:auto;margin:6px 0 0}}
  code{{background:#e8eaf6;padding:1px 4px;border-radius:2px;font-size:.9em}}
  .info-grid{{display:grid;grid-template-columns:160px 1fr;gap:4px 12px;font-size:.9em}}
  .info-grid .label{{font-weight:bold;color:#555}}
</style>
</head>
<body>
<h1>Browser Extension Security Audit</h1>

<div class="card">
  <div class="info-grid">
    <span class="label">Name</span><span>{_esc(info['name'])}</span>
    <span class="label">Version</span><span>{_esc(info['version'])}</span>
    <span class="label">Manifest</span><span>v{_esc(str(info['manifest_version']))}</span>
    <span class="label">Risk Score</span><span><span class="score-badge">{_esc(risk_label)}</span></span>
    <span class="label">Reason</span><span>{_esc(risk_reason)}</span>
    <span class="label">Recommendation</span><span>{_esc(recommendation)}</span>
  </div>
</div>

<h2>Permissions</h2>
<table>
  <tr><th>Risk</th><th>Permission</th><th>Explanation</th></tr>
  {perm_rows if perm_rows else '<tr><td colspan="3"><em>None declared</em></td></tr>'}
</table>

{('<h2>Host Permissions</h2><table><tr><th>Risk</th><th>Pattern</th><th>Explanation</th></tr>' + host_rows + '</table>') if host_rows else ''}

<h2>Code Findings ({len(code_findings)})</h2>
{finding_cards if finding_cards else '<p style="color:#2e7d32"><strong>No dangerous patterns detected.</strong></p>'}

<h2>Network Endpoints ({len(endpoints)})</h2>
<table>
  <tr><th>URL</th><th>Category</th><th>Source</th></tr>
  {ep_rows if ep_rows else '<tr><td colspan="3"><em>None found</em></td></tr>'}
</table>

<p style="margin-top:40px;font-size:.75em;color:#9e9e9e">
  Generated by ext_auditor.py — Browser Extension Security Auditor
</p>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    args     = sys.argv[1:]
    fmt      = "text"
    out_file = None

    # parse flags
    filtered = []
    i = 0
    while i < len(args):
        if args[i] == "--format" and i + 1 < len(args):
            fmt = args[i+1].lower()
            i  += 2
        elif args[i] == "-o" and i + 1 < len(args):
            out_file = args[i+1]
            i       += 2
        else:
            filtered.append(args[i])
            i += 1

    if not filtered:
        print("Usage: python ext_auditor.py [--format text|json|html] [-o output.html] <dir|zip|crx|xpi>")
        sys.exit(1)

    ext_path = filtered[0]

    # Load
    files    = load_extension(ext_path)
    manifest = parse_manifest(files)
    info     = extract_info(manifest)

    # Analyze
    perm_results  = [(p, *score_permission(p)) for p in info["permissions"]]
    host_results  = score_host_permissions(info["host_permissions"])

    # Also score any host-like permissions from MV2 permissions list
    extra_hosts = [p for p in info["permissions"] if p.startswith(("http://","https://","*://","<all","file://"))]
    extra_host_results = [(p, *score_permission(p)) for p in extra_hosts]
    # Merge and deduplicate
    all_perm_results = [(p, s, e) for p, s, e in perm_results if not p.startswith(("http://","https://","*://","<all","file://"))]
    all_host_results = host_results + extra_host_results

    code_findings = scan_js_files(files, manifest)
    endpoints     = extract_network_endpoints(files)
    risk_label, risk_reason, recommendation = compute_risk(
        all_perm_results, all_host_results, code_findings, endpoints
    )

    if fmt == "json":
        report = build_json_report(info, all_perm_results, all_host_results,
                                   code_findings, endpoints, risk_label, risk_reason, recommendation)
        output = json.dumps(report, indent=2)
        if out_file:
            Path(out_file).write_text(output, encoding="utf-8")
            print(f"[+] JSON report saved to {out_file}")
        else:
            print(output)

    elif fmt == "html":
        output = build_html_report(info, all_perm_results, all_host_results,
                                   code_findings, endpoints, risk_label, risk_reason, recommendation)
        target = out_file or "ext_audit_report.html"
        Path(target).write_text(output, encoding="utf-8")
        print(f"[+] HTML report saved to {target}")

    else:
        print_text_report(info, all_perm_results, all_host_results,
                          code_findings, endpoints, risk_label, risk_reason, recommendation)


if __name__ == "__main__":
    main()
