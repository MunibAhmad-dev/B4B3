#!/usr/bin/env python3
"""
sol03_content_script_audit.py — Browser Extension Content Script Auditor
Usage: python sol03.py <extension_dir_or_zip_or_crx>

Scans all JavaScript files referenced in manifest content_scripts, background,
and popup sections for dangerous patterns and reports findings with severity.
"""

import sys
import re
import json
import zipfile
import struct
import io
from pathlib import Path
from collections import defaultdict

# ─────────────────────────────────────────────────────────────────────────────
# CRX / ZIP / Directory loader
# ─────────────────────────────────────────────────────────────────────────────

def load_extension(path):
    """Return dict {filename: bytes} for a dir, .zip, .crx (v2/v3), or .xpi."""
    path = Path(path)
    if not path.exists():
        sys.exit(f"[!] Path not found: {path}")

    if path.is_dir():
        files = {}
        for f in path.rglob("*"):
            if f.is_file():
                rel = str(f.relative_to(path)).replace("\\", "/")
                files[rel] = f.read_bytes()
        return files

    raw = path.read_bytes()

    # CRX2/CRX3: magic = b'Cr24' (0x43723234)
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
            zip_start = 16  # unknown version, best-effort
        raw = raw[zip_start:]

    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            return {name: zf.read(name) for name in zf.namelist()}
    except zipfile.BadZipFile:
        sys.exit(f"[!] Cannot open as zip/crx: {path}")


def parse_manifest(files):
    """Parse manifest.json from extension file dict."""
    if "manifest.json" not in files:
        sys.exit("[!] No manifest.json found in extension.")
    try:
        return json.loads(files["manifest.json"].decode("utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        sys.exit(f"[!] manifest.json parse error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Script collector
# ─────────────────────────────────────────────────────────────────────────────

def _scripts_from_html(html_bytes, files):
    """Extract JS src paths from an HTML file."""
    html = html_bytes.decode("utf-8", errors="replace")
    found = set()
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js)["\']', html, re.I):
        js = m.group(1).lstrip("/")
        if js in files:
            found.add(js)
    return found


def collect_scripts(manifest, files):
    """Return sorted list of JS filenames to audit."""
    scripts = set()

    # content_scripts array
    for cs_block in manifest.get("content_scripts", []):
        for js in cs_block.get("js", []):
            scripts.add(js.lstrip("/"))

    # background (MV2: scripts list; MV3: service_worker string)
    bg = manifest.get("background", {})
    for js in bg.get("scripts", []):
        scripts.add(js.lstrip("/"))
    if "service_worker" in bg:
        scripts.add(bg["service_worker"].lstrip("/"))

    # popup / action
    for key in ("browser_action", "page_action", "action"):
        popup = manifest.get(key, {}).get("default_popup", "")
        if popup:
            popup = popup.lstrip("/")
            if popup.endswith(".html") and popup in files:
                scripts |= _scripts_from_html(files[popup], files)
            elif popup in files:
                scripts.add(popup)

    # options page
    for key in ("options_page",):
        page = manifest.get(key, "").lstrip("/")
        if page:
            if page.endswith(".html") and page in files:
                scripts |= _scripts_from_html(files[page], files)
            elif page in files:
                scripts.add(page)
    opts_ui_page = manifest.get("options_ui", {}).get("page", "").lstrip("/")
    if opts_ui_page:
        if opts_ui_page.endswith(".html") and opts_ui_page in files:
            scripts |= _scripts_from_html(files[opts_ui_page], files)
        elif opts_ui_page in files:
            scripts.add(opts_ui_page)

    # keep only files that actually exist in the archive
    return sorted(s for s in scripts if s in files)


# ─────────────────────────────────────────────────────────────────────────────
# Dangerous pattern definitions
# ─────────────────────────────────────────────────────────────────────────────

PATTERNS = [
    # (name, severity, compiled_regex, human_description)

    # --- Dynamic code execution ---
    ("eval_usage",
     "HIGH",
     re.compile(r'\beval\s*\('),
     "Dynamic code execution via eval()"),

    ("new_function",
     "HIGH",
     re.compile(r'\bnew\s+Function\s*\('),
     "Dynamic code execution via new Function()"),

    # --- DOM injection ---
    ("document_write",
     "MEDIUM",
     re.compile(r'\bdocument\.write\s*\('),
     "DOM injection via document.write()"),

    ("innerHTML_assign",
     "HIGH",
     # match .innerHTML = or .innerHTML += but not .innerHTML = "constant"
     re.compile(r'\.innerHTML\s*[+]?=\s*(?![\s]*["\'](?:[^"\'<>]{0,120})["\'])'),
     "DOM injection via innerHTML with non-constant right-hand side"),

    ("outerHTML_assign",
     "HIGH",
     re.compile(r'\.outerHTML\s*[+]?=\s*(?![\s]*["\'](?:[^"\'<>]{0,120})["\'])'),
     "DOM injection via outerHTML with non-constant right-hand side"),

    ("insertAdjacentHTML",
     "HIGH",
     re.compile(r'\.insertAdjacentHTML\s*\('),
     "DOM injection via insertAdjacentHTML()"),

    # --- External network calls ---
    ("fetch_external",
     "MEDIUM",
     re.compile(r'\bfetch\s*\(\s*["\']https?://'),
     "External fetch() call to hardcoded URL"),

    ("xhr_open_external",
     "MEDIUM",
     re.compile(r'\.open\s*\(\s*["\'][A-Z]+["\'],\s*["\']https?://'),
     "XMLHttpRequest.open() to external URL"),

    ("sendMessage_ext_id",
     "MEDIUM",
     re.compile(r'chrome\.runtime\.sendMessage\s*\(\s*["\'][a-z0-9]{32}["\']'),
     "chrome.runtime.sendMessage to external extension ID"),

    # --- Password / credential theft ---
    ("password_queryselector",
     "HIGH",
     re.compile(r'querySelectorAll?\s*\(\s*["\']input\[type=["\']?password["\']?\]["\']', re.I),
     "Querying password input fields — potential credential theft"),

    ("password_value_read",
     "HIGH",
     re.compile(r'(?:password|pwd|passwd)\w*\s*(?:\.\s*value\b|\[["\']\s*value\s*["\']\])', re.I),
     "Reading .value from password-related variable — potential credential theft"),

    # --- Dynamic script injection ---
    ("tabs_executeScript",
     "HIGH",
     re.compile(r'chrome\.tabs\.executeScript\s*\('),
     "Dynamic script injection via chrome.tabs.executeScript()"),

    ("scripting_executeScript",
     "HIGH",
     re.compile(r'chrome\.scripting\.executeScript\s*\('),
     "Dynamic script injection via chrome.scripting.executeScript()"),

    # --- Crypto mining ---
    ("mining_coinhive",
     "CRITICAL",
     re.compile(r'CoinHive|coinhive', re.I),
     "Crypto mining library — CoinHive reference detected"),

    ("mining_cryptonight",
     "CRITICAL",
     re.compile(r'cryptonight|wasm_miner|asm\.js.*miner', re.I),
     "Crypto mining pattern — cryptonight / wasm_miner"),

    ("mining_api_calls",
     "CRITICAL",
     re.compile(r'\.mine\(\)|startMining\b|stopMining\b|hashesPerSecond', re.I),
     "Crypto mining API call — mine() / startMining / hashesPerSecond"),

    # --- Keylogging ---
    ("keylogging_keydown",
     "HIGH",
     re.compile(r'addEventListener\s*\(\s*["\']keydown["\']'),
     "addEventListener('keydown') — potential keylogger"),

    ("keylogging_keypress",
     "HIGH",
     re.compile(r'addEventListener\s*\(\s*["\']keypress["\']'),
     "addEventListener('keypress') — potential keylogger"),

    ("keylogging_input_value",
     "HIGH",
     re.compile(r'addEventListener\s*\(\s*["\']input["\'][^)]*\).*?\.value\b', re.S),
     "Input event listener with .value access — potential keylogger"),

    # --- Beaconing (setInterval / setTimeout with network) ---
    ("beaconing_setinterval",
     "MEDIUM",
     re.compile(r'setInterval\s*\([^;]{0,200}(?:fetch\s*\(|new\s+XMLHttpRequest|\.send\s*\()', re.S),
     "setInterval with network call inside — potential beaconing pattern"),

    ("beaconing_settimeout",
     "MEDIUM",
     re.compile(r'setTimeout\s*\([^;]{0,200}(?:fetch\s*\(|new\s+XMLHttpRequest|\.send\s*\()', re.S),
     "setTimeout with network call inside — potential beaconing pattern"),

    # --- Obfuscated execution ---
    ("atob_eval",
     "HIGH",
     re.compile(r'atob\s*\(', ),
     "atob() base64 decode — check if result is eval()'d or injected"),
]

# ─────────────────────────────────────────────────────────────────────────────
# Output helpers
# ─────────────────────────────────────────────────────────────────────────────

SEVERITY_ORDER  = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLORS = {
    "CRITICAL": "\033[1;91m",
    "HIGH":     "\033[91m",
    "MEDIUM":   "\033[93m",
    "LOW":      "\033[94m",
    "INFO":     "\033[96m",
}
RESET = "\033[0m"
USE_COLOR = sys.stdout.isatty()


def colorize(severity, text):
    if USE_COLOR:
        return f"{SEVERITY_COLORS.get(severity, '')}{text}{RESET}"
    return text


# ─────────────────────────────────────────────────────────────────────────────
# Scanner
# ─────────────────────────────────────────────────────────────────────────────

def scan_file(filename, js_bytes):
    """Scan one JS file. Returns list of (lineno, severity, name, description, snippet)."""
    findings = []
    content = js_bytes.decode("utf-8", errors="replace")
    lines   = content.splitlines()

    for lineno, line in enumerate(lines, 1):
        for name, severity, regex, description in PATTERNS:
            if regex.search(line):
                snippet = line.strip()[:120]
                findings.append((lineno, severity, name, description, snippet))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Main audit
# ─────────────────────────────────────────────────────────────────────────────

def audit_extension(path):
    files    = load_extension(path)
    manifest = parse_manifest(files)
    name     = manifest.get("name", "Unknown Extension")
    version  = manifest.get("version", "?")
    mv       = manifest.get("manifest_version", "?")

    print(f"\n{'='*72}")
    print(f"  Extension       : {name} v{version}")
    print(f"  Manifest version: {mv}")
    print(f"  Source          : {path}")
    print(f"{'='*72}\n")

    scripts = collect_scripts(manifest, files)
    if not scripts:
        print("[i] No auditable JS files found under content_scripts / background / popup.")
        return

    print(f"[*] Auditing {len(scripts)} script file(s):\n")

    all_findings   = {}            # filename -> [(lineno, sev, name, desc, snippet)]
    severity_total = defaultdict(int)

    for script in scripts:
        findings = scan_file(script, files[script])
        if findings:
            all_findings[script] = findings
        for f in findings:
            severity_total[f[1]] += 1

    if not all_findings:
        print(colorize("INFO", "  [+] No dangerous patterns detected in any script.\n"))
    else:
        for filename in sorted(all_findings):
            findings = sorted(all_findings[filename], key=lambda x: SEVERITY_ORDER[x[1]])
            print(f"  ── {filename} ──")
            for lineno, severity, name, description, snippet in findings:
                sev_tag = colorize(severity, f"[{severity:8}]")
                print(f"    {filename}:{lineno}: {sev_tag} {name}")
                print(f"                    {description}")
                print(f"                    ↳ {snippet}")
            print()

    # Summary
    print(f"\n{'─'*72}")
    print("  FINDINGS SUMMARY")
    print(f"{'─'*72}")
    total = sum(severity_total.values())
    print(f"  Total : {total} finding(s) across {len(all_findings)} file(s)\n")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = severity_total[sev]
        if count:
            label = colorize(sev, f"{sev}")
            print(f"    {label:<40} {count}")

    # Risk verdict
    print()
    if severity_total["CRITICAL"]:
        print(colorize("CRITICAL", "  VERDICT: CRITICAL — Malware-grade patterns detected."))
    elif severity_total["HIGH"] >= 3:
        print(colorize("HIGH", "  VERDICT: HIGH RISK — Multiple high-severity patterns present."))
    elif severity_total["HIGH"]:
        print(colorize("HIGH", "  VERDICT: ELEVATED RISK — High-severity patterns require review."))
    elif severity_total["MEDIUM"]:
        print(colorize("MEDIUM", "  VERDICT: MODERATE RISK — Patterns warrant manual review."))
    else:
        print("  VERDICT: LOW RISK — No significant dangerous patterns found.")
    print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <extension_dir_or_zip_or_crx>")
        sys.exit(1)
    audit_extension(sys.argv[1])
