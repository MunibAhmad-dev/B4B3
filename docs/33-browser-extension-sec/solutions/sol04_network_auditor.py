#!/usr/bin/env python3
"""
sol04_network_auditor.py — Browser Extension Network Endpoint Auditor
Usage: python sol04.py <extension_dir_or_zip_or_crx>

Extracts all URL string literals from every JS and JSON file in the extension,
classifies each URL, and flags suspicious network destinations.
"""

import sys
import re
import json
import zipfile
import struct
import io
import base64
from pathlib import Path
from collections import defaultdict

# ─────────────────────────────────────────────────────────────────────────────
# Loader (same pattern as sol03)
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


def parse_manifest(files):
    if "manifest.json" not in files:
        sys.exit("[!] No manifest.json found.")
    try:
        return json.loads(files["manifest.json"].decode("utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        sys.exit(f"[!] manifest.json parse error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# URL extraction patterns
# ─────────────────────────────────────────────────────────────────────────────

# Match quoted URL strings
URL_IN_QUOTES  = re.compile(r'["\']((https?|ftp|wss?|chrome-extension)://[^\s"\'<>\\]{5,})["\']')
# Hardcoded IP
IP_ADDR        = re.compile(r'\b((?:\d{1,3}\.){3}\d{1,3})\b')
# Base64 blobs (potential obfuscated URL)
B64_BLOB       = re.compile(r'["\']([A-Za-z0-9+/]{24,}={0,2})["\']')
# POST with credential-like params
POST_EXFIL     = re.compile(
    r'(?:fetch|\.open)\s*\(\s*["\']POST["\'].*?'
    r'(?:password|passwd|email|user(?:name)?|token|key|cred|secret|auth)',
    re.S | re.I
)
# Dynamic fetch (fetch(variable)) — no literal URL
DYNAMIC_FETCH  = re.compile(r'\bfetch\s*\(\s*(?!["\'`])([a-zA-Z_$][a-zA-Z0-9_$.]*)')

# Suspicious TLDs
SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".pw", ".ml", ".ga", ".cf", ".gq",
    ".top", ".work", ".click", ".bid", ".stream", ".racing",
    ".download", ".accountant", ".loan", ".win", ".trade",
    ".party", ".science", ".review", ".faith",
}

# Domains always trusted (CDNs, browser vendor infrastructure)
TRUSTED_DOMAINS = (
    ".googleapis.com", ".gstatic.com", ".google.com", ".google-analytics.com",
    ".googletagmanager.com", ".mozilla.org", ".firefox.com",
    ".microsoft.com", ".bing.com",
    "cdnjs.cloudflare.com", "ajax.googleapis.com",
    ".jquery.com", ".jsdelivr.net", ".unpkg.com", ".w3.org",
    ".amazon.com", ".amazonaws.com",
)

BROWSER_UPDATE_STORES = (
    "chrome.google.com", "addons.mozilla.org",
    "microsoftedge.microsoft.com", "clients2.google.com",
    "update.googleapis.com",
)


def hostname_from_url(url):
    """Crude stdlib-only hostname extractor."""
    try:
        after_proto = url.split("://", 1)[1]
        host = after_proto.split("/")[0].split("?")[0].split("#")[0]
        host = host.rsplit(":", 1)[0]  # strip port
        return host.lower()
    except Exception:
        return url.lower()


def classify_url(url):
    """Return (category_string, detail)."""
    if url.startswith("chrome-extension://") or url.startswith("moz-extension://"):
        return "INTERNAL", ""

    host = hostname_from_url(url)

    # Trusted
    for suffix in TRUSTED_DOMAINS:
        if host == suffix.lstrip(".") or host.endswith(suffix):
            return "TRUSTED", host

    # Hardcoded IP in hostname position
    if re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', host):
        return "SUSPICIOUS_IP", host

    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            return "SUSPICIOUS_TLD", f"TLD={tld}"

    return "EXTERNAL", host


def try_decode_b64(blob):
    """Attempt base64 decode and return decoded string or None."""
    try:
        padded = blob + "=" * (-len(blob) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="strict")
        return decoded
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Output helpers
# ─────────────────────────────────────────────────────────────────────────────

USE_COLOR = sys.stdout.isatty()
CAT_COLORS = {
    "INTERNAL":             "\033[96m",
    "TRUSTED":              "\033[92m",
    "EXTERNAL":             "\033[93m",
    "SUSPICIOUS_IP":        "\033[1;91m",
    "SUSPICIOUS_TLD":       "\033[1;91m",
    "SUSPICIOUS_B64":       "\033[1;91m",
    "DYNAMIC":              "\033[90m",
}
RESET = "\033[0m"


def colorize(cat, text):
    if USE_COLOR:
        return f"{CAT_COLORS.get(cat, '')}{text}{RESET}"
    return text


# ─────────────────────────────────────────────────────────────────────────────
# Main audit
# ─────────────────────────────────────────────────────────────────────────────

def audit_extension(path):
    files    = load_extension(path)
    manifest = parse_manifest(files)
    name     = manifest.get("name", "Unknown")
    version  = manifest.get("version", "?")

    print(f"\n{'='*72}")
    print(f"  Extension : {name} v{version}")
    print(f"  Source    : {path}")
    print(f"{'='*72}\n")

    # --- Check update_url ---
    update_url = manifest.get("update_url", "")
    if update_url:
        is_store = any(s in update_url for s in BROWSER_UPDATE_STORES)
        if not is_store:
            flag = colorize("SUSPICIOUS_IP", "[FLAG]")
            print(f"  {flag} update_url points to non-browser-store domain:")
            print(f"    {update_url}\n")

    # --- Scan all JS and JSON files ---
    target_files = sorted(
        f for f in files
        if f.endswith(".js") or f.endswith(".json")
    )

    # url -> {"category": str, "detail": str, "sources": [(file, line)]}
    url_inventory = {}
    exfil_findings  = []  # (file, line, snippet)
    dynamic_findings = [] # (file, line, snippet)

    for filename in target_files:
        content = files[filename].decode("utf-8", errors="replace")
        lines   = content.splitlines()

        for lineno, line in enumerate(lines, 1):
            # Quoted URL literals
            for m in URL_IN_QUOTES.finditer(line):
                url = m.group(1)
                if url not in url_inventory:
                    cat, detail = classify_url(url)
                    url_inventory[url] = {"category": cat, "detail": detail, "sources": []}
                url_inventory[url]["sources"].append((filename, lineno))

            # POST exfiltration pattern
            if POST_EXFIL.search(line):
                exfil_findings.append((filename, lineno, line.strip()[:120]))

            # Dynamic fetch (variable URL)
            dm = DYNAMIC_FETCH.search(line)
            if dm:
                dynamic_findings.append((filename, lineno, line.strip()[:100]))

        # Base64-encoded URL search (whole-file pass)
        for m in B64_BLOB.finditer(content):
            blob    = m.group(1)
            decoded = try_decode_b64(blob)
            if decoded:
                for um in URL_IN_QUOTES.finditer(f'"{decoded}"'):
                    url = um.group(1)
                    if url not in url_inventory:
                        url_inventory[url] = {
                            "category": "SUSPICIOUS_B64",
                            "detail":   "decoded from base64 blob",
                            "sources":  [(filename, 0)],
                        }

    # ── URL Table ─────────────────────────────────────────────────────────────
    if not url_inventory:
        print("  [i] No URL string literals found.\n")
    else:
        print(f"  {'URL':<56} {'CATEGORY':<22} SOURCE")
        print(f"  {'─'*56} {'─'*22} {'─'*28}")
        for url, info in sorted(url_inventory.items(), key=lambda x: x[1]["category"]):
            cat     = info["category"]
            sources = info["sources"]
            src_str = "; ".join(f"{f}:{l}" for f, l in sources[:2])
            if len(sources) > 2:
                src_str += f" (+{len(sources)-2})"
            url_disp = (url[:54] + "..") if len(url) > 56 else url
            print(f"  {url_disp:<56} {colorize(cat, cat):<22} {src_str}")

    # ── POST Exfiltration ─────────────────────────────────────────────────────
    if exfil_findings:
        print(f"\n  {'─'*72}")
        print(f"  {colorize('SUSPICIOUS_IP', '[!] POST EXFILTRATION PATTERNS DETECTED:')}")
        for fname, lineno, snippet in exfil_findings:
            print(f"    {fname}:{lineno}:")
            print(f"      {snippet}")

    # ── Dynamic fetches ───────────────────────────────────────────────────────
    if dynamic_findings:
        print(f"\n  {'─'*72}")
        print(f"  [i] DYNAMIC URL FETCHES (variable argument — cannot classify statically):")
        for fname, lineno, snippet in dynamic_findings[:20]:
            print(f"    {fname}:{lineno}: {snippet}")
        if len(dynamic_findings) > 20:
            print(f"    ... and {len(dynamic_findings)-20} more")

    # ── Summary ───────────────────────────────────────────────────────────────
    counts = defaultdict(int)
    for info in url_inventory.values():
        counts[info["category"]] += 1

    print(f"\n  {'─'*72}")
    print("  SUMMARY")
    print(f"  {'─'*72}")
    print(f"  Total unique URL literals  : {len(url_inventory)}")
    for cat in ("INTERNAL", "TRUSTED", "EXTERNAL", "SUSPICIOUS_IP", "SUSPICIOUS_TLD", "SUSPICIOUS_B64"):
        if counts[cat]:
            print(f"    {colorize(cat, cat):<40} : {counts[cat]}")
    if exfil_findings:
        print(f"  POST exfil patterns        : {len(exfil_findings)}")
    if dynamic_findings:
        print(f"  Dynamic URL references     : {len(dynamic_findings)}")

    suspicious_total = counts["SUSPICIOUS_IP"] + counts["SUSPICIOUS_TLD"] + counts["SUSPICIOUS_B64"]
    print()
    if suspicious_total:
        print(colorize("SUSPICIOUS_IP",
                        f"  WARNING: {suspicious_total} suspicious URL(s) detected — manual review required."))
    elif counts["EXTERNAL"]:
        print(f"  NOTE: {counts['EXTERNAL']} external URL(s) found — verify they are expected.")
    else:
        print("  No suspicious URLs detected.")
    print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <extension_dir_or_zip_or_crx>")
        sys.exit(1)
    audit_extension(sys.argv[1])
