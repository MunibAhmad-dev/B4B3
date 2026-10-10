"""
Module 33 — Solution 02: Permission Risk Scorer
================================================
Complete implementation. Scores 50+ Chrome/Firefox permissions and host
permission patterns. Prints per-permission risk and an overall 0-100 score.

Usage:
    python sol02_permission_scorer.py <extension_dir_or_crx_or_zip>
"""

import sys
import os
import re
import json
import zipfile
import struct
import io
from urllib.parse import urlparse
from typing import Dict, List, Tuple


# ---------------------------------------------------------------------------
# Permission risk table  (permission_string → (risk_level, description))
# ---------------------------------------------------------------------------

PERMISSION_RISKS: Dict[str, Tuple[str, str]] = {
    # CRITICAL
    "nativeMessaging": (
        "CRITICAL",
        "Spawn native OS executables via registered native host — full RCE risk"
    ),
    "debugger": (
        "CRITICAL",
        "Attach Chrome DevTools Protocol to any tab — read/write memory, execute JS, intercept HTTPS"
    ),
    "proxy": (
        "CRITICAL",
        "Control browser proxy — route all traffic through attacker-controlled server"
    ),

    # HIGH
    "cookies": (
        "HIGH",
        "Read and write all cookies for any domain — enables complete session hijacking"
    ),
    "webRequestBlocking": (
        "HIGH",
        "Synchronously intercept and modify network requests — strip CSP/HSTS headers, inject content"
    ),
    "webRequest": (
        "HIGH",
        "Observe all network requests, headers, bodies (with blocking: full MITM)"
    ),
    "tabs": (
        "HIGH",
        "Access tab URL/title for all open tabs; enumerate browsing history in real time"
    ),
    "webNavigation": (
        "HIGH",
        "Track all navigation events including redirects — reconstruct full browsing history"
    ),
    "downloads": (
        "HIGH",
        "Initiate silent downloads and read full download history"
    ),
    "management": (
        "HIGH",
        "Install, uninstall, enable, or disable other extensions — supply chain attack vector"
    ),
    "browsingData": (
        "HIGH",
        "Delete cookies, cache, history, passwords — cover-track erasure or persistent cookie replacement"
    ),
    "privacy": (
        "HIGH",
        "Modify browser privacy settings — disable HTTPS-only mode, enable mixed content"
    ),
    "declarativeNetRequestFeedback": (
        "HIGH",
        "Observe matched declarativeNetRequest rules — reveals sensitive navigation patterns"
    ),
    "scripting": (
        "HIGH",
        "Programmatically inject scripts and CSS into tabs (MV3 replacement for tabs.executeScript)"
    ),
    "identity.email": (
        "HIGH",
        "Access Google account email address of the signed-in user"
    ),

    # MEDIUM
    "storage": (
        "MEDIUM",
        "Read/write extension's own key-value store — can stage exfiltrated data between sends"
    ),
    "unlimitedStorage": (
        "MEDIUM",
        "Remove 5MB storage cap — facilitates bulk data staging"
    ),
    "notifications": (
        "MEDIUM",
        "Display OS-level notifications — enables phishing overlays and social engineering"
    ),
    "history": (
        "MEDIUM",
        "Read and modify full browsing history — user profiling and intelligence gathering"
    ),
    "bookmarks": (
        "MEDIUM",
        "Read and modify bookmarks — credential hints, reconnaissance"
    ),
    "clipboardRead": (
        "MEDIUM",
        "Read clipboard contents at any time — capture copied passwords, crypto addresses, MFA codes"
    ),
    "clipboardWrite": (
        "MEDIUM",
        "Overwrite clipboard — replace crypto wallet addresses, inject malicious content"
    ),
    "activeTab": (
        "MEDIUM",
        "Access current tab URL and execute scripts in it on user gesture — targeted injection"
    ),
    "identity": (
        "MEDIUM",
        "OAuth token acquisition via Google Identity API — account access"
    ),
    "geolocation": (
        "MEDIUM",
        "Request HTML5 geolocation of the user"
    ),
    "topSites": (
        "MEDIUM",
        "Access list of most-visited sites — user profiling"
    ),
    "sessions": (
        "MEDIUM",
        "Access recently closed tabs and windows — browsing history reconstruction"
    ),
    "pageCapture": (
        "MEDIUM",
        "Save the current page as MHTML — full page content capture"
    ),
    "contentSettings": (
        "MEDIUM",
        "Modify per-site content settings (cookies, JavaScript, plugins, etc.)"
    ),
    "declarativeContent": (
        "MEDIUM",
        "Show page actions based on URL/DOM — reveals content analysis of visited pages"
    ),
    "webAuthenticationProxy": (
        "MEDIUM",
        "Act as a WebAuthn authenticator proxy — MFA bypass potential"
    ),
    "offscreen": (
        "MEDIUM",
        "Create offscreen documents — hidden execution context for audio/clipboard/DOM work"
    ),
    "sidePanel": (
        "MEDIUM",
        "Access Chrome side panel — persistent UI injection"
    ),

    # LOW
    "contextMenus": (
        "LOW",
        "Add items to browser right-click context menus"
    ),
    "alarms": (
        "LOW",
        "Schedule periodic callbacks — used legitimately and for periodic beaconing"
    ),
    "idle": (
        "LOW",
        "Detect user idle state — can be used to time-gate malicious activity"
    ),
    "gcm": (
        "LOW",
        "Google Cloud Messaging (legacy push notifications)"
    ),
    "fontSettings": (
        "LOW",
        "Manage browser font settings"
    ),
    "i18n": (
        "LOW",
        "Internationalization API — access extension message catalog"
    ),
    "tts": (
        "LOW",
        "Text-to-speech synthesis"
    ),
    "ttsEngine": (
        "LOW",
        "Implement a speech synthesis engine"
    ),
    "accessibilityFeatures.read": (
        "LOW",
        "Read accessibility feature settings"
    ),
    "accessibilityFeatures.modify": (
        "LOW",
        "Modify accessibility feature settings"
    ),
    "audio": (
        "LOW",
        "Gain information about audio devices"
    ),
    "certificateProvider": (
        "LOW",
        "Expose certificates to the platform certificate store (enterprise)"
    ),
    "devtools": (
        "LOW",
        "Add panels/sidebars to Chrome DevTools"
    ),
    "documentScan": (
        "LOW",
        "Access document scanner devices (Chromebook)"
    ),
    "enterprise.deviceAttributes": (
        "LOW",
        "Read enterprise device identifier"
    ),
    "fileSystem": (
        "LOW",
        "Read/write user-selected files (Chrome Apps)"
    ),
    "fileBrowserHandler": (
        "LOW",
        "Extend ChromeOS file browser"
    ),
    "input": (
        "LOW",
        "Intercept keyboard events globally (risk: keylogger if combined with other perms)"
    ),
    "loginState": (
        "LOW",
        "Read screen lock/login state (ChromeOS)"
    ),
    "printing": (
        "LOW",
        "Submit print jobs"
    ),
    "system.cpu": (
        "LOW",
        "Read CPU metadata"
    ),
    "system.display": (
        "LOW",
        "Read/modify display configuration"
    ),
    "system.memory": (
        "LOW",
        "Read physical memory info"
    ),
    "system.storage": (
        "LOW",
        "Read/observe storage device info"
    ),
    "tabCapture": (
        "LOW",
        "Capture audio/video from a tab"
    ),
    "tabGroups": (
        "LOW",
        "Read and manage tab groups"
    ),
    "wallpaper": (
        "LOW",
        "Change ChromeOS wallpaper"
    ),
    "declarativeNetRequest": (
        "LOW",
        "Block/redirect requests via declarative rules (MV3 webRequest replacement)"
    ),
    "dns": (
        "LOW",
        "Resolve hostnames using the browser's DNS infrastructure"
    ),
    "vpnProvider": (
        "LOW",
        "Implement a VPN client (ChromeOS)"
    ),
    "action": (
        "LOW",
        "Control extension icon, badge, tooltip (UI only)"
    ),
    "runtime": (
        "LOW",
        "Core extension runtime access — available to all extensions implicitly"
    ),
}

# Points added to score per risk level
RISK_SCORE: Dict[str, int] = {
    "CRITICAL": 40,
    "HIGH":     20,
    "MEDIUM":    5,
    "LOW":       1,
    "UNKNOWN":   2,
}

RISK_COLOR_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def score_host_permission(pattern: str) -> Tuple[str, str, int]:
    """
    Score a single host permission pattern.
    Returns (risk_level, reason, score_delta).
    """
    if pattern in ("<all_urls>", "*://*/*", "http://*/*", "https://*/*"):
        return ("HIGH", "Universal host access — content script on every page", 20)

    try:
        parsed = urlparse(pattern)
        host   = parsed.netloc or parsed.path
    except Exception:
        host = pattern

    # Strip port
    host = host.split(":")[0]

    # Pure wildcard host
    if host == "*":
        return ("HIGH", "Wildcard host — all domains", 20)

    # Subdomain wildcard e.g. *.example.com
    if host.startswith("*."):
        domain = host[2:]
        # Count dots to judge breadth
        if domain.count(".") == 1:
            return ("MEDIUM", f"Subdomain wildcard on {domain}", 10)
        else:
            return ("LOW", f"Subdomain wildcard on specific domain {domain}", 3)

    # Specific origin
    return ("LOW", f"Single origin: {host}", 1)


def compute_overall_score(perm_results: list, host_results: list) -> Tuple[int, str]:
    """
    Compute 0-100 score and determine overall risk label.
    """
    score = 0
    for _, level, _ in perm_results:
        score += RISK_SCORE.get(level, 2)
    for _, level, _, _ in host_results:
        score += RISK_SCORE.get(level, 2)

    score = min(score, 100)

    if score >= 80:
        label = "CRITICAL"
    elif score >= 50:
        label = "HIGH"
    elif score >= 20:
        label = "MEDIUM"
    else:
        label = "LOW"

    return score, label


def analyze_permissions(manifest: dict) -> Tuple[list, list]:
    """
    Returns (perm_results, host_results).
    perm_results: list of (permission, level, description)
    host_results: list of (pattern, level, reason, score_delta)
    """
    raw_perms  = manifest.get("permissions", [])
    raw_hosts  = manifest.get("host_permissions", [])  # MV3

    perm_results = []
    host_results = []

    for perm in raw_perms:
        # In MV2, host patterns appear in permissions list
        if perm.startswith("http") or perm.startswith("*") or perm == "<all_urls>":
            level, reason, delta = score_host_permission(perm)
            host_results.append((perm, level, reason, delta))
        elif perm in PERMISSION_RISKS:
            level, desc = PERMISSION_RISKS[perm]
            perm_results.append((perm, level, desc))
        else:
            perm_results.append((perm, "UNKNOWN", "Permission not in risk table — review manually"))

    for perm in raw_hosts:
        level, reason, delta = score_host_permission(perm)
        host_results.append((perm, level, reason, delta))

    return perm_results, host_results


def print_report(manifest: dict) -> None:
    name = manifest.get("name", "?")
    mv   = manifest.get("manifest_version", "?")

    perm_results, host_results = analyze_permissions(manifest)
    score, label = compute_overall_score(perm_results, host_results)

    print("=" * 68)
    print(f"  Permission Risk Report: {name}  (MV{mv})")
    print("=" * 68)

    # Print permissions grouped by risk level
    for target_level in RISK_COLOR_ORDER:
        group = [(p, l, d) for p, l, d in perm_results if l == target_level]
        if not group:
            continue
        print(f"\n  [{target_level}] PERMISSIONS")
        print("  " + "-" * 56)
        for perm, level, desc in group:
            print(f"    {perm}")
            print(f"      {desc}")

    if host_results:
        print(f"\n  HOST PERMISSIONS")
        print("  " + "-" * 56)
        for pattern, level, reason, _ in host_results:
            print(f"    [{level:8s}]  {pattern}")
            print(f"               {reason}")

    # Optional permissions
    opt = manifest.get("optional_permissions", [])
    if opt:
        print(f"\n  OPTIONAL PERMISSIONS (user must grant at runtime)")
        for p in opt:
            if p in PERMISSION_RISKS:
                level, desc = PERMISSION_RISKS[p]
            else:
                level, desc = "LOW", "Not in risk table"
            print(f"    [{level:8s}]  {p}")

    print()
    print("=" * 68)
    print(f"  Overall Risk Score : {score}/100")
    print(f"  Overall Risk Level : {label}")
    print("=" * 68)


# ---------------------------------------------------------------------------
# Extension loader (from sol01)
# ---------------------------------------------------------------------------

def unpack_crx(data: bytes) -> zipfile.ZipFile:
    if data[:4] != b"Cr24":
        raise ValueError("Not a CRX file")
    version = struct.unpack_from("<I", data, 4)[0]
    if version == 2:
        pk_len  = struct.unpack_from("<I", data, 8)[0]
        sig_len = struct.unpack_from("<I", data, 12)[0]
        zip_start = 16 + pk_len + sig_len
    elif version == 3:
        hdr_len   = struct.unpack_from("<I", data, 8)[0]
        zip_start = 12 + hdr_len
    else:
        raise ValueError(f"Unknown CRX version {version}")
    return zipfile.ZipFile(io.BytesIO(data[zip_start:]))


def load_manifest_from_path(path: str) -> dict:
    path = os.path.abspath(path)
    if os.path.isdir(path):
        mf = os.path.join(path, "manifest.json")
        with open(mf, "r", encoding="utf-8") as f:
            return json.load(f)

    with open(path, "rb") as f:
        raw = f.read()

    if path.lower().endswith(".crx"):
        zf = unpack_crx(raw)
    else:
        zf = zipfile.ZipFile(io.BytesIO(raw))

    return json.loads(zf.read("manifest.json").decode("utf-8"))


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <extension_dir_or_crx_or_zip>")
        sys.exit(1)

    manifest = load_manifest_from_path(sys.argv[1])
    print_report(manifest)


if __name__ == "__main__":
    main()
