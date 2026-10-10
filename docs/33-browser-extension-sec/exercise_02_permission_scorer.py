"""
Module 33 — Exercise 02: Permission Risk Scorer
=================================================
Given a parsed manifest dict, assign a risk level (CRITICAL/HIGH/MEDIUM/LOW)
to each permission and print a summary score.

Build on exercise_01 or import the load/parse helpers from your solution.

Usage:
    python exercise_02_permission_scorer.py <extension_dir_or_crx_or_zip>

TODOs are marked with ### TODO ###.
"""

import sys
import os
import json
import zipfile
import struct
import io


# ---------------------------------------------------------------------------
# Risk table — complete this dict with all permissions you know about.
# Keys are exact permission strings.
# Values are (risk_level, description) tuples.
# Risk levels: "CRITICAL", "HIGH", "MEDIUM", "LOW"
# ---------------------------------------------------------------------------

PERMISSION_RISKS = {
    # CRITICAL
    "nativeMessaging": ("CRITICAL", "Spawn native OS executables — full RCE risk"),
    "debugger":        ("CRITICAL", "Attach Chrome DevTools Protocol to any tab — read memory, execute JS"),
    "proxy":           ("CRITICAL", "Control browser proxy — intercept all traffic"),

    # HIGH
    "cookies":         ("HIGH", "Read/write cookies for any domain — session hijacking"),
    "webRequestBlocking": ("HIGH", "Intercept and modify network requests synchronously"),
    "downloads":       ("HIGH", "Initiate downloads and read download history"),
    "management":      ("HIGH", "Install/uninstall/disable other extensions"),
    "browsingData":    ("HIGH", "Delete cookies, cache, history — cover-track erasure"),
    "privacy":         ("HIGH", "Modify browser privacy settings"),

    ### TODO ###
    # Add at least 15 more permissions with appropriate risk levels.
    # Suggested additions: tabs, webNavigation, webRequest, history, bookmarks,
    # clipboardRead, clipboardWrite, activeTab, storage, notifications,
    # identity, geolocation, unlimitedStorage, contextMenus, alarms, idle,
    # gcm, declarativeNetRequest, offscreen, scripting, ...
}


def score_host_permissions(host_perms: list) -> list:
    """
    Score host_permissions (and wildcard entries in permissions).
    Returns a list of (pattern, risk_level, reason) tuples.
    """
    results = []
    for pattern in host_perms:
        ### TODO ###
        # Rules:
        # "<all_urls>" or "*://*/*"  → HIGH "Universal host access"
        # "*://*.<tld>/*" broad TLD  → HIGH
        # "https://*.example.com/*"  → MEDIUM "Specific domain wildcard"
        # "https://example.com/*"    → LOW "Single origin"
        # Hint: check for '<all_urls>' exactly, then check for leading '*'
        results.append((pattern, "UNKNOWN", "TODO: implement scoring"))
    return results


def compute_overall_score(permission_results: list, host_results: list) -> int:
    """
    Compute an integer 0-100 overall risk score.

    ### TODO ###
    Suggested algorithm:
    - Start at 0
    - For each CRITICAL permission: add 40 points (capped at 100)
    - For each HIGH permission:     add 20 points
    - For each MEDIUM permission:   add 5 points
    - For each LOW permission:      add 1 point
    - Host permission wildcards: treat "<all_urls>" as +20, subdomain wildcards as +10
    - Cap at 100
    """
    return 0  # TODO: replace with real computation


def print_score_report(manifest: dict) -> None:
    permissions  = manifest.get("permissions", [])
    host_perms   = manifest.get("host_permissions", [])

    # Separate host-like entries from named permissions in MV2 (where they're mixed)
    named_perms  = [p for p in permissions if not p.startswith("http") and p != "<all_urls>"]
    host_in_perms = [p for p in permissions if p.startswith("http") or p == "<all_urls>"]
    all_host     = host_perms + host_in_perms

    print("=" * 60)
    print("PERMISSION RISK ANALYSIS")
    print("=" * 60)

    perm_results = []
    for perm in named_perms:
        if perm in PERMISSION_RISKS:
            level, desc = PERMISSION_RISKS[perm]
        else:
            level, desc = "LOW", "Unknown/unlisted permission"
        perm_results.append((perm, level, desc))
        print(f"  [{level:8s}]  {perm}")
        print(f"             {desc}")

    print()
    print("HOST PERMISSIONS")
    print("-" * 60)

    host_results = score_host_permissions(all_host)
    for pattern, level, reason in host_results:
        print(f"  [{level:8s}]  {pattern}")
        print(f"             {reason}")

    overall = compute_overall_score(perm_results, host_results)
    print()
    print(f"Overall Risk Score: {overall}/100")

    if overall >= 80:
        print("Risk Level: CRITICAL")
    elif overall >= 50:
        print("Risk Level: HIGH")
    elif overall >= 20:
        print("Risk Level: MEDIUM")
    else:
        print("Risk Level: LOW")


# ---------------------------------------------------------------------------
# Minimal manifest loader (copy from exercise_01 or your solution)
# ---------------------------------------------------------------------------

def load_manifest_from_path(path: str) -> dict:
    """
    ### TODO ###
    Reuse or copy your implementation from exercise_01:
    - Handle directory, .crx, .zip
    - Parse and return manifest.json as a dict
    """
    raise NotImplementedError("TODO: implement load_manifest_from_path (reuse exercise_01 code)")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <extension_dir_or_crx_or_zip>")
        sys.exit(1)

    manifest = load_manifest_from_path(sys.argv[1])
    print(f"Extension: {manifest.get('name', '?')}  v{manifest.get('version', '?')}")
    print()
    print_score_report(manifest)


if __name__ == "__main__":
    main()
