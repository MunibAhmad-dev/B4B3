"""
Module 33 — Exercise 03: Content Script Auditor
=================================================
Scan all JavaScript files listed in content_scripts (and background scripts)
for dangerous patterns that indicate malicious behaviour.

Patterns to detect:
  - eval() / new Function()          dynamic code execution
  - document.write()                 DOM injection
  - innerHTML= / outerHTML= / insertAdjacentHTML  DOM injection sinks
  - XMLHttpRequest / fetch to external URLs        data exfiltration
  - localStorage access              persistent data staging
  - chrome.tabs.executeScript        dynamic script injection into tabs
  - Form field reading (input[type=password], .value on password fields)
  - Crypto miner strings (CoinHive, coinhive, cryptonight, wasmMiner)

Usage:
    python exercise_03_content_script_audit.py <extension_dir_or_crx_or_zip>

TODOs are marked with ### TODO ###.
"""

import sys
import os
import re
import json
import zipfile
import struct
import io
from typing import List, Tuple, Dict


# ---------------------------------------------------------------------------
# Pattern definitions — add patterns to this list
# ---------------------------------------------------------------------------

# Each entry: (pattern_name, regex_string, risk_level, description)
PATTERNS: List[Tuple[str, str, str, str]] = [
    (
        "eval()",
        r"\beval\s*\(",
        "HIGH",
        "Dynamic code execution via eval()"
    ),
    (
        "new Function()",
        r"\bnew\s+Function\s*\(",
        "HIGH",
        "Dynamic code execution via new Function()"
    ),
    (
        "document.write()",
        r"\bdocument\s*\.\s*write\s*\(",
        "MEDIUM",
        "DOM injection via document.write()"
    ),
    ### TODO ###
    # Add patterns for:
    # - innerHTML assignment (e.g. element.innerHTML = ...)
    # - outerHTML assignment
    # - insertAdjacentHTML(
    # - XMLHttpRequest (new XMLHttpRequest)
    # - fetch( calls
    # - localStorage.setItem / localStorage.getItem
    # - chrome.tabs.executeScript(
    # - password field reading: type="password" or type='password' in querySelector strings
    # - CoinHive / coinhive / cryptonight / wasmMiner / CryptoNoter
    #
    # Hint for fetch: r'\bfetch\s*\(' will match any fetch() call.
    # For external URLs inside fetch, you'll need a second pass (see scan_file).
]


def extract_urls_from_js(source: str) -> List[str]:
    """
    Extract all string literals that look like URLs from JavaScript source.
    Returns a list of URL strings found.

    ### TODO ###
    Use a regex to find strings like:
      "https://api.example.com/collect"
      'http://192.168.1.1/beacon'
    Hint: match quoted strings starting with http:// or https://
    """
    return []  # TODO: return list of extracted URL strings


def is_external_url(url: str, extension_id: str = None) -> bool:
    """
    Return True if the URL points to an external server (not chrome-extension://).

    ### TODO ###
    - chrome-extension:// URLs are internal
    - Everything else is external
    """
    return False  # TODO


def scan_file(filename: str, source: str) -> List[dict]:
    """
    Scan a single JS file's source for all defined patterns.
    Returns a list of finding dicts:
      {file, line, column, pattern_name, risk_level, description, snippet}
    """
    findings = []
    lines = source.splitlines()

    for pattern_name, regex, risk_level, description in PATTERNS:
        ### TODO ###
        # Use re.finditer() with the regex to find all matches in the full source.
        # For each match:
        #   1. Calculate the line number by counting newlines before match.start()
        #   2. Extract a snippet (the matching line, stripped)
        #   3. Append a finding dict
        pass

    return findings


def get_js_files_to_scan(manifest: dict, files: dict) -> List[str]:
    """
    Return a list of JS filenames from the extension that should be audited.
    Includes: content_scripts js files, background scripts/service_worker,
    and any popup/options HTML-referenced scripts.

    ### TODO ###
    1. Collect all .js files listed in manifest["content_scripts"][*]["js"]
    2. Collect background scripts from manifest["background"]["scripts"] (MV2)
       or manifest["background"]["service_worker"] (MV3)
    3. Optionally: scan all .js files in the extension regardless of manifest
       (belt-and-suspenders approach)
    """
    return list(k for k in files.keys() if k.endswith(".js"))  # TODO: refine


def audit_extension(path: str) -> None:
    ### TODO ###
    # 1. Load the extension (handle dir/.crx/.zip) — reuse exercise_01 code
    # 2. Parse manifest.json
    # 3. Get list of JS files to scan
    # 4. For each JS file, decode bytes to string and call scan_file()
    # 5. Collect all findings and print a report grouped by risk level
    raise NotImplementedError("TODO: implement audit_extension")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <extension_dir_or_crx_or_zip>")
        sys.exit(1)
    audit_extension(sys.argv[1])


if __name__ == "__main__":
    main()
