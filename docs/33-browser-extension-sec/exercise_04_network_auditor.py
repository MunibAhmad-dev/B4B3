"""
Module 33 — Exercise 04: Network Endpoint Auditor
===================================================
Find all URLs referenced in an extension's JS and JSON files,
classify them, and flag suspicious ones.

Classifications:
  - INTERNAL     chrome-extension:// or relative paths
  - TRUSTED      Known vendor domains (*.google.com, *.mozilla.org, *.gstatic.com, *.googleapis.com)
  - HARDCODED_IP Direct IP addresses (highly suspicious in extensions)
  - EXTERNAL     Other domains
  - SUSPICIOUS   Unusual TLDs (.xyz .tk .pw .ml .ga .cf .gq) or known C2 patterns

Flags:
  - EXFIL_ENDPOINT  URL used in a POST fetch/XHR call alongside form-like field names
  - BEACON_PATTERN  setInterval() + fetch/XHR in same function/scope
  - UPDATE_URL      manifest update_url pointing to external server

Usage:
    python exercise_04_network_auditor.py <extension_dir_or_crx_or_zip>

TODOs are marked with ### TODO ###.
"""

import sys
import os
import re
import json
import zipfile
import struct
import io
from typing import List, Dict, Tuple


# ---------------------------------------------------------------------------
# Trusted domains list — extend as needed
# ---------------------------------------------------------------------------

TRUSTED_DOMAINS = [
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "mozilla.org", "firefox.com", "mozilla.net",
    "chrome.google.com", "chromewebstore.google.com",
    "microsoft.com", "windows.com",
    "cloudflare.com", "cdnjs.cloudflare.com",
    "jquery.com", "jsdelivr.net", "unpkg.com",
]

SUSPICIOUS_TLDS = [".xyz", ".tk", ".pw", ".ml", ".ga", ".cf", ".gq", ".top", ".click", ".download"]

# Regex for extracting URLs from string literals
URL_RE = re.compile(
    r"""(?:["'`])((https?://[^\s"'`>]+))(?:["'`])""",
    re.IGNORECASE
)

IP_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)


def classify_url(url: str) -> Tuple[str, str]:
    """
    Return (classification, reason) for a URL.

    Classifications: INTERNAL, TRUSTED, HARDCODED_IP, SUSPICIOUS, EXTERNAL

    ### TODO ###
    1. If url starts with "chrome-extension://" → INTERNAL
    2. If url's hostname matches an IP regex → HARDCODED_IP
    3. Extract hostname from url (hint: use urllib.parse.urlparse or simple split)
    4. Check if hostname ends with any TRUSTED_DOMAINS entry → TRUSTED
    5. Check if hostname ends with any SUSPICIOUS_TLDS entry → SUSPICIOUS
    6. Otherwise → EXTERNAL
    """
    return ("UNKNOWN", "TODO: implement classify_url")


def find_beacon_patterns(source: str, filename: str) -> List[dict]:
    """
    Detect setInterval/setTimeout paired with fetch or XHR calls in nearby lines.
    This is the classic beaconing/polling pattern.

    ### TODO ###
    Strategy:
    1. Find all line numbers containing setInterval or setTimeout
    2. Find all line numbers containing fetch( or new XMLHttpRequest
    3. If any fetch/XHR line is within 20 lines of a setInterval/setTimeout → flag it
    Return a list of finding dicts with file/line/description.
    """
    return []  # TODO


def find_exfil_patterns(source: str, filename: str) -> List[dict]:
    """
    Detect POST requests with form-like payload keys (password, email, username, token, etc.)

    ### TODO ###
    Look for patterns like:
      fetch("https://...", { method: "POST", body: JSON.stringify({password: ...}) })
      xhr.send("username=" + user + "&password=" + pass)
    Return list of finding dicts.
    """
    return []  # TODO


def extract_all_urls(files: dict) -> Dict[str, List[Tuple[str, int, str]]]:
    """
    Scan all .js and .json files. Return a dict:
      { url: [(filename, line_number, context_snippet), ...] }

    ### TODO ###
    1. For each file in files.items() where name ends in .js or .json:
       a. Decode bytes to string (ignore errors)
       b. Use URL_RE.finditer() to find all URL string literals
       c. For each match, compute line number, record (filename, lineno, line_text)
    2. Return the combined dict (one URL may appear in multiple files)
    """
    return {}  # TODO


def audit_network(path: str) -> None:
    """
    ### TODO ###
    1. Load extension (dir/.crx/.zip)
    2. Extract all URLs
    3. Classify each URL
    4. Check manifest for update_url
    5. Run beacon and exfil pattern detectors on all JS files
    6. Print categorized report
    """
    raise NotImplementedError("TODO: implement audit_network")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <extension_dir_or_crx_or_zip>")
        sys.exit(1)
    audit_network(sys.argv[1])


if __name__ == "__main__":
    main()
