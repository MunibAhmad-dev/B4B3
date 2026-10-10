#!/usr/bin/env python3
"""
sol03_dex_strings.py — Complete DEX String Extractor and Analyzer
Usage: python sol03.py <file.apk_or_dex>

Parses the DEX file format from scratch (no external libs), extracts all strings,
and categorizes them into security-relevant buckets.
"""

import sys
import re
import struct
import zipfile
import io
from pathlib import Path
from collections import defaultdict

# ─────────────────────────────────────────────────────────────────────────────
# DEX constants
# ─────────────────────────────────────────────────────────────────────────────

DEX_MAGIC_VERSIONS = {
    b"dex\n035\0", b"dex\n036\0", b"dex\n037\0", b"dex\n038\0", b"dex\n039\0"
}
ENDIAN_CONSTANT = 0x12345678

# ─────────────────────────────────────────────────────────────────────────────
# APK/DEX loader
# ─────────────────────────────────────────────────────────────────────────────

def load_dex(path):
    """Return bytes of classes.dex from a .dex file or .apk."""
    path = Path(path)
    if not path.exists():
        sys.exit(f"[!] File not found: {path}")

    data = path.read_bytes()

    # Try as APK (ZIP)
    if data[:2] == b'PK':
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as apk:
                names = apk.namelist()
                # Support multidex — find all dex files
                dex_files = sorted(n for n in names if re.fullmatch(r'classes\d*\.dex', n))
                if not dex_files:
                    sys.exit("[!] No classes*.dex found in APK")
                print(f"[+] APK contains {len(dex_files)} DEX file(s): {', '.join(dex_files)}")
                # Return primary classes.dex
                d = apk.read(dex_files[0])
                print(f"[+] Using {dex_files[0]} ({len(d):,} bytes)")
                return d
        except zipfile.BadZipFile:
            pass  # Not a zip, try as raw DEX

    return data


# ─────────────────────────────────────────────────────────────────────────────
# ULEB128 decoder
# ─────────────────────────────────────────────────────────────────────────────

def read_uleb128(data, offset):
    """
    Decode a ULEB128 (Unsigned Little-Endian Base 128) integer.
    Returns (value, offset_after_last_byte).
    """
    result = 0
    shift  = 0
    while True:
        if offset >= len(data):
            raise ValueError(f"ULEB128 read past end of data at offset {offset}")
        byte    = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        shift  += 7
        if not (byte & 0x80):
            break
    return result, offset


# ─────────────────────────────────────────────────────────────────────────────
# DEX header parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_dex_header(data):
    """Parse the 112-byte DEX header. Returns a dict."""
    if len(data) < 112:
        sys.exit(f"[!] File too small for DEX header ({len(data)} bytes)")

    magic = data[:8]
    if magic not in DEX_MAGIC_VERSIONS:
        print(f"[!] Unexpected DEX magic: {magic!r} — attempting to continue")

    # Adler-32 is at offset 8 (4 bytes) — skip verification for now
    # SHA-1 hash is at offset 12 (20 bytes) — skip

    hdr = {
        "magic":            magic,
        "file_size":        struct.unpack_from('<I', data, 32)[0],
        "header_size":      struct.unpack_from('<I', data, 36)[0],
        "endian_tag":       struct.unpack_from('<I', data, 40)[0],
        "link_size":        struct.unpack_from('<I', data, 44)[0],
        "link_off":         struct.unpack_from('<I', data, 48)[0],
        "map_off":          struct.unpack_from('<I', data, 52)[0],
        "string_ids_size":  struct.unpack_from('<I', data, 56)[0],
        "string_ids_off":   struct.unpack_from('<I', data, 60)[0],
        "type_ids_size":    struct.unpack_from('<I', data, 64)[0],
        "type_ids_off":     struct.unpack_from('<I', data, 68)[0],
        "proto_ids_size":   struct.unpack_from('<I', data, 72)[0],
        "proto_ids_off":    struct.unpack_from('<I', data, 76)[0],
        "field_ids_size":   struct.unpack_from('<I', data, 80)[0],
        "field_ids_off":    struct.unpack_from('<I', data, 84)[0],
        "method_ids_size":  struct.unpack_from('<I', data, 88)[0],
        "method_ids_off":   struct.unpack_from('<I', data, 92)[0],
        "class_defs_size":  struct.unpack_from('<I', data, 96)[0],
        "class_defs_off":   struct.unpack_from('<I', data, 100)[0],
        "data_size":        struct.unpack_from('<I', data, 104)[0],
        "data_off":         struct.unpack_from('<I', data, 108)[0],
    }
    return hdr


# ─────────────────────────────────────────────────────────────────────────────
# String extraction
# ─────────────────────────────────────────────────────────────────────────────

def read_string_data_item(data, offset):
    """
    Read a string_data_item at the given offset.
    Format: ULEB128 char_count + MUTF-8 bytes + null terminator.
    Returns the decoded string.
    """
    char_count, offset = read_uleb128(data, offset)
    # Read until null terminator, up to 4 * char_count bytes (safety limit)
    max_bytes = max(char_count * 4, 4096)
    end = offset
    limit = min(offset + max_bytes, len(data))
    while end < limit and data[end] != 0:
        end += 1
    raw = data[offset:end]

    # MUTF-8 → Python string
    # MUTF-8 differs from UTF-8 in two ways:
    #   1. Null char is encoded as 0xC0 0x80 (not 0x00)
    #   2. Supplementary chars use two 3-byte CESU-8 sequences
    # For most strings, regular UTF-8 decode works fine.
    # Handle the MUTF-8 null encoding specifically:
    raw = raw.replace(b'\xc0\x80', b'\x00')
    try:
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return raw.decode("latin-1", errors="replace")


def extract_all_strings(data):
    """Extract all strings from the DEX file's string table."""
    hdr    = parse_dex_header(data)
    count  = hdr["string_ids_size"]
    ids_off = hdr["string_ids_off"]

    strings = []
    for i in range(count):
        # Each entry in string_ids is a uint32 offset to string_data_item
        if ids_off + i * 4 + 4 > len(data):
            break
        str_data_off = struct.unpack_from('<I', data, ids_off + i * 4)[0]
        try:
            s = read_string_data_item(data, str_data_off)
        except Exception as e:
            s = f"<err:{e}>"
        strings.append(s)

    return strings, hdr


# ─────────────────────────────────────────────────────────────────────────────
# String categorizer
# ─────────────────────────────────────────────────────────────────────────────

URL_RE      = re.compile(r'https?://\S{5,}|ftp://\S{5,}')
IP_RE       = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
B64_RE      = re.compile(r'^[A-Za-z0-9+/]{32,}={0,2}$')
HEX32_RE    = re.compile(r'^[0-9a-fA-F]{32}$')
HEX64_RE    = re.compile(r'^[0-9a-fA-F]{64}$')
ROOT_CMDS   = re.compile(r'\bsu\b|busybox|mount\s+-o\s+remount|/system/xbin|/sbin/su|/data/adb')
CRED_RE     = re.compile(r'(?:password|apikey|api_key|token|secret|auth_key)\s*=\s*.{3,}', re.I)
ADB_RE      = re.compile(r'adb\s+connect|adb\s+tcpip|adb\s+forward|\.setprop\s+service\.adb')
RSA_RE      = re.compile(r'BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY')


def categorize_strings(strings):
    """
    Categorize strings into security-relevant buckets.
    Returns dict: category → list of strings.
    """
    cats = defaultdict(list)

    for s in strings:
        s_stripped = s.strip()
        if not s_stripped or len(s_stripped) < 4:
            continue

        if URL_RE.search(s_stripped):
            cats["URLS"].append(s_stripped)
        if IP_RE.search(s_stripped) and not s_stripped.startswith("android."):
            cats["IP_ADDRESSES"].append(s_stripped)
        if B64_RE.fullmatch(s_stripped) and len(s_stripped) > 40:
            cats["BASE64_BLOBS"].append(s_stripped)
        if HEX32_RE.fullmatch(s_stripped) or HEX64_RE.fullmatch(s_stripped):
            cats["HEX_KEYS"].append(s_stripped)
        if ROOT_CMDS.search(s_stripped):
            cats["ROOT_COMMANDS"].append(s_stripped)
        if CRED_RE.search(s_stripped):
            cats["CREDENTIALS"].append(s_stripped)
        if ADB_RE.search(s_stripped):
            cats["ADB_COMMANDS"].append(s_stripped)
        if RSA_RE.search(s_stripped):
            cats["CRYPTO_KEYS"].append(s_stripped)

    return cats


# ─────────────────────────────────────────────────────────────────────────────
# Output
# ─────────────────────────────────────────────────────────────────────────────

USE_COLOR = sys.stdout.isatty()
CAT_SEVERITIES = {
    "URLS":          ("HIGH",   "Potential C2 / exfil endpoints"),
    "IP_ADDRESSES":  ("HIGH",   "Hardcoded IP addresses"),
    "BASE64_BLOBS":  ("MEDIUM", "Base64-encoded data — possible payload"),
    "HEX_KEYS":      ("MEDIUM", "32/64-char hex values — possible keys"),
    "ROOT_COMMANDS": ("CRITICAL","Root/shell commands — rootkit / privilege escalation"),
    "CREDENTIALS":   ("CRITICAL","Hardcoded credentials or tokens"),
    "ADB_COMMANDS":  ("HIGH",   "ADB commands — remote debugging abuse"),
    "CRYPTO_KEYS":   ("CRITICAL","Private key material embedded in APK"),
}
_C = {"CRITICAL":"\033[1;91m","HIGH":"\033[91m","MEDIUM":"\033[93m","LOW":"\033[92m","INFO":"\033[96m"}
_R = "\033[0m"


def col(sev, text):
    return f"{_C.get(sev,'')}{text}{_R}" if USE_COLOR else text


def analyze(path):
    dex_data = load_dex(path)
    print("\n" + "=" * 72)

    # Validate DEX magic
    magic = dex_data[:8]
    if magic in DEX_MAGIC_VERSIONS:
        print(f"[+] DEX magic OK: {magic!r}")
    else:
        print(f"[!] Unexpected magic: {magic!r} — continuing anyway")

    # Parse header
    hdr = parse_dex_header(dex_data)
    print(f"[*] DEX header:")
    print(f"    Version         : {hdr['magic'][4:7].decode('ascii', errors='replace')}")
    print(f"    File size       : {hdr['file_size']:,} bytes")
    print(f"    String count    : {hdr['string_ids_size']:,}")
    print(f"    Type count      : {hdr['type_ids_size']:,}")
    print(f"    Method count    : {hdr['method_ids_size']:,}")
    print(f"    Class count     : {hdr['class_defs_size']:,}")
    endian = "little-endian" if hdr["endian_tag"] == ENDIAN_CONSTANT else f"unknown (0x{hdr['endian_tag']:08X})"
    print(f"    Endian          : {endian}")

    # Extract strings
    print(f"\n[*] Extracting {hdr['string_ids_size']:,} strings...")
    strings, _ = extract_all_strings(dex_data)
    print(f"[+] Extracted {len(strings):,} strings")

    # Categorize
    categories = categorize_strings(strings)

    # Report
    print(f"\n{'='*72}")
    print("  SECURITY-RELEVANT STRINGS")
    print(f"{'='*72}")

    total_interesting = 0
    for cat, (sev, desc) in CAT_SEVERITIES.items():
        items = categories.get(cat, [])
        if not items:
            continue
        total_interesting += len(items)
        print(f"\n  {col(sev, '['+sev+']')} {cat} — {desc} ({len(items)} found)")
        print(f"  {'─'*60}")
        for item in items[:25]:  # cap at 25 per category
            display = item[:100] + "..." if len(item) > 100 else item
            print(f"    {display}")
        if len(items) > 25:
            print(f"    ... and {len(items)-25} more")

    if total_interesting == 0:
        print(f"\n  {col('INFO','[+] No security-relevant strings found in primary DEX.')}")
    else:
        print(f"\n{'─'*72}")
        print(f"  Total interesting strings: {total_interesting}")

    print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <file.apk_or_dex>")
        sys.exit(1)
    analyze(sys.argv[1])
