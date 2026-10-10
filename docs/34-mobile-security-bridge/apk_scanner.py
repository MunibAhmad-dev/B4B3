#!/usr/bin/env python3
"""
apk_scanner.py — Standalone Android APK Security Scanner
stdlib only (zipfile, struct, json, re, os, sys, pathlib, html, io, math, collections, subprocess)

Usage:
  python apk_scanner.py <file.apk>
  python apk_scanner.py --dir <directory>        scan all .apk files
  python apk_scanner.py --device [serial]        scan device via ADB
  python apk_scanner.py --format json <file.apk>
  python apk_scanner.py --format html -o report.html <file.apk>
"""

import sys
import os
import re
import json
import struct
import zipfile
import io
import math
import collections
import subprocess
import html as html_module
from pathlib import Path

# ═════════════════════════════════════════════════════════════════════════════
# 1. APK EXTRACTION
# ═════════════════════════════════════════════════════════════════════════════

def open_apk(path):
    """
    Open an APK file. Returns dict {filename: bytes}.
    Raises SystemExit on failure.
    """
    path = Path(path)
    if not path.exists():
        sys.exit(f"[!] Not found: {path}")
    try:
        with zipfile.ZipFile(str(path)) as apk:
            return {e.filename: apk.read(e.filename) for e in apk.infolist()}, apk.infolist()
    except zipfile.BadZipFile:
        sys.exit(f"[!] Not a valid APK/ZIP: {path}")


# ═════════════════════════════════════════════════════════════════════════════
# 2. BINARY AXML MANIFEST DECODER
# ═════════════════════════════════════════════════════════════════════════════

AXML_FILE_MAGIC    = 0x00080003
AXML_STRING_POOL   = 0x001C0001
AXML_START_ELEM    = 0x00100102
AXML_END_ELEM      = 0x00100103
AXML_START_NS      = 0x00100100
TYPE_STRING        = 0x03
TYPE_INT_DEC       = 0x10
TYPE_INT_BOOL      = 0x12
TYPE_INT_HEX       = 0x11
TYPE_REFERENCE     = 0x01


def _parse_string_pool(data, base):
    string_count  = struct.unpack_from('<I', data, base + 8)[0]
    flags         = struct.unpack_from('<I', data, base + 16)[0]
    strings_start = struct.unpack_from('<I', data, base + 20)[0]
    use_utf8      = bool(flags & 0x100)
    offsets_base  = base + 28
    strings = []
    for i in range(string_count):
        off = struct.unpack_from('<I', data, offsets_base + i * 4)[0]
        abs_off = base + strings_start + off
        try:
            if use_utf8:
                b0 = data[abs_off]
                abs_off += 2 if (b0 & 0x80) else 1
                b0 = data[abs_off]
                if b0 & 0x80:
                    bl = ((b0 & 0x7F) << 8) | data[abs_off + 1]
                    abs_off += 2
                else:
                    bl = b0
                    abs_off += 1
                strings.append(data[abs_off:abs_off + bl].decode("utf-8", errors="replace"))
            else:
                cl = struct.unpack_from('<H', data, abs_off)[0]
                strings.append(data[abs_off + 2:abs_off + 2 + cl * 2].decode("utf-16-le", errors="replace"))
        except Exception:
            strings.append(f"<s{i}>")
    return strings


def decode_axml(data):
    """
    Full AXML decoder. Returns (pkg_name, elements) where
    elements is list of (elem_name, {attr_name: attr_value}).
    """
    if len(data) < 8:
        return "", []
    magic = struct.unpack_from('<I', data, 0)[0]
    if magic != AXML_FILE_MAGIC:
        return "", []

    strings  = []
    elements = []
    pkg_name = ""
    offset   = 8

    while offset < len(data) - 8:
        ctype = struct.unpack_from('<I', data, offset)[0]
        csize = struct.unpack_from('<I', data, offset + 4)[0]
        if csize < 8 or offset + csize > len(data):
            break

        if ctype == AXML_STRING_POOL:
            strings = _parse_string_pool(data, offset)

        elif ctype == AXML_START_ELEM:
            name_idx   = struct.unpack_from('<i', data, offset + 20)[0]
            attr_sz    = struct.unpack_from('<H', data, offset + 28)[0]
            attr_cnt   = struct.unpack_from('<H', data, offset + 30)[0]
            attr_base  = offset + 38
            attrs = {}
            for a in range(attr_cnt):
                aoff   = attr_base + a * attr_sz
                if aoff + 20 > len(data): break
                an     = struct.unpack_from('<i', data, aoff + 4)[0]
                ar     = struct.unpack_from('<i', data, aoff + 8)[0]
                adt    = struct.unpack_from('<I', data, aoff + 12)[0]
                adv    = struct.unpack_from('<I', data, aoff + 16)[0]
                dtype  = (adt >> 24) & 0xFF
                aname  = strings[an] if 0 <= an < len(strings) else f"<{an}>"
                if dtype == TYPE_STRING and 0 <= ar < len(strings):
                    aval = strings[ar]
                elif dtype == TYPE_INT_BOOL:
                    aval = "true" if adv else "false"
                elif dtype == TYPE_INT_DEC:
                    aval = str(struct.unpack('<i', struct.pack('<I', adv))[0])
                elif dtype == TYPE_INT_HEX:
                    aval = f"0x{adv:08X}"
                elif dtype == TYPE_REFERENCE:
                    aval = f"@0x{adv:08X}"
                else:
                    aval = f"0x{adv:08X}"
                attrs[aname] = aval

            ename = strings[name_idx] if 0 <= name_idx < len(strings) else f"<{name_idx}>"
            elements.append((ename, attrs))
            if ename == "manifest":
                pkg_name = attrs.get("package", "")

        offset += csize

    return pkg_name, elements


def extract_manifest_data(files):
    """Return (pkg_name, permissions, activities, receivers, services, providers)."""
    if "AndroidManifest.xml" not in files:
        return "unknown", [], [], [], [], []

    pkg_name, elements = decode_axml(files["AndroidManifest.xml"])
    permissions = []
    activities  = []
    receivers   = []
    services    = []
    providers   = []

    for ename, attrs in elements:
        if ename in ("uses-permission", "uses-permission-sdk-23"):
            p = attrs.get("name", "")
            if p:
                permissions.append(p)
        elif ename == "activity":
            activities.append(attrs.get("name", "?"))
        elif ename == "receiver":
            receivers.append(attrs.get("name", "?"))
        elif ename == "service":
            services.append(attrs.get("name", "?"))
        elif ename == "provider":
            providers.append(attrs.get("name", "?"))

    return pkg_name, permissions, activities, receivers, services, providers


# ═════════════════════════════════════════════════════════════════════════════
# 3. PERMISSION ANALYSIS
# ═════════════════════════════════════════════════════════════════════════════

PERM_RISK = {
    "android.permission.BIND_DEVICE_ADMIN":            ("CRITICAL", "Prevents uninstall — ransomware / RAT"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE":   ("CRITICAL", "UI scraping and auto-tap — banking trojans"),
    "android.permission.BIND_INPUT_METHOD":            ("CRITICAL", "Custom keyboard — captures all keystrokes"),
    "android.permission.SYSTEM_ALERT_WINDOW":          ("CRITICAL", "Overlay attacks — credential phishing"),
    "android.permission.WRITE_SECURE_SETTINGS":        ("CRITICAL", "Modify secure system settings"),
    "android.permission.FACTORY_RESET":                ("CRITICAL", "Wipe device — destructive malware"),
    "android.permission.RECORD_AUDIO":                 ("HIGH",     "Microphone — background audio recording"),
    "android.permission.CAMERA":                       ("HIGH",     "Camera — remote video/photo capture"),
    "android.permission.READ_SMS":                     ("HIGH",     "Read SMS including 2FA codes"),
    "android.permission.SEND_SMS":                     ("HIGH",     "Send SMS — fraud / premium numbers"),
    "android.permission.RECEIVE_SMS":                  ("HIGH",     "Intercept incoming SMS"),
    "android.permission.READ_CALL_LOG":                ("HIGH",     "Read call history"),
    "android.permission.PROCESS_OUTGOING_CALLS":       ("HIGH",     "Intercept and redirect calls"),
    "android.permission.ACCESS_FINE_LOCATION":         ("HIGH",     "Precise GPS location"),
    "android.permission.ACCESS_BACKGROUND_LOCATION":   ("HIGH",     "Background GPS — persistent tracking"),
    "android.permission.REQUEST_INSTALL_PACKAGES":     ("HIGH",     "Install other APKs — dropper"),
    "android.permission.READ_CONTACTS":                ("HIGH",     "Read all contacts"),
    "android.permission.GET_ACCOUNTS":                 ("HIGH",     "List all accounts on device"),
    "android.permission.MANAGE_EXTERNAL_STORAGE":      ("HIGH",     "Full filesystem access"),
    "android.permission.CALL_PHONE":                   ("HIGH",     "Make calls without user"),
    "android.permission.READ_PHONE_STATE":             ("HIGH",     "IMEI/IMSI — device fingerprint"),
    "android.permission.WRITE_SETTINGS":               ("HIGH",     "Modify system settings"),
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": ("HIGH", "Read all notifications"),
    "android.permission.DUMP":                         ("HIGH",     "Dump service state — data leak"),
    "android.permission.READ_LOGS":                    ("HIGH",     "Read system log"),
    "android.permission.INTERNET":                     ("MEDIUM",   "Network access"),
    "android.permission.ACCESS_COARSE_LOCATION":       ("MEDIUM",   "Approximate location"),
    "android.permission.READ_EXTERNAL_STORAGE":        ("MEDIUM",   "Read external storage"),
    "android.permission.WRITE_EXTERNAL_STORAGE":       ("MEDIUM",   "Write external storage"),
    "android.permission.RECEIVE_BOOT_COMPLETED":       ("MEDIUM",   "Persistence — auto-start on boot"),
    "android.permission.FOREGROUND_SERVICE":           ("MEDIUM",   "Persistent foreground service"),
    "android.permission.WAKE_LOCK":                    ("MEDIUM",   "Keep CPU awake"),
    "android.permission.PACKAGE_USAGE_STATS":          ("MEDIUM",   "App usage stats — spyware signal"),
    "android.permission.SCHEDULE_EXACT_ALARM":         ("MEDIUM",   "Exact scheduling — C2 timing"),
    "android.permission.BLUETOOTH_SCAN":               ("MEDIUM",   "Bluetooth scanning — proximity tracking"),
    "android.permission.NFC":                          ("MEDIUM",   "NFC — payment relay possible"),
    "android.permission.USE_BIOMETRIC":                ("MEDIUM",   "Biometric authentication"),
    "android.permission.BODY_SENSORS":                 ("MEDIUM",   "Body sensors"),
    "android.permission.ACTIVITY_RECOGNITION":         ("MEDIUM",   "Physical activity detection"),
    "android.permission.VIBRATE":                      ("LOW",      "Vibration"),
    "android.permission.ACCESS_NETWORK_STATE":         ("LOW",      "Network state check"),
    "android.permission.ACCESS_WIFI_STATE":            ("LOW",      "WiFi info"),
    "android.permission.CHANGE_NETWORK_STATE":         ("LOW",      "Change network state"),
}

DANGEROUS_COMBOS = [
    (frozenset({"android.permission.RECORD_AUDIO","android.permission.INTERNET"}),
     "CRITICAL","RECORD_AUDIO + INTERNET → remote mic tap"),
    (frozenset({"android.permission.CAMERA","android.permission.INTERNET"}),
     "CRITICAL","CAMERA + INTERNET → remote camera streaming"),
    (frozenset({"android.permission.READ_SMS","android.permission.SEND_SMS"}),
     "CRITICAL","READ_SMS + SEND_SMS → SMS fraud / 2FA bypass"),
    (frozenset({"android.permission.READ_SMS","android.permission.INTERNET"}),
     "CRITICAL","READ_SMS + INTERNET → SMS exfiltration"),
    (frozenset({"android.permission.ACCESS_FINE_LOCATION","android.permission.ACCESS_BACKGROUND_LOCATION"}),
     "HIGH","GPS + BACKGROUND_LOCATION → persistent tracking"),
    (frozenset({"android.permission.READ_CONTACTS","android.permission.INTERNET"}),
     "HIGH","READ_CONTACTS + INTERNET → contact exfil"),
    (frozenset({"android.permission.BIND_DEVICE_ADMIN"}),
     "CRITICAL","BIND_DEVICE_ADMIN → ransomware / unremovable"),
    (frozenset({"android.permission.BIND_ACCESSIBILITY_SERVICE","android.permission.INTERNET"}),
     "CRITICAL","ACCESSIBILITY + INTERNET → banking trojan pattern"),
    (frozenset({"android.permission.SYSTEM_ALERT_WINDOW","android.permission.BIND_ACCESSIBILITY_SERVICE"}),
     "CRITICAL","OVERLAY + ACCESSIBILITY → UI hijack / credential phishing"),
    (frozenset({"android.permission.REQUEST_INSTALL_PACKAGES","android.permission.INTERNET"}),
     "HIGH","INSTALL_PACKAGES + INTERNET → dropper"),
    (frozenset({"android.permission.BIND_NOTIFICATION_LISTENER_SERVICE","android.permission.INTERNET"}),
     "CRITICAL","NOTIFICATION_LISTENER + INTERNET → OTP/message exfil"),
    (frozenset({"android.permission.FOREGROUND_SERVICE","android.permission.INTERNET","android.permission.RECEIVE_BOOT_COMPLETED"}),
     "HIGH","FOREGROUND_SERVICE + BOOT + INTERNET → persistent C2 service"),
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def score_permission(perm):
    return PERM_RISK.get(perm, ("INFO", "Unknown permission"))


def detect_combos(perm_set):
    return [
        (sev, desc)
        for combo_set, sev, desc in DANGEROUS_COMBOS
        if combo_set.issubset(perm_set)
    ]


# ═════════════════════════════════════════════════════════════════════════════
# 4. DEX STRING EXTRACTION (ULEB128 + MUTF-8)
# ═════════════════════════════════════════════════════════════════════════════

DEX_MAGIC = {b"dex\n035\0", b"dex\n036\0", b"dex\n037\0", b"dex\n038\0", b"dex\n039\0"}
URL_RE    = re.compile(r'https?://\S{5,}|ftp://\S{5,}')
IP_RE     = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
B64_RE    = re.compile(r'^[A-Za-z0-9+/]{32,}={0,2}$')
ROOT_RE   = re.compile(r'\bsu\b|busybox|mount -o remount|/system/xbin|/sbin/su')
CRED_RE   = re.compile(r'(?:password|apikey|api_key|secret|auth_token)\s*=\s*.{4,}', re.I)
ADB_RE    = re.compile(r'adb connect|adb tcpip|\.setprop service\.adb')
RSA_RE    = re.compile(r'BEGIN.*PRIVATE KEY')


def _uleb128(data, off):
    r = shift = 0
    while True:
        b = data[off]; off += 1
        r |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            return r, off


def _read_dex_string(data, off):
    _, off = _uleb128(data, off)
    end = off
    while end < len(data) and data[end]:
        end += 1
    raw = data[off:end].replace(b'\xc0\x80', b'\x00')
    return raw.decode("utf-8", errors="replace")


def extract_dex_strings(dex_bytes):
    """Extract all strings from a DEX file bytes object."""
    if dex_bytes[:8] not in DEX_MAGIC:
        return []
    try:
        count  = struct.unpack_from('<I', dex_bytes, 56)[0]
        ids_off = struct.unpack_from('<I', dex_bytes, 60)[0]
        strings = []
        for i in range(count):
            if ids_off + i * 4 + 4 > len(dex_bytes):
                break
            sdo = struct.unpack_from('<I', dex_bytes, ids_off + i * 4)[0]
            try:
                strings.append(_read_dex_string(dex_bytes, sdo))
            except Exception:
                strings.append("")
        return strings
    except Exception:
        return []


def categorize_dex_strings(strings):
    cats = collections.defaultdict(list)
    for s in strings:
        ss = s.strip()
        if not ss or len(ss) < 4:
            continue
        if URL_RE.search(ss):
            cats["urls"].append(ss)
        if IP_RE.search(ss) and not ss.startswith("android."):
            cats["ips"].append(ss)
        if B64_RE.fullmatch(ss) and len(ss) > 40:
            cats["b64"].append(ss)
        if ROOT_RE.search(ss):
            cats["root_cmds"].append(ss)
        if CRED_RE.search(ss):
            cats["credentials"].append(ss)
        if ADB_RE.search(ss):
            cats["adb_cmds"].append(ss)
        if RSA_RE.search(ss):
            cats["rsa_keys"].append(ss)
    return cats


# ═════════════════════════════════════════════════════════════════════════════
# 5. NATIVE LIBRARY INVENTORY
# ═════════════════════════════════════════════════════════════════════════════

ELF_MACHINES = {
    0x28: "ARM (32-bit)", 0xB7: "AArch64 (ARM64)",
    0x03: "x86 (32-bit)", 0x3E: "x86-64",
    0x14: "PowerPC",       0xF3: "RISC-V",
}


def inventory_native_libs(files):
    """Return list of {path, arch, size, strings_preview}."""
    libs = []
    for name, data in files.items():
        if not (name.startswith("lib/") and name.endswith(".so")):
            continue
        entry = {"path": name, "arch": "unknown", "size": len(data), "strings": []}
        if len(data) >= 20 and data[:4] == b'\x7fELF':
            bits    = data[4]  # 1=32-bit, 2=64-bit
            machine = struct.unpack_from('<H', data, 18)[0]
            entry["arch"] = ELF_MACHINES.get(machine, f"machine=0x{machine:04X}")
            entry["bits"] = 32 if bits == 1 else 64
        # extract printable strings >= 6 chars
        raw_strs = re.findall(rb'[\x20-\x7e]{6,}', data)
        entry["strings"] = [s.decode("ascii") for s in raw_strs[:10]]
        libs.append(entry)
    return libs


# ═════════════════════════════════════════════════════════════════════════════
# 6. SIGNING CERTIFICATE CHECK
# ═════════════════════════════════════════════════════════════════════════════

def check_signing_cert(files):
    """
    Locate META-INF/*.RSA or *.DSA, read raw DER PKCS#7 bytes.
    Returns dict with {file, size, self_signed_indicator, subject_bytes_hex}.
    """
    cert_files = [f for f in files if re.match(r'META-INF/.+\.(RSA|DSA|EC)$', f, re.I)]
    if not cert_files:
        return {"found": False, "file": None}

    cert_file = cert_files[0]
    data = files[cert_file]

    info = {
        "found":     True,
        "file":      cert_file,
        "size":      len(data),
        "algorithm": cert_file.split(".")[-1].upper(),
    }

    # Crude self-signed check: in a self-signed cert the issuer == subject.
    # The PKCS#7 DER structure is complex; we do a heuristic:
    # look for the OID for commonName (2.5.4.3 → 55 04 03) appearing twice at different offsets.
    cn_oid = bytes([0x55, 0x04, 0x03])
    positions = [i for i in range(len(data)) if data[i:i+3] == cn_oid]
    info["cn_count"] = len(positions)
    info["self_signed_likely"] = len(positions) == 2 and positions[0] != positions[1]

    # Fingerprint = SHA-256 of the raw DER bytes (stdlib hashlib)
    try:
        import hashlib
        info["sha256_fingerprint"] = hashlib.sha256(data).hexdigest()
    except Exception:
        info["sha256_fingerprint"] = "unavailable"

    return info


# ═════════════════════════════════════════════════════════════════════════════
# 7. ENTROPY CHECK (assets / high-entropy files)
# ═════════════════════════════════════════════════════════════════════════════

def _entropy(data):
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total  = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


MEDIA_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".mp3", ".mp4",
              ".ttf", ".otf", ".woff", ".webp", ".svg"}


def check_high_entropy_assets(files):
    """Return list of {path, size, entropy} for assets with entropy > 7.2."""
    suspicious = []
    for name, data in files.items():
        if not name.startswith("assets/"):
            continue
        ext = Path(name).suffix.lower()
        if ext in MEDIA_EXTS or len(data) < 256:
            continue
        e = _entropy(data)
        if e > 7.2:
            suspicious.append({"path": name, "size": len(data), "entropy": round(e, 3)})
    return sorted(suspicious, key=lambda x: -x["entropy"])


# ═════════════════════════════════════════════════════════════════════════════
# 8. ADB LIVE DEVICE SCAN
# ═════════════════════════════════════════════════════════════════════════════

def _adb_run(args, timeout=10):
    try:
        r = subprocess.run(["adb"] + args, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.returncode
    except Exception:
        return "", 1


def adb_device_scan(serial=None):
    """Run a basic security scan on a connected ADB device. Returns dict."""
    target = ["-s", serial] if serial else []

    def shell(cmd):
        out, _ = _adb_run(target + ["shell", cmd], timeout=8)
        return out.strip()

    model   = shell("getprop ro.product.model")
    version = shell("getprop ro.build.version.release")
    debug   = shell("getprop ro.debuggable")
    selinux = shell("getenforce")

    root_indicators = []
    for rp in ["/system/xbin/su", "/sbin/su", "/data/adb/magisk"]:
        out = shell(f"ls {rp} 2>/dev/null")
        if out and "No such" not in out and "not found" not in out:
            root_indicators.append(f"Found: {rp}")
    su_path = shell("which su 2>/dev/null")
    if su_path:
        root_indicators.append(f"su in PATH: {su_path}")

    open_ports = []
    netstat_out = shell("netstat -tlnp 2>/dev/null || ss -tlnp 2>/dev/null")
    for line in netstat_out.splitlines():
        if "LISTEN" in line:
            open_ports.append(line.strip())

    return {
        "model":           model,
        "android_version": version,
        "debug_build":     debug == "1",
        "selinux":         selinux,
        "root_indicators": root_indicators,
        "open_ports":      open_ports[:10],
    }


# ═════════════════════════════════════════════════════════════════════════════
# 9. RISK SCORE
# ═════════════════════════════════════════════════════════════════════════════

def compute_risk(per_perm, combos, dex_cats, entropy_assets, cert_info):
    """Return (score 0-100, label, top_findings list)."""
    sev_counts = collections.defaultdict(int)
    top = []

    for perm, sev, expl in per_perm:
        sev_counts[sev] += 1

    for sev, desc in combos:
        sev_counts[sev] += 1
        top.append((sev, desc))

    if dex_cats.get("credentials"):
        sev_counts["CRITICAL"] += 1
        top.append(("CRITICAL", f"Hardcoded credentials in DEX: {dex_cats['credentials'][0][:50]}"))
    if dex_cats.get("rsa_keys"):
        sev_counts["CRITICAL"] += 1
        top.append(("CRITICAL", "Private key material found in DEX strings"))
    if dex_cats.get("root_cmds"):
        sev_counts["HIGH"] += 1
        top.append(("HIGH", f"Root/shell commands in DEX: {dex_cats['root_cmds'][0][:50]}"))
    if entropy_assets:
        sev_counts["MEDIUM"] += len(entropy_assets)
        top.append(("MEDIUM", f"High-entropy assets (possible encrypted payload): {entropy_assets[0]['path']}"))

    score = min(
        sev_counts["CRITICAL"] * 30 +
        sev_counts["HIGH"]     * 10 +
        sev_counts["MEDIUM"]   *  3,
        100
    )

    if sev_counts["CRITICAL"]:
        label = "CRITICAL"
    elif sev_counts["HIGH"] >= 3:
        label = "HIGH"
    elif sev_counts["HIGH"]:
        label = "ELEVATED"
    elif sev_counts["MEDIUM"] >= 3:
        label = "MEDIUM"
    elif sev_counts["MEDIUM"]:
        label = "LOW-MEDIUM"
    else:
        label = "LOW"

    top_sorted = sorted(top, key=lambda x: SEVERITY_ORDER.get(x[0], 9))[:8]
    return score, label, top_sorted


# ═════════════════════════════════════════════════════════════════════════════
# 10. OUTPUT — TEXT (ANSI color)
# ═════════════════════════════════════════════════════════════════════════════

USE_COLOR = sys.stdout.isatty()
_C = {
    "CRITICAL":  "\033[1;91m", "HIGH":      "\033[91m",
    "ELEVATED":  "\033[91m",   "MEDIUM":    "\033[93m",
    "LOW-MEDIUM":"\033[93m",   "LOW":       "\033[92m",
    "INFO":      "\033[96m",
}
_R = "\033[0m"


def col(k, t):
    return f"{_C.get(k,'')}{t}{_R}" if USE_COLOR else t


def print_text_report(apk_path, pkg_name, permissions, per_perm, combos,
                      dex_summary, entropy_assets, cert_info, native_libs,
                      score, risk_label, top_findings):
    W = 72
    print(f"\n{'='*W}")
    print(f"  APK Security Report")
    print(f"{'='*W}")
    print(f"  File       : {apk_path}")
    print(f"  Package    : {pkg_name or 'unknown'}")
    print(f"  Risk Score : {score}/100  [{col(risk_label, risk_label)}]")

    # Permissions
    print(f"\n{'─'*W}")
    print("  PERMISSIONS")
    print(f"{'─'*W}")
    for perm, sev, expl in sorted(per_perm, key=lambda x: SEVERITY_ORDER.get(x[1], 9)):
        print(f"  {col(sev, '['+sev+']'):<30} {perm}")
        print(f"    {expl}")

    # Combos
    if combos:
        print(f"\n{'─'*W}")
        print("  DANGEROUS COMBINATIONS")
        print(f"{'─'*W}")
        for sev, desc in sorted(combos, key=lambda x: SEVERITY_ORDER.get(x[0], 9)):
            print(f"  {col(sev, '['+sev+']')} {desc}")

    # DEX strings
    if any(dex_summary.values()):
        print(f"\n{'─'*W}")
        print("  DEX STRING FINDINGS")
        print(f"{'─'*W}")
        cat_sev = {
            "credentials":"CRITICAL","rsa_keys":"CRITICAL","root_cmds":"HIGH",
            "adb_cmds":"HIGH","urls":"MEDIUM","ips":"MEDIUM","b64":"MEDIUM",
        }
        for cat, items in dex_summary.items():
            if not items:
                continue
            sev = cat_sev.get(cat, "INFO")
            print(f"  {col(sev, '['+sev+']')} {cat.upper()} ({len(items)})")
            for item in items[:5]:
                print(f"    {item[:80]}")

    # Entropy
    if entropy_assets:
        print(f"\n{'─'*W}")
        print("  HIGH-ENTROPY ASSETS (possible encrypted payloads)")
        print(f"{'─'*W}")
        for a in entropy_assets:
            print(f"  {col('MEDIUM','[MEDIUM]')} {a['path']}  entropy={a['entropy']}  size={a['size']:,}")

    # Native libs
    if native_libs:
        print(f"\n{'─'*W}")
        print("  NATIVE LIBRARIES")
        print(f"{'─'*W}")
        for lib in native_libs:
            print(f"  {lib['path']:<55} {lib['arch']:<20} {lib['size']:>8,} B")

    # Certificate
    print(f"\n{'─'*W}")
    print("  SIGNING CERTIFICATE")
    print(f"{'─'*W}")
    if cert_info.get("found"):
        self_signed = cert_info.get("self_signed_likely", False)
        ss_str = col("MEDIUM", "likely self-signed") if self_signed else "not self-signed"
        print(f"  {cert_info['file']}  [{cert_info['algorithm']}]  {ss_str}")
        print(f"  SHA-256: {cert_info.get('sha256_fingerprint','?')}")
    else:
        print(f"  {col('HIGH','[!] No signing certificate found')}")

    # Top findings
    if top_findings:
        print(f"\n{'─'*W}")
        print("  TOP FINDINGS")
        print(f"{'─'*W}")
        for sev, desc in top_findings:
            print(f"  {col(sev, '['+sev+']')} {desc}")

    print()


# ═════════════════════════════════════════════════════════════════════════════
# 11. OUTPUT — JSON
# ═════════════════════════════════════════════════════════════════════════════

def build_json_report(apk_path, pkg_name, per_perm, combos, dex_summary,
                      entropy_assets, cert_info, native_libs, score, risk_label, top_findings):
    return {
        "apk":          str(apk_path),
        "package":      pkg_name,
        "score":        score,
        "risk_label":   risk_label,
        "permissions":  [{"name": p, "risk": s, "explanation": e} for p, s, e in per_perm],
        "combos":       [{"risk": s, "description": d} for s, d in combos],
        "dex_strings":  {cat: items[:20] for cat, items in dex_summary.items()},
        "entropy_assets": entropy_assets,
        "native_libs":  [{"path": l["path"], "arch": l["arch"], "size": l["size"]} for l in native_libs],
        "certificate":  cert_info,
        "top_findings": [{"risk": s, "description": d} for s, d in top_findings],
    }


# ═════════════════════════════════════════════════════════════════════════════
# 12. OUTPUT — HTML
# ═════════════════════════════════════════════════════════════════════════════

_SEV_COLOR = {
    "CRITICAL":  "#e53935", "HIGH":       "#e65100",
    "ELEVATED":  "#e65100", "MEDIUM":     "#f9a825",
    "LOW-MEDIUM":"#9e9d24", "LOW":        "#2e7d32",
    "INFO":      "#0277bd",
}


def _e(s):
    return html_module.escape(str(s))


def build_html_report(apk_path, pkg_name, per_perm, combos, dex_summary,
                      entropy_assets, cert_info, native_libs, score, risk_label, top_findings):
    rc = _SEV_COLOR.get(risk_label, "#555")

    perm_rows = "".join(
        f"<tr><td><span class='badge' style='background:{_SEV_COLOR.get(s,\"#888\")}'>{_e(s)}</span></td>"
        f"<td><code>{_e(p)}</code></td><td>{_e(e)}</td></tr>"
        for p, s, e in sorted(per_perm, key=lambda x: SEVERITY_ORDER.get(x[1], 9))
    )
    combo_rows = "".join(
        f"<tr><td><span class='badge' style='background:{_SEV_COLOR.get(s,\"#888\")}'>{_e(s)}</span></td>"
        f"<td>{_e(d)}</td></tr>"
        for s, d in sorted(combos, key=lambda x: SEVERITY_ORDER.get(x[0], 9))
    )
    finding_rows = "".join(
        f"<tr><td><span class='badge' style='background:{_SEV_COLOR.get(s,\"#888\")}'>{_e(s)}</span></td>"
        f"<td>{_e(d)}</td></tr>"
        for s, d in top_findings
    )
    lib_rows = "".join(
        f"<tr><td><code>{_e(l['path'])}</code></td><td>{_e(l['arch'])}</td>"
        f"<td>{l['size']:,}</td></tr>"
        for l in native_libs
    )
    entropy_rows = "".join(
        f"<tr><td><code>{_e(a['path'])}</code></td><td>{a['entropy']}</td>"
        f"<td>{a['size']:,}</td></tr>"
        for a in entropy_assets
    )

    cert_html = (
        f"<p><code>{_e(cert_info['file'])}</code> [{_e(cert_info['algorithm'])}] — "
        f"{'<span style=\"color:#f9a825\">likely self-signed</span>' if cert_info.get('self_signed_likely') else 'not self-signed'}<br>"
        f"SHA-256: <code>{cert_info.get('sha256_fingerprint','?')}</code></p>"
        if cert_info.get("found") else
        "<p style='color:#e53935'>No signing certificate found</p>"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>APK Scan: {_e(pkg_name or Path(apk_path).name)}</title>
<style>
  body{{font-family:system-ui,sans-serif;max-width:1000px;margin:0 auto;padding:24px;background:#f5f5f5;color:#212121}}
  h1{{color:#1a237e;border-bottom:3px solid #1a237e;padding-bottom:8px}}
  h2{{color:#1a237e;margin-top:32px;border-bottom:1px solid #9fa8da}}
  .score{{display:inline-block;padding:6px 18px;border-radius:4px;color:#fff;font-weight:bold;background:{rc}}}
  .card{{background:#fff;border-radius:6px;padding:16px 20px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,.15)}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:3px;color:#fff;font-size:.75em;font-weight:bold}}
  table{{width:100%;border-collapse:collapse;margin-top:8px}}
  th{{background:#1a237e;color:#fff;padding:6px 10px;text-align:left;font-size:.85em}}
  td{{padding:5px 10px;border-bottom:1px solid #e0e0e0;font-size:.85em;vertical-align:top}}
  tr:hover td{{background:#e8eaf6}}
  code{{background:#e8eaf6;padding:1px 4px;border-radius:2px;font-size:.85em}}
  .grid{{display:grid;grid-template-columns:150px 1fr;gap:4px 12px;font-size:.9em}}
  .label{{font-weight:bold;color:#555}}
</style>
</head>
<body>
<h1>APK Security Scan Report</h1>
<div class="card">
  <div class="grid">
    <span class="label">File</span><span>{_e(apk_path)}</span>
    <span class="label">Package</span><span>{_e(pkg_name or 'unknown')}</span>
    <span class="label">Risk Score</span><span><span class="score">{risk_label} ({score}/100)</span></span>
  </div>
</div>

<h2>Permissions ({len(per_perm)})</h2>
<table><tr><th>Risk</th><th>Permission</th><th>Explanation</th></tr>
{perm_rows or '<tr><td colspan="3"><em>None declared</em></td></tr>'}
</table>

{('<h2>Dangerous Combinations</h2><table><tr><th>Risk</th><th>Description</th></tr>' + combo_rows + '</table>') if combo_rows else ''}

{('<h2>Top Findings</h2><table><tr><th>Risk</th><th>Description</th></tr>' + finding_rows + '</table>') if finding_rows else ''}

{('<h2>High-Entropy Assets</h2><table><tr><th>Path</th><th>Entropy</th><th>Size</th></tr>' + entropy_rows + '</table>') if entropy_rows else ''}

{('<h2>Native Libraries</h2><table><tr><th>Path</th><th>Architecture</th><th>Size</th></tr>' + lib_rows + '</table>') if lib_rows else ''}

<h2>Signing Certificate</h2>
{cert_html}

<p style="margin-top:40px;font-size:.75em;color:#9e9e9e">Generated by apk_scanner.py</p>
</body>
</html>"""


# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

def scan_apk(apk_path, fmt="text", out_file=None):
    """Scan a single APK file and output the report."""
    files, entries = open_apk(apk_path)
    pkg_name, permissions, activities, receivers, services, providers = extract_manifest_data(files)

    per_perm = [(p, *score_permission(p)) for p in permissions]
    combos   = detect_combos(set(permissions))

    # DEX strings
    dex_summary = collections.defaultdict(list)
    for dex_name in sorted(n for n in files if re.fullmatch(r'classes\d*\.dex', n)):
        cats = categorize_dex_strings(extract_dex_strings(files[dex_name]))
        for k, v in cats.items():
            dex_summary[k].extend(v)

    entropy_assets = check_high_entropy_assets(files)
    native_libs    = inventory_native_libs(files)
    cert_info      = check_signing_cert(files)

    score, risk_label, top_findings = compute_risk(per_perm, combos, dex_summary,
                                                    entropy_assets, cert_info)

    if fmt == "json":
        report = build_json_report(str(apk_path), pkg_name, per_perm, combos,
                                   dex_summary, entropy_assets, cert_info,
                                   native_libs, score, risk_label, top_findings)
        output = json.dumps(report, indent=2)
        if out_file:
            Path(out_file).write_text(output, encoding="utf-8")
            print(f"[+] JSON report: {out_file}")
        else:
            print(output)

    elif fmt == "html":
        output = build_html_report(str(apk_path), pkg_name, per_perm, combos,
                                   dex_summary, entropy_assets, cert_info,
                                   native_libs, score, risk_label, top_findings)
        target = out_file or "apk_scan_report.html"
        Path(target).write_text(output, encoding="utf-8")
        print(f"[+] HTML report: {target}")

    else:
        print_text_report(str(apk_path), pkg_name, permissions, per_perm, combos,
                          dex_summary, entropy_assets, cert_info, native_libs,
                          score, risk_label, top_findings)


def main():
    args      = sys.argv[1:]
    fmt       = "text"
    out_file  = None
    scan_dir  = None
    device    = False
    dev_serial = None

    filtered = []
    i = 0
    while i < len(args):
        if args[i] == "--format" and i + 1 < len(args):
            fmt = args[i+1].lower(); i += 2
        elif args[i] == "-o" and i + 1 < len(args):
            out_file = args[i+1]; i += 2
        elif args[i] == "--dir" and i + 1 < len(args):
            scan_dir = args[i+1]; i += 2
        elif args[i] == "--device":
            device = True
            if i + 1 < len(args) and not args[i+1].startswith("--"):
                dev_serial = args[i+1]; i += 2
            else:
                i += 1
        else:
            filtered.append(args[i]); i += 1

    if device:
        print("[*] ADB Device Scan")
        result = adb_device_scan(dev_serial)
        if fmt == "json":
            print(json.dumps(result, indent=2))
        else:
            print(f"  Model           : {result['model']}")
            print(f"  Android version : {result['android_version']}")
            print(f"  Debug build     : {result['debug_build']}")
            print(f"  SELinux         : {result['selinux']}")
            print(f"  Root indicators : {result['root_indicators'] or ['none']}")
            print(f"  Open ports      : {result['open_ports'][:5] or ['none detected']}")
        return

    if scan_dir:
        apks = list(Path(scan_dir).rglob("*.apk"))
        if not apks:
            print(f"[!] No .apk files found in {scan_dir}")
            return
        print(f"[*] Found {len(apks)} APK(s) in {scan_dir}")
        for apk in apks:
            print(f"\n{'='*72}")
            print(f"  Scanning: {apk}")
            try:
                scan_apk(apk, fmt=fmt, out_file=None)
            except SystemExit as e:
                print(f"  [!] Error: {e}")
        return

    if not filtered:
        print("Usage: python apk_scanner.py [--format text|json|html] [-o output] <file.apk>")
        print("       python apk_scanner.py --dir <directory>")
        print("       python apk_scanner.py --device [serial]")
        sys.exit(1)

    scan_apk(filtered[0], fmt=fmt, out_file=out_file)


if __name__ == "__main__":
    main()
