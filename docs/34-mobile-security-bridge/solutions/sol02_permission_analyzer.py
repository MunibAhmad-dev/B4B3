#!/usr/bin/env python3
"""
sol02_permission_analyzer.py — Complete Android Permission Analyzer
Usage: python sol02.py <app.apk>

Decodes binary AndroidManifest.xml, extracts all permissions,
scores each one, detects dangerous combinations, and prints a risk report.
"""

import sys
import struct
import zipfile
from pathlib import Path
from collections import defaultdict

# ─────────────────────────────────────────────────────────────────────────────
# AXML parsing (adapted from sol01)
# ─────────────────────────────────────────────────────────────────────────────

CHUNK_FILE_XML       = 0x00080003
CHUNK_STRING_POOL    = 0x001C0001
CHUNK_XML_START_ELEM = 0x00100102
CHUNK_XML_END_ELEM   = 0x00100103
CHUNK_XML_START_NS   = 0x00100100


def parse_string_pool(data, base):
    chunk_size    = struct.unpack_from('<I', data, base + 4)[0]
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
                if b0 & 0x80:
                    abs_off += 2
                else:
                    abs_off += 1
                b0 = data[abs_off]
                if b0 & 0x80:
                    byte_len = ((b0 & 0x7F) << 8) | data[abs_off + 1]
                    abs_off += 2
                else:
                    byte_len = b0
                    abs_off += 1
                strings.append(data[abs_off:abs_off + byte_len].decode("utf-8", errors="replace"))
            else:
                char_len = struct.unpack_from('<H', data, abs_off)[0]
                abs_off += 2
                strings.append(data[abs_off:abs_off + char_len * 2].decode("utf-16-le", errors="replace"))
        except Exception:
            strings.append(f"<str_{i}>")
    return strings


def parse_axml_permissions(data):
    """Parse binary AXML and return list of (element_name, {attr_name: attr_value})."""
    magic = struct.unpack_from('<I', data, 0)[0]
    if magic != CHUNK_FILE_XML:
        return []

    strings = []
    elements = []
    offset = 8

    while offset < len(data) - 8:
        ctype = struct.unpack_from('<I', data, offset)[0]
        csize = struct.unpack_from('<I', data, offset + 4)[0]
        if csize < 8 or offset + csize > len(data):
            break

        if ctype == CHUNK_STRING_POOL:
            strings = parse_string_pool(data, offset)

        elif ctype == CHUNK_XML_START_ELEM:
            name_idx   = struct.unpack_from('<i', data, offset + 20)[0]
            attr_size  = struct.unpack_from('<H', data, offset + 28)[0]
            attr_count = struct.unpack_from('<H', data, offset + 30)[0]
            attr_base  = offset + 38

            attrs = {}
            for a in range(attr_count):
                a_off   = attr_base + a * attr_size
                if a_off + 20 > len(data):
                    break
                a_name  = struct.unpack_from('<i', data, a_off + 4)[0]
                a_raw   = struct.unpack_from('<i', data, a_off + 8)[0]
                a_dtype = struct.unpack_from('<I', data, a_off + 12)[0]
                a_data  = struct.unpack_from('<I', data, a_off + 16)[0]
                dtype   = (a_dtype >> 24) & 0xFF

                name_s = strings[a_name] if 0 <= a_name < len(strings) else f"<{a_name}>"
                if dtype == 0x03 and 0 <= a_raw < len(strings):
                    val_s = strings[a_raw]
                elif dtype == 0x12:
                    val_s = "true" if a_data else "false"
                elif dtype == 0x10:
                    val_s = str(struct.unpack('<i', struct.pack('<I', a_data))[0])
                else:
                    val_s = f"0x{a_data:08X}"
                attrs[name_s] = val_s

            elem_name = strings[name_idx] if 0 <= name_idx < len(strings) else f"<{name_idx}>"
            elements.append((elem_name, attrs))

        offset += csize

    return elements


def extract_permissions(apk_path):
    """Open APK, decode manifest, return list of permission name strings."""
    path = Path(apk_path)
    if not path.exists():
        sys.exit(f"[!] File not found: {path}")

    with zipfile.ZipFile(str(path)) as apk:
        if "AndroidManifest.xml" not in apk.namelist():
            sys.exit("[!] AndroidManifest.xml not found")
        manifest_data = apk.read("AndroidManifest.xml")

    elements = parse_axml_permissions(manifest_data)

    permissions = []
    pkg_name    = "Unknown"
    for elem_name, attrs in elements:
        if elem_name == "manifest":
            pkg_name = attrs.get("package", "Unknown")
        elif elem_name in ("uses-permission", "uses-permission-sdk-23"):
            perm = attrs.get("name", "")
            if perm:
                permissions.append(perm)

    return pkg_name, permissions


# ─────────────────────────────────────────────────────────────────────────────
# Permission risk table (90+ entries)
# ─────────────────────────────────────────────────────────────────────────────

PERM_RISK = {
    # ── CRITICAL ──────────────────────────────────────────────────────────────
    "android.permission.BIND_DEVICE_ADMIN":
        ("CRITICAL", "Device administrator — malware uses this to block uninstall (ransomware, RAT)"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE":
        ("CRITICAL", "Accessibility service — abused by banking trojans for UI scraping and auto-tap"),
    "android.permission.BIND_INPUT_METHOD":
        ("CRITICAL", "Custom keyboard/IME — captures every keystroke typed"),
    "android.permission.SYSTEM_ALERT_WINDOW":
        ("CRITICAL", "Draw over other apps — overlay attacks, fake UI, phishing"),
    "android.permission.WRITE_SECURE_SETTINGS":
        ("CRITICAL", "Modify secure system settings — requires system or root"),
    "android.permission.FACTORY_RESET":
        ("CRITICAL", "Wipe the device — ransomware / destructive malware"),
    "android.permission.MASTER_CLEAR":
        ("CRITICAL", "Factory reset the device"),
    "android.permission.REBOOT":
        ("CRITICAL", "Reboot the device — can block user access"),
    "android.permission.MANAGE_DEVICE_ADMINS":
        ("CRITICAL", "Add/remove device administrators"),
    "android.permission.RECEIVE_EMERGENCY_BROADCAST":
        ("CRITICAL", "Receive emergency alerts before user"),

    # ── HIGH ──────────────────────────────────────────────────────────────────
    "android.permission.RECORD_AUDIO":
        ("HIGH", "Microphone access — can tap audio in background"),
    "android.permission.CAMERA":
        ("HIGH", "Camera access — can photograph / stream video"),
    "android.permission.READ_SMS":
        ("HIGH", "Read all SMS including 2FA codes"),
    "android.permission.SEND_SMS":
        ("HIGH", "Send SMS — potential fraud, premium numbers, 2FA bypass"),
    "android.permission.RECEIVE_SMS":
        ("HIGH", "Intercept incoming SMS before user sees them"),
    "android.permission.READ_CALL_LOG":
        ("HIGH", "Read complete call history"),
    "android.permission.WRITE_CALL_LOG":
        ("HIGH", "Modify or delete call records"),
    "android.permission.PROCESS_OUTGOING_CALLS":
        ("HIGH", "Intercept and redirect outgoing phone calls"),
    "android.permission.ACCESS_FINE_LOCATION":
        ("HIGH", "Precise GPS location"),
    "android.permission.ACCESS_BACKGROUND_LOCATION":
        ("HIGH", "Location access even when app is not visible — persistent tracking"),
    "android.permission.REQUEST_INSTALL_PACKAGES":
        ("HIGH", "Install additional APKs — dropper / secondary payload installer"),
    "android.permission.REQUEST_DELETE_PACKAGES":
        ("HIGH", "Remove other apps without user confirmation (Android 8+)"),
    "android.permission.INSTALL_PACKAGES":
        ("HIGH", "System-level package installation — requires system priv"),
    "android.permission.DELETE_PACKAGES":
        ("HIGH", "Silently delete packages — system privilege required"),
    "android.permission.READ_CONTACTS":
        ("HIGH", "Read all contact names, emails, phone numbers"),
    "android.permission.WRITE_CONTACTS":
        ("HIGH", "Modify or delete contacts"),
    "android.permission.GET_ACCOUNTS":
        ("HIGH", "Enumerate all Google/social accounts on device"),
    "android.permission.MANAGE_EXTERNAL_STORAGE":
        ("HIGH", "Read/write all files — unrestricted filesystem access (Android 11+)"),
    "android.permission.USE_CREDENTIALS":
        ("HIGH", "Use account credentials"),
    "android.permission.AUTHENTICATE_ACCOUNTS":
        ("HIGH", "Act as an account authenticator"),
    "android.permission.MANAGE_ACCOUNTS":
        ("HIGH", "Manage accounts — add, remove, modify"),
    "android.permission.READ_PRIVILEGED_PHONE_STATE":
        ("HIGH", "Read IMEI, IMSI and full phone identity — system privilege"),
    "android.permission.CALL_PHONE":
        ("HIGH", "Make phone calls without user interaction"),
    "android.permission.ANSWER_PHONE_CALLS":
        ("HIGH", "Answer incoming calls programmatically"),
    "android.permission.READ_PHONE_STATE":
        ("HIGH", "Read IMEI, IMSI, SIM info, call state"),
    "android.permission.WRITE_SETTINGS":
        ("HIGH", "Modify system settings"),
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS":
        ("HIGH", "Mount/unmount filesystems — can access removable media"),
    "android.permission.PACKAGE_USAGE_STATS":
        ("HIGH", "Read what apps the user opens and how often — spyware signal"),
    "android.permission.DUMP":
        ("HIGH", "Dump internal state of services — can leak sensitive data"),
    "android.permission.READ_LOGS":
        ("HIGH", "Read system log — may contain credentials, sensitive data"),
    "android.permission.CAPTURE_AUDIO_OUTPUT":
        ("HIGH", "Capture audio output — record what plays on device"),
    "android.permission.CAPTURE_VIDEO_OUTPUT":
        ("HIGH", "Capture video output — screen recording"),
    "android.permission.CHANGE_NETWORK_STATE":
        ("HIGH", "Change WiFi/mobile data state"),
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE":
        ("HIGH", "Read all notifications — 2FA codes, messages, emails"),
    "android.permission.FOREGROUND_SERVICE":
        ("HIGH", "Run persistent foreground service — battery and stealth implications"),

    # ── MEDIUM ────────────────────────────────────────────────────────────────
    "android.permission.INTERNET":
        ("MEDIUM", "Network access — required by nearly all apps but needed for exfil"),
    "android.permission.ACCESS_COARSE_LOCATION":
        ("MEDIUM", "Approximate location via network/WiFi"),
    "android.permission.READ_EXTERNAL_STORAGE":
        ("MEDIUM", "Read files from external storage"),
    "android.permission.WRITE_EXTERNAL_STORAGE":
        ("MEDIUM", "Write files to external storage"),
    "android.permission.RECEIVE_BOOT_COMPLETED":
        ("MEDIUM", "Start on boot — persistence mechanism"),
    "android.permission.BLUETOOTH":
        ("MEDIUM", "Bluetooth communication"),
    "android.permission.BLUETOOTH_SCAN":
        ("MEDIUM", "Scan for nearby Bluetooth devices — proximity tracking"),
    "android.permission.BLUETOOTH_CONNECT":
        ("MEDIUM", "Connect to paired Bluetooth devices"),
    "android.permission.NFC":
        ("MEDIUM", "NFC communication — HCE payment relay possible"),
    "android.permission.VIBRATE":
        ("LOW",    "Vibrate the device"),
    "android.permission.WAKE_LOCK":
        ("MEDIUM", "Prevent CPU from sleeping — battery drain, background activity"),
    "android.permission.CHANGE_WIFI_STATE":
        ("MEDIUM", "Connect/disconnect from WiFi networks"),
    "android.permission.ACCESS_WIFI_STATE":
        ("MEDIUM", "Read WiFi network names, signal strength"),
    "android.permission.ACCESS_NETWORK_STATE":
        ("LOW",    "Check if network is available"),
    "android.permission.USE_BIOMETRIC":
        ("MEDIUM", "Use fingerprint/face recognition"),
    "android.permission.USE_FINGERPRINT":
        ("MEDIUM", "Use fingerprint authentication"),
    "android.permission.BODY_SENSORS":
        ("MEDIUM", "Heart rate, step counter and other body sensors"),
    "android.permission.ACTIVITY_RECOGNITION":
        ("MEDIUM", "Detect physical activity (walking, running, driving)"),
    "android.permission.ADD_VOICEMAIL":
        ("MEDIUM", "Add voicemail to the system"),
    "android.permission.USE_SIP":
        ("MEDIUM", "Make SIP calls"),
    "android.permission.HIDE_OVERLAY_WINDOWS":
        ("MEDIUM", "Hide overlay windows from accessibility capture"),
    "android.permission.SCHEDULE_EXACT_ALARM":
        ("MEDIUM", "Schedule exact alarms — persistent timing for C2 callbacks"),

    # ── LOW ───────────────────────────────────────────────────────────────────
    "android.permission.VIBRATE":
        ("LOW", "Vibrate only"),
    "android.permission.FLASHLIGHT":
        ("LOW", "Control flashlight"),
    "android.permission.SET_WALLPAPER":
        ("LOW", "Change the wallpaper"),
    "android.permission.KILL_BACKGROUND_PROCESSES":
        ("LOW", "Kill background processes"),
    "android.permission.EXPAND_STATUS_BAR":
        ("LOW", "Expand/collapse the status bar"),
}


# ─────────────────────────────────────────────────────────────────────────────
# Dangerous combo detection
# ─────────────────────────────────────────────────────────────────────────────

DANGEROUS_COMBOS = [
    (
        frozenset({"android.permission.RECORD_AUDIO", "android.permission.INTERNET"}),
        "CRITICAL",
        "RECORD_AUDIO + INTERNET → possible remote microphone tap / audio exfiltration"
    ),
    (
        frozenset({"android.permission.CAMERA", "android.permission.INTERNET"}),
        "CRITICAL",
        "CAMERA + INTERNET → possible remote camera streaming"
    ),
    (
        frozenset({"android.permission.READ_SMS", "android.permission.SEND_SMS"}),
        "CRITICAL",
        "READ_SMS + SEND_SMS → SMS fraud / 2FA interception"
    ),
    (
        frozenset({"android.permission.READ_SMS", "android.permission.INTERNET"}),
        "CRITICAL",
        "READ_SMS + INTERNET → SMS content exfiltration (2FA codes, messages)"
    ),
    (
        frozenset({"android.permission.PROCESS_OUTGOING_CALLS", "android.permission.INTERNET"}),
        "HIGH",
        "PROCESS_OUTGOING_CALLS + INTERNET → call interception and reporting"
    ),
    (
        frozenset({"android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION"}),
        "HIGH",
        "ACCESS_FINE_LOCATION + ACCESS_BACKGROUND_LOCATION → silent persistent GPS tracking"
    ),
    (
        frozenset({"android.permission.READ_CONTACTS", "android.permission.INTERNET"}),
        "HIGH",
        "READ_CONTACTS + INTERNET → contact list exfiltration"
    ),
    (
        frozenset({"android.permission.READ_CALL_LOG", "android.permission.INTERNET"}),
        "HIGH",
        "READ_CALL_LOG + INTERNET → call history exfiltration"
    ),
    (
        frozenset({"android.permission.BIND_DEVICE_ADMIN"}),
        "CRITICAL",
        "BIND_DEVICE_ADMIN alone → ransomware / prevents app removal"
    ),
    (
        frozenset({"android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.INTERNET"}),
        "CRITICAL",
        "BIND_ACCESSIBILITY_SERVICE + INTERNET → banking trojan pattern (UI scraping + exfil)"
    ),
    (
        frozenset({"android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_ACCESSIBILITY_SERVICE"}),
        "CRITICAL",
        "SYSTEM_ALERT_WINDOW + BIND_ACCESSIBILITY_SERVICE → overlay attack / credential phishing"
    ),
    (
        frozenset({"android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.INTERNET"}),
        "HIGH",
        "REQUEST_INSTALL_PACKAGES + INTERNET → dropper / downloads and installs secondary payload"
    ),
    (
        frozenset({"android.permission.PACKAGE_USAGE_STATS", "android.permission.INTERNET"}),
        "HIGH",
        "PACKAGE_USAGE_STATS + INTERNET → app usage spying and reporting"
    ),
    (
        frozenset({"android.permission.BIND_NOTIFICATION_LISTENER_SERVICE", "android.permission.INTERNET"}),
        "CRITICAL",
        "NOTIFICATION_LISTENER + INTERNET → reads all notifications (OTP, messages) and exfiltrates"
    ),
    (
        frozenset({"android.permission.FOREGROUND_SERVICE", "android.permission.INTERNET",
                   "android.permission.RECEIVE_BOOT_COMPLETED"}),
        "HIGH",
        "FOREGROUND_SERVICE + INTERNET + BOOT → persistent background service with network access"
    ),
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
USE_COLOR = sys.stdout.isatty()
COLORS = {"CRITICAL": "\033[1;91m", "HIGH": "\033[91m", "MEDIUM": "\033[93m",
          "LOW": "\033[92m", "INFO": "\033[96m"}
RESET = "\033[0m"


def col(sev, text):
    return f"{COLORS.get(sev,'')}{text}{RESET}" if USE_COLOR else text


def score_permission(perm):
    if perm in PERM_RISK:
        return PERM_RISK[perm]
    # Strip to short name
    short = perm.split(".")[-1] if "." in perm else perm
    return ("INFO", f"Unknown permission: {perm}")


def detect_combos(perm_set):
    found = []
    for combo_set, severity, description in DANGEROUS_COMBOS:
        if combo_set.issubset(perm_set):
            found.append((severity, description))
    return found


def compute_score(per_perm, combos):
    counts = defaultdict(int)
    for _, sev, _ in per_perm:
        counts[sev] += 1
    for sev, _ in combos:
        counts[sev] += 1

    score = 0
    score += counts["CRITICAL"] * 30
    score += counts["HIGH"]     * 10
    score += counts["MEDIUM"]   *  3
    score += counts["LOW"]      *  1
    score = min(score, 100)

    if counts["CRITICAL"]:
        label = "CRITICAL"
    elif counts["HIGH"] >= 3:
        label = "HIGH"
    elif counts["HIGH"]:
        label = "ELEVATED"
    elif counts["MEDIUM"] >= 3:
        label = "MEDIUM"
    elif counts["MEDIUM"]:
        label = "LOW-MEDIUM"
    else:
        label = "LOW"

    return score, label


def analyze(apk_path):
    pkg_name, permissions = extract_permissions(apk_path)
    perm_set = set(permissions)

    print(f"\n{'='*72}")
    print(f"  APK Permission Analyzer")
    print(f"{'='*72}")
    print(f"  Package     : {pkg_name}")
    print(f"  Permissions : {len(permissions)}")
    print(f"  Source      : {apk_path}\n")

    # Per-permission table
    per_perm = []
    print(f"  {'Severity':<12} {'Permission':<55} Explanation")
    print(f"  {'─'*12} {'─'*55} {'─'*30}")
    for perm in sorted(permissions):
        sev, expl = score_permission(perm)
        per_perm.append((perm, sev, expl))
        sev_str = col(sev, f"[{sev}]")
        print(f"  {sev_str:<30} {perm}")
        print(f"                    {expl}")

    # Dangerous combos
    combos = detect_combos(perm_set)
    if combos:
        print(f"\n{'─'*72}")
        print("  DANGEROUS COMBINATIONS DETECTED:")
        print(f"{'─'*72}")
        for sev, desc in sorted(combos, key=lambda x: SEVERITY_ORDER[x[0]]):
            print(f"  {col(sev, '['+sev+']')} {desc}")

    # Risk score
    score, label = compute_score(per_perm, combos)
    print(f"\n{'─'*72}")
    print(f"  Risk Score  : {score}/100")
    print(f"  Risk Level  : {col(label, label)}")
    print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <app.apk>")
        sys.exit(1)
    analyze(sys.argv[1])
