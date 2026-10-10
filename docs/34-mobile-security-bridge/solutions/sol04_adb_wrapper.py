#!/usr/bin/env python3
"""
sol04_adb_wrapper.py — Complete ADB Wrapper and Device Security Scanner
Usage: python sol04.py              (scan first connected device)
       python sol04.py <serial>     (scan specific device)
       python sol04.py --list       (list devices only)
"""

import sys
import re
import subprocess
from typing import List, Optional
from pathlib import Path


class AdbWrapper:
    """Complete Python wrapper around the adb command-line tool."""

    def __init__(self, adb_path: str = "adb"):
        self.adb_path = adb_path
        self._verify_adb()

    def _verify_adb(self):
        try:
            r = subprocess.run([self.adb_path, "version"],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                first_line = r.stdout.splitlines()[0] if r.stdout else "unknown"
                print(f"[+] {first_line}")
        except FileNotFoundError:
            sys.exit(f"[!] adb not found at '{self.adb_path}'.\n"
                     f"    Install Android SDK platform-tools and add to PATH.")
        except subprocess.TimeoutExpired:
            print("[!] adb version timed out — ADB server may be slow to start")

    def _run(self, args: list, timeout: int = 10) -> subprocess.CompletedProcess:
        """Run adb with the given argument list. Returns CompletedProcess."""
        try:
            return subprocess.run(
                [self.adb_path] + args,
                capture_output=True, text=True, timeout=timeout
            )
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(args, returncode=1,
                                               stdout="", stderr="timeout")
        except FileNotFoundError:
            return subprocess.CompletedProcess(args, returncode=1,
                                               stdout="", stderr="adb not found")

    # ─────────────────────────────────────────────────────────────────────────
    # Device management
    # ─────────────────────────────────────────────────────────────────────────

    def devices(self) -> List[dict]:
        """
        Run `adb devices -l` and return list of device dicts.
        Each dict: {serial, state, product, model, transport_id}
        """
        r = self._run(["devices", "-l"], timeout=10)
        devices = []
        for line in r.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("List of devices"):
                continue
            # Format: <serial>  <state>  [key:value ...]
            parts = line.split(None, 2)
            if len(parts) < 2:
                continue
            serial, state = parts[0], parts[1]
            info_str = parts[2] if len(parts) > 2 else ""

            dev = {"serial": serial, "state": state, "model": "unknown",
                   "product": "", "transport_id": ""}
            for kv in info_str.split():
                if ":" in kv:
                    k, v = kv.split(":", 1)
                    if k == "model":
                        dev["model"] = v.replace("_", " ")
                    elif k == "product":
                        dev["product"] = v
                    elif k == "transport_id":
                        dev["transport_id"] = v
            devices.append(dev)
        return devices

    # ─────────────────────────────────────────────────────────────────────────
    # Shell command execution
    # ─────────────────────────────────────────────────────────────────────────

    def shell(self, serial: str, cmd: str, timeout: int = 10) -> str:
        """Run `adb -s <serial> shell <cmd>` and return stdout."""
        r = self._run(["-s", serial, "shell", cmd], timeout=timeout)
        return r.stdout

    # ─────────────────────────────────────────────────────────────────────────
    # File transfer
    # ─────────────────────────────────────────────────────────────────────────

    def pull(self, serial: str, remote: str, local: str) -> bool:
        """Pull a file from the device. Returns True on success."""
        r = self._run(["-s", serial, "pull", remote, local], timeout=30)
        if r.returncode == 0:
            print(f"[+] Pulled {remote} → {local}")
            return True
        print(f"[!] pull failed: {r.stderr.strip() or r.stdout.strip()}")
        return False

    def push(self, serial: str, local: str, remote: str) -> bool:
        """Push a file to the device. Returns True on success."""
        r = self._run(["-s", serial, "push", local, remote], timeout=30)
        return r.returncode == 0

    # ─────────────────────────────────────────────────────────────────────────
    # App / package management
    # ─────────────────────────────────────────────────────────────────────────

    def install(self, serial: str, apk_path: str) -> tuple:
        """Install an APK. Returns (success: bool, output: str)."""
        r = self._run(["-s", serial, "install", "-r", apk_path], timeout=120)
        success = r.returncode == 0 and "Success" in r.stdout
        return success, (r.stdout + r.stderr).strip()

    def packages(self, serial: str) -> dict:
        """
        Return dict {package_name: apk_path} from `pm list packages -f`.
        """
        out = self.shell(serial, "pm list packages -f")
        result = {}
        for line in out.splitlines():
            line = line.strip()
            # Format: package:<path>=<package_name>
            m = re.match(r'package:(.+?)=([^\s]+)$', line)
            if m:
                result[m.group(2)] = m.group(1)
        return result

    def get_package_path(self, serial: str, package: str) -> str:
        """Return the APK path for an installed package."""
        out = self.shell(serial, f"pm path {package}")
        # Output: "package:/data/app/..."
        m = re.search(r'package:(.+)', out)
        return m.group(1).strip() if m else ""

    # ─────────────────────────────────────────────────────────────────────────
    # Process and system info
    # ─────────────────────────────────────────────────────────────────────────

    def running_procs(self, serial: str) -> List[dict]:
        """Return list of running processes as [{pid, name, user}]."""
        out = self.shell(serial, "ps -A")
        procs = []
        for line in out.splitlines()[1:]:  # skip header
            parts = line.split()
            if len(parts) >= 9:
                procs.append({
                    "user": parts[0],
                    "pid":  parts[1],
                    "ppid": parts[2],
                    "name": parts[-1],
                })
        return procs

    def logcat(self, serial: str, lines: int = 200, tag_filter: Optional[str] = None) -> str:
        """Return recent logcat output."""
        cmd = f"logcat -d -t {lines}"
        if tag_filter:
            cmd += f" -s {tag_filter}"
        return self.shell(serial, cmd, timeout=15)

    def get_prop(self, serial: str, prop: str) -> str:
        """Return a device property via getprop."""
        return self.shell(serial, f"getprop {prop}").strip()

    # ─────────────────────────────────────────────────────────────────────────
    # Security audit
    # ─────────────────────────────────────────────────────────────────────────

    def scan_device(self, serial: str) -> dict:
        """
        Perform a security audit of the connected device.
        Returns a dict of findings.
        """
        audit = {
            "serial":            serial,
            "model":             self.get_prop(serial, "ro.product.model"),
            "android_version":   self.get_prop(serial, "ro.build.version.release"),
            "sdk_version":       self.get_prop(serial, "ro.build.version.sdk"),
            "build_type":        self.get_prop(serial, "ro.build.type"),
            "debuggable":        self.get_prop(serial, "ro.debuggable"),
            "usb_config":        self.get_prop(serial, "persist.sys.usb.config"),
            "selinux_status":    self.shell(serial, "getenforce").strip(),
            "root_indicators":   [],
            "developer_flags":   [],
            "open_ports":        [],
            "suspicious_pkgs":   [],
            "logcat_warnings":   [],
        }

        # Root indicators
        root_paths = [
            "/system/xbin/su", "/sbin/su", "/system/bin/su",
            "/data/local/tmp/su", "/data/adb/magisk", "/sbin/.magisk",
        ]
        for rp in root_paths:
            result = self.shell(serial, f"ls {rp} 2>/dev/null").strip()
            if result and "No such file" not in result and "not found" not in result:
                audit["root_indicators"].append(f"Found: {rp}")

        which_su = self.shell(serial, "which su 2>/dev/null").strip()
        if which_su:
            audit["root_indicators"].append(f"su in PATH: {which_su}")

        which_busybox = self.shell(serial, "which busybox 2>/dev/null").strip()
        if which_busybox:
            audit["root_indicators"].append(f"busybox found: {which_busybox}")

        # Developer options / flags
        if audit["debuggable"] == "1":
            audit["developer_flags"].append("ro.debuggable=1 (debug build — low trust device)")
        if "adb" in audit["usb_config"]:
            audit["developer_flags"].append(f"USB config includes 'adb': {audit['usb_config']}")
        adb_enabled = self.get_prop(serial, "persist.service.adb.enable")
        if adb_enabled == "1":
            audit["developer_flags"].append("persist.service.adb.enable=1 (ADB always on)")

        # Open ports
        netstat_out = self.shell(serial, "netstat -tlnp 2>/dev/null || ss -tlnp 2>/dev/null")
        for line in netstat_out.splitlines():
            if "LISTEN" in line or "UNCONN" in line:
                parts = line.split()
                if parts:
                    audit["open_ports"].append(line.strip())

        # Suspicious packages (non-Play, sideloaded)
        all_pkgs = self.shell(serial, "pm list packages -i -f 2>/dev/null")
        for line in all_pkgs.splitlines():
            m = re.match(r'package:(.+?)=(.+)\s+installer=(.*)$', line)
            if m:
                apk_path    = m.group(1)
                pkg_name    = m.group(2)
                installer   = m.group(3).strip()
                # Unknown installer = sideloaded
                if installer not in ("com.android.packageinstaller",
                                     "com.google.android.packageinstaller",
                                     "com.google.android.gms",
                                     "com.sec.android.app.packageinstaller",
                                     "") and not installer.startswith("com.android.vending"):
                    audit["suspicious_pkgs"].append(
                        f"{pkg_name} (installer: {installer or 'unknown'})"
                    )

        # Recent logcat warnings
        logcat_out = self.logcat(serial, lines=100)
        for line in logcat_out.splitlines():
            if any(kw in line for kw in ("FATAL EXCEPTION", "W/SELinux", "E/SELinux",
                                          "Permission denial", "SecurityException")):
                audit["logcat_warnings"].append(line.strip()[:120])

        return audit


# ─────────────────────────────────────────────────────────────────────────────
# Output helpers
# ─────────────────────────────────────────────────────────────────────────────

USE_COLOR = sys.stdout.isatty()
_C = {
    "CRITICAL": "\033[1;91m", "HIGH": "\033[91m",
    "MEDIUM":   "\033[93m",   "LOW":  "\033[92m",
    "INFO":     "\033[96m",
}
_R = "\033[0m"


def col(sev, text):
    return f"{_C.get(sev,'')}{text}{_R}" if USE_COLOR else text


def print_device_report(audit: dict):
    print(f"\n{'='*72}")
    print(f"  ADB Device Security Report")
    print(f"{'='*72}")
    print(f"  Serial          : {audit['serial']}")
    print(f"  Model           : {audit['model']}")
    print(f"  Android version : {audit['android_version']} (SDK {audit['sdk_version']})")
    print(f"  Build type      : {audit['build_type']}")
    print(f"  SELinux         : {audit['selinux_status'] or 'unknown'}")

    print(f"\n{'─'*72}")
    print("  ROOT INDICATORS")
    print(f"{'─'*72}")
    if audit["root_indicators"]:
        for item in audit["root_indicators"]:
            print(f"  {col('CRITICAL','[!]')} {item}")
    else:
        print(f"  {col('LOW','[+] No root indicators found.')}")

    print(f"\n{'─'*72}")
    print("  DEVELOPER / DEBUG FLAGS")
    print(f"{'─'*72}")
    if audit["developer_flags"]:
        for item in audit["developer_flags"]:
            print(f"  {col('HIGH','[!]')} {item}")
    else:
        print(f"  {col('LOW','[+] No debug flags set.')}")

    print(f"\n{'─'*72}")
    print("  OPEN NETWORK PORTS (LISTENING)")
    print(f"{'─'*72}")
    if audit["open_ports"]:
        for port in audit["open_ports"][:20]:
            print(f"  {col('MEDIUM','[*]')} {port}")
    else:
        print("  (none detected or netstat unavailable)")

    print(f"\n{'─'*72}")
    print("  SUSPICIOUS / SIDELOADED PACKAGES")
    print(f"{'─'*72}")
    if audit["suspicious_pkgs"]:
        for pkg in audit["suspicious_pkgs"][:20]:
            print(f"  {col('HIGH','[!]')} {pkg}")
    else:
        print("  (none detected)")

    print(f"\n{'─'*72}")
    print("  RECENT LOGCAT SECURITY EVENTS")
    print(f"{'─'*72}")
    if audit["logcat_warnings"]:
        for line in audit["logcat_warnings"][:10]:
            print(f"  {col('MEDIUM','[*]')} {line}")
    else:
        print("  (no FATAL/SELinux entries in recent logcat)")

    # Overall verdict
    is_rooted = bool(audit["root_indicators"])
    is_debug  = bool(audit["developer_flags"])
    print(f"\n{'─'*72}")
    if is_rooted:
        print(f"  {col('CRITICAL', 'VERDICT: Device shows root indicators — treat as untrusted.')}")
    elif is_debug:
        print(f"  {col('HIGH', 'VERDICT: Debug/developer mode active — elevated risk.')}")
    else:
        print(f"  {col('LOW', 'VERDICT: No obvious compromise indicators.')}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    args   = sys.argv[1:]
    serial = None
    list_only = "--list" in args
    for a in args:
        if not a.startswith("--"):
            serial = a

    adb = AdbWrapper()

    devices = adb.devices()
    if not devices:
        print("[!] No ADB devices found. Connect a device with USB debugging enabled.")
        return

    print(f"\n[*] Connected devices ({len(devices)}):")
    for d in devices:
        state_col = col("LOW" if d["state"] == "device" else "HIGH", d["state"])
        print(f"  {d['serial']:<25} {state_col:<20} {d['model']}")

    if list_only:
        return

    # Select device
    online = [d for d in devices if d["state"] == "device"]
    if not online:
        print("[!] No online (authorized) devices.")
        return

    if serial:
        target = next((d for d in online if d["serial"] == serial), None)
        if not target:
            print(f"[!] Device {serial!r} not found or not online.")
            return
    else:
        target = online[0]
        if len(online) > 1:
            print(f"[*] Multiple devices found — using first: {target['serial']}")

    print(f"\n[*] Scanning device: {target['serial']} ({target['model']})")
    audit = adb.scan_device(target["serial"])
    print_device_report(audit)


if __name__ == "__main__":
    main()
