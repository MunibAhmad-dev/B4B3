#!/usr/bin/env python3
"""
exercise_04_adb_wrapper.py — ADB Subprocess Wrapper (Skeleton)
Usage: python exercise_04_adb_wrapper.py

Goal: build a Python wrapper around the adb command-line tool using subprocess,
then use it to enumerate connected devices and run basic commands.

Prerequisites: adb must be installed and in your PATH.
"""

import sys
import subprocess
from typing import List, Tuple, Optional


class AdbWrapper:
    """Thin Python wrapper around the adb command-line tool."""

    def __init__(self, adb_path: str = "adb"):
        self.adb_path = adb_path
        self._check_adb()

    def _check_adb(self):
        """Verify adb is available."""
        try:
            result = subprocess.run(
                [self.adb_path, "version"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                version_line = result.stdout.splitlines()[0] if result.stdout else "unknown"
                print(f"[+] ADB found: {version_line}")
            else:
                print(f"[!] adb returned error: {result.stderr.strip()}")
        except FileNotFoundError:
            print(f"[!] adb not found at '{self.adb_path}'. Install Android SDK platform-tools.")
        except subprocess.TimeoutExpired:
            print("[!] adb timed out — is the ADB server running?")

    def devices(self) -> List[dict]:
        """
        TODO: Implement this method.

        Run: adb devices -l
        Parse the output to return a list of device dicts.
        Each dict should have keys: serial, state, model (if available).

        The output of `adb devices -l` looks like:
            List of devices attached
            emulator-5554          device product:sdk_gphone64_x86_64 ...  model:sdk_gphone64_x86_64
            R52HA1234X             device product:a51 transport_id:2 model:SM_A515F

        The first column is the serial. The second is the state (device / offline / unauthorized).
        The rest contains key:value pairs — extract "model:" if present.

        Return empty list if no devices.
        """
        # TODO: implement
        print("[TODO] devices() not yet implemented")
        return []

    def shell(self, serial: str, cmd: str, timeout: int = 10) -> str:
        """
        TODO: Implement this method.

        Run: adb -s <serial> shell <cmd>
        Return the stdout output as a string.
        If the command fails or times out, return an empty string and print an error.

        Use subprocess.run() with capture_output=True and text=True.
        """
        # TODO: implement
        print(f"[TODO] shell() not yet implemented — would run: adb -s {serial} shell {cmd}")
        return ""

    def pull(self, serial: str, remote_path: str, local_path: str) -> bool:
        """
        TODO: Implement this method.

        Run: adb -s <serial> pull <remote_path> <local_path>
        Return True on success, False on failure.

        Hint: check result.returncode == 0.
        """
        # TODO: implement
        print(f"[TODO] pull() not yet implemented — would run: adb -s {serial} pull {remote_path} {local_path}")
        return False


def demo_usage():
    """Demonstrate the ADB wrapper."""
    print("=" * 60)
    print("  ADB Wrapper Demo")
    print("=" * 60)

    adb = AdbWrapper()

    print("\n[*] Listing connected devices:")
    devices = adb.devices()
    if not devices:
        print("  No devices found (or devices() not yet implemented)")
        print("  Connect a device or start an emulator and try again.")
        return

    for dev in devices:
        print(f"  Serial : {dev.get('serial', '?')}")
        print(f"  State  : {dev.get('state', '?')}")
        print(f"  Model  : {dev.get('model', 'unknown')}")
        print()

    # Use the first available device for demo commands
    online = [d for d in devices if d.get("state") == "device"]
    if not online:
        print("[!] No online devices available for shell commands")
        return

    serial = online[0]["serial"]
    print(f"[*] Using device: {serial}\n")

    # Demo: run a shell command
    print("[*] Running: getprop ro.product.model")
    model = adb.shell(serial, "getprop ro.product.model")
    print(f"  Model: {model.strip()}")

    print("\n[*] Running: id")
    whoami = adb.shell(serial, "id")
    print(f"  Identity: {whoami.strip()}")

    # Demo: check for su
    print("\n[*] Checking for su (root indicator):")
    su_check = adb.shell(serial, "which su")
    if su_check.strip():
        print(f"  [!] su found at: {su_check.strip()}")
    else:
        print("  su not found — device likely not rooted")


if __name__ == "__main__":
    demo_usage()
