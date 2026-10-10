"""
Module 33 — Solution 01: Manifest Parser
==========================================
Complete implementation. Handles .crx (v2 and v3), .zip, and plain directories.
Parses manifest.json and prints all security-relevant fields.

Usage:
    python sol01_manifest_parser.py <extension_dir_or_crx_or_zip>
"""

import sys
import os
import json
import zipfile
import struct
import io
from typing import Dict


def unpack_crx(data: bytes) -> zipfile.ZipFile:
    """Unpack a CRX v2 or v3 file into a ZipFile."""
    if data[:4] != b"Cr24":
        raise ValueError("Not a CRX file — missing 'Cr24' magic bytes")

    version = struct.unpack_from("<I", data, 4)[0]

    if version == 2:
        pubkey_len = struct.unpack_from("<I", data, 8)[0]
        sig_len    = struct.unpack_from("<I", data, 12)[0]
        zip_start  = 16 + pubkey_len + sig_len
    elif version == 3:
        header_len = struct.unpack_from("<I", data, 8)[0]
        zip_start  = 12 + header_len
    else:
        raise ValueError(f"Unknown CRX version: {version}")

    return zipfile.ZipFile(io.BytesIO(data[zip_start:]))


def load_extension(path: str) -> Dict[str, bytes]:
    """
    Load all extension files into {relative_path: bytes}.
    Handles directory, .crx, and .zip.
    """
    path = os.path.abspath(path)

    if os.path.isdir(path):
        files = {}
        for root, _, filenames in os.walk(path):
            for fname in filenames:
                full = os.path.join(root, fname)
                rel  = os.path.relpath(full, path).replace("\\", "/")
                with open(full, "rb") as f:
                    files[rel] = f.read()
        return files

    with open(path, "rb") as f:
        raw = f.read()

    if path.lower().endswith(".crx"):
        zf = unpack_crx(raw)
    elif path.lower().endswith(".zip"):
        zf = zipfile.ZipFile(io.BytesIO(raw))
    else:
        raise ValueError(f"Unsupported format: {path}")

    files = {}
    for name in zf.namelist():
        try:
            files[name] = zf.read(name)
        except Exception:
            pass
    return files


def find_manifest(files: Dict[str, bytes]) -> dict:
    """Parse and return manifest.json from the file dict."""
    # Look for manifest.json at root or one level deep
    for candidate in ("manifest.json", ):
        if candidate in files:
            return json.loads(files[candidate].decode("utf-8", errors="replace"))

    for key in sorted(files.keys()):
        if key.endswith("/manifest.json") or key == "manifest.json":
            return json.loads(files[key].decode("utf-8", errors="replace"))

    raise FileNotFoundError("manifest.json not found in extension")


def print_manifest_summary(manifest: dict) -> None:
    """Print a complete security-oriented manifest summary."""
    name    = manifest.get("name", "<unknown>")
    version = manifest.get("version", "<unknown>")
    mv      = manifest.get("manifest_version", "<unknown>")

    print("=" * 65)
    print(f"  Browser Extension Manifest Summary")
    print("=" * 65)
    print(f"  Name             : {name}")
    print(f"  Version          : {version}")
    print(f"  Manifest Version : MV{mv}")
    print()

    # --- Permissions ---
    perms = manifest.get("permissions", [])
    if perms:
        print("[*] Permissions:")
        for p in perms:
            print(f"    - {p}")
    else:
        print("[*] Permissions: (none)")
    print()

    # --- Host Permissions (MV3) ---
    host_perms = manifest.get("host_permissions", [])
    if host_perms:
        print("[*] Host Permissions (MV3):")
        for p in host_perms:
            print(f"    - {p}")
        print()

    # --- Content Scripts ---
    content_scripts = manifest.get("content_scripts", [])
    if content_scripts:
        print(f"[*] Content Scripts ({len(content_scripts)} entry/entries):")
        for i, cs in enumerate(content_scripts, 1):
            matches = cs.get("matches", [])
            js      = cs.get("js", [])
            css     = cs.get("css", [])
            run_at  = cs.get("run_at", "document_idle")
            all_fr  = cs.get("all_frames", False)
            print(f"    Entry {i}:")
            print(f"      Match patterns : {', '.join(matches) if matches else '(none)'}")
            print(f"      JS files       : {', '.join(js) if js else '(none)'}")
            print(f"      CSS files      : {', '.join(css) if css else '(none)'}")
            print(f"      run_at         : {run_at}")
            print(f"      all_frames     : {all_fr}")
        print()
    else:
        print("[*] Content Scripts: (none)\n")

    # --- Background ---
    bg = manifest.get("background", {})
    if bg:
        print("[*] Background:")
        sw = bg.get("service_worker")
        if sw:
            print(f"    Service Worker : {sw}  [MV3]")
        scripts = bg.get("scripts", [])
        if scripts:
            print(f"    Scripts        : {', '.join(scripts)}  [MV2]")
        persistent = bg.get("persistent")
        if persistent is not None:
            print(f"    Persistent     : {persistent}")
        print()

    # --- Web Accessible Resources ---
    war = manifest.get("web_accessible_resources", [])
    if war:
        print("[*] Web Accessible Resources:")
        if isinstance(war, list):
            for item in war:
                if isinstance(item, str):
                    print(f"    - {item}")
                elif isinstance(item, dict):
                    resources = item.get("resources", [])
                    matches   = item.get("matches", [])
                    print(f"    Resources: {resources}  Matches: {matches}")
        print()

    # --- Update URL ---
    update_url = manifest.get("update_url")
    if update_url:
        print(f"[!] update_url (extension can auto-update from external server):")
        print(f"    {update_url}")
        print()

    # --- Externally Connectable ---
    ec = manifest.get("externally_connectable", {})
    if ec:
        print(f"[*] externally_connectable: {ec}")
        print()

    # --- Content Security Policy ---
    csp = manifest.get("content_security_policy")
    if csp:
        print(f"[*] Content Security Policy: {csp}")
        print()

    # --- Optional Permissions ---
    opt = manifest.get("optional_permissions", [])
    if opt:
        print(f"[*] Optional Permissions: {', '.join(opt)}")
        print()


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <extension_dir_or_crx_or_zip>")
        sys.exit(1)

    path = sys.argv[1]
    print(f"[*] Loading: {path}\n")

    files    = load_extension(path)
    manifest = find_manifest(files)
    print_manifest_summary(manifest)

    print(f"[*] Total files in extension: {len(files)}")
    js_files = [k for k in files if k.endswith(".js")]
    print(f"[*] JavaScript files: {len(js_files)}")
    for jf in sorted(js_files):
        size = len(files[jf])
        print(f"    {jf}  ({size:,} bytes)")


if __name__ == "__main__":
    main()
