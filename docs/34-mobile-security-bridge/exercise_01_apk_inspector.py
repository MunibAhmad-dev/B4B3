#!/usr/bin/env python3
"""
exercise_01_apk_inspector.py — APK Structure Inspector (Skeleton)
Usage: python exercise_01_apk_inspector.py <app.apk>

Goal: open an APK as a ZIP, list all entries, extract the binary
AndroidManifest.xml, and verify the AXML magic bytes.
"""

import sys
import zipfile
from pathlib import Path


def list_apk_contents(apk_path):
    """Open the APK as a ZIP and print all entries with sizes."""
    # An APK is just a ZIP file — zipfile.ZipFile handles it directly.
    with zipfile.ZipFile(apk_path, 'r') as apk:
        entries = apk.infolist()
        print(f"APK: {apk_path}  ({len(entries)} entries)\n")
        print(f"  {'Name':<60} {'Size':>10} {'Compressed':>12} {'Method':>8}")
        print(f"  {'─'*60} {'─'*10} {'─'*12} {'─'*8}")
        for entry in entries:
            method = "deflate" if entry.compress_type == zipfile.ZIP_DEFLATED else \
                     "stored"  if entry.compress_type == zipfile.ZIP_STORED  else \
                     f"type={entry.compress_type}"
            print(f"  {entry.filename:<60} {entry.file_size:>10,} {entry.compress_size:>12,} {method:>8}")
        return apk


def extract_manifest(apk_path):
    """Extract and return raw bytes of AndroidManifest.xml."""
    with zipfile.ZipFile(apk_path, 'r') as apk:
        if "AndroidManifest.xml" not in apk.namelist():
            print("[!] AndroidManifest.xml not found in APK")
            return None
        raw = apk.read("AndroidManifest.xml")
        print(f"\nAndroidManifest.xml: {len(raw)} bytes")
        return raw


def check_axml_magic(data):
    """
    TODO: Implement this function.

    Check that the binary manifest starts with the AXML magic bytes.
    AXML magic (little-endian uint32 at offset 0) = 0x00080003

    Steps:
    1. Import struct
    2. Unpack a little-endian uint32 from data at offset 0
    3. Compare to 0x00080003
    4. Print the first 32 bytes as hex for inspection
    5. Print whether magic matches or not

    Expected output when magic is correct:
        First 32 bytes: 03 00 08 00 ...
        [+] AXML magic OK (0x00080003)
    """
    # TODO: implement
    print("[TODO] check_axml_magic not yet implemented")
    print(f"First 32 bytes (raw): {data[:32]}")


def find_string_pool(data):
    """
    TODO: Implement this function.

    Find the String Pool chunk in the AXML data.
    The String Pool chunk type is 0x001C0001 (little-endian uint32).

    Steps:
    1. Start scanning at offset 8 (after the file header: type + file_size)
    2. At each chunk, read: chunk_type (uint32), chunk_size (uint32)
    3. When chunk_type == 0x001C0001, print the offset and chunk_size
    4. Also read string_count (uint32 at chunk_offset + 8) and print it

    Hint: use struct.unpack_from('<II', data, offset) to read two uint32s at once.
    """
    # TODO: implement
    print("[TODO] find_string_pool not yet implemented")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <app.apk>")
        sys.exit(1)

    apk_path = sys.argv[1]
    if not Path(apk_path).exists():
        print(f"[!] File not found: {apk_path}")
        sys.exit(1)

    # Step 1: list all entries
    print("=" * 80)
    print("STEP 1: APK Contents")
    print("=" * 80)
    with zipfile.ZipFile(apk_path, 'r') as apk:
        entries = apk.infolist()
        print(f"APK: {apk_path}  ({len(entries)} entries)\n")
        print(f"  {'Name':<60} {'Size':>10} {'Compressed':>12}")
        print(f"  {'─'*60} {'─'*10} {'─'*12}")
        for entry in entries:
            print(f"  {entry.filename:<60} {entry.file_size:>10,} {entry.compress_size:>12,}")

    # Step 2: extract manifest
    print("\n" + "=" * 80)
    print("STEP 2: Extract AndroidManifest.xml")
    print("=" * 80)
    manifest_data = extract_manifest(apk_path)
    if manifest_data is None:
        sys.exit(1)

    # Step 3: check AXML magic
    print("\n" + "=" * 80)
    print("STEP 3: Verify AXML Magic")
    print("=" * 80)
    check_axml_magic(manifest_data)

    # Step 4: find string pool
    print("\n" + "=" * 80)
    print("STEP 4: Locate String Pool Chunk")
    print("=" * 80)
    find_string_pool(manifest_data)


if __name__ == "__main__":
    main()
