"""
Module 33 — Exercise 01: Manifest Parser
=========================================
Parse a browser extension's manifest.json and print its key security-relevant fields.

Supports:
  - Plain directory containing manifest.json
  - .zip archive
  - .crx file (both v2 and v3)

Usage:
    python exercise_01_manifest_parser.py <path>

Where <path> is a directory, .zip, or .crx file.

TODOs are marked with ### TODO ###. Complete each one to make the script functional.
"""

import sys
import os
import json
import zipfile
import struct
import io


def unpack_crx(data: bytes) -> zipfile.ZipFile:
    """
    Unpack a CRX file and return its contents as a ZipFile object.

    CRX2 format:
        Offset 0:  4 bytes  magic "Cr24"
        Offset 4:  4 bytes  version (little-endian) = 2
        Offset 8:  4 bytes  public key length
        Offset 12: 4 bytes  signature length
        Offset 16: pubkey_len bytes  DER-encoded RSA public key
        Offset 16+pubkey_len: sig_len bytes  RSA signature
        After that: ZIP data

    CRX3 format:
        Offset 0:  4 bytes  magic "Cr24"
        Offset 4:  4 bytes  version (little-endian) = 3
        Offset 8:  4 bytes  header_size
        Offset 12: header_size bytes  CrxFileHeader protobuf
        After that: ZIP data
    """
    ### TODO ###
    # 1. Check that the first 4 bytes equal b"Cr24"; raise ValueError if not.
    # 2. Read the version (little-endian uint32 at offset 4).
    # 3. If version == 2:
    #       Read pubkey_len (uint32 at offset 8) and sig_len (uint32 at offset 12).
    #       zip_start = 16 + pubkey_len + sig_len
    # 4. If version == 3:
    #       Read header_len (uint32 at offset 8).
    #       zip_start = 12 + header_len
    # 5. Otherwise raise ValueError(f"Unknown CRX version {version}").
    # 6. Return zipfile.ZipFile(io.BytesIO(data[zip_start:]))
    raise NotImplementedError("TODO: implement unpack_crx")


def load_extension(path: str):
    """
    Load extension files into a dict {filename: bytes}.
    Handles: directory, .zip, .crx.
    """
    path = os.path.abspath(path)

    if os.path.isdir(path):
        ### TODO ###
        # Walk the directory recursively.
        # For each file, read its bytes and store in the dict with a relative path key.
        # Hint: use os.walk() and open(filepath, "rb").read()
        files = {}
        raise NotImplementedError("TODO: implement directory loading")

    elif path.lower().endswith(".crx"):
        ### TODO ###
        # Read the file as bytes, call unpack_crx(), then read all entries from the ZipFile.
        # Return a dict {name: zf.read(name)} for each name in zf.namelist().
        raise NotImplementedError("TODO: implement .crx loading")

    elif path.lower().endswith(".zip"):
        ### TODO ###
        # Open as a ZipFile and return {name: zf.read(name)} for each name.
        raise NotImplementedError("TODO: implement .zip loading")

    else:
        raise ValueError(f"Unsupported extension format: {path}")


def parse_manifest(files: dict) -> dict:
    """
    Find manifest.json in the file dict and return the parsed Python dict.
    """
    ### TODO ###
    # 1. Look for "manifest.json" in files (try both "manifest.json" and
    #    any key ending in "/manifest.json" in case there's a subdirectory prefix).
    # 2. Decode the bytes as UTF-8 and parse with json.loads().
    # 3. Return the dict.
    raise NotImplementedError("TODO: implement parse_manifest")


def print_manifest_summary(manifest: dict) -> None:
    """
    Print a human-readable summary of the manifest fields relevant to security.
    """
    name    = manifest.get("name", "<unknown>")
    version = manifest.get("version", "<unknown>")
    mv      = manifest.get("manifest_version", "<unknown>")

    print(f"Extension Name    : {name}")
    print(f"Version           : {version}")
    print(f"Manifest Version  : {mv}")
    print()

    ### TODO ###
    # Print permissions list (manifest.get("permissions", []))
    # Print host_permissions list (manifest.get("host_permissions", []))
    # For content_scripts, print each entry's "matches" list and "js" list.
    # Print background: service_worker or scripts key.
    # Print update_url if present.
    raise NotImplementedError("TODO: implement print_manifest_summary")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <extension_dir_or_crx_or_zip>")
        sys.exit(1)

    path = sys.argv[1]

    print(f"[*] Loading extension from: {path}")
    files    = load_extension(path)
    manifest = parse_manifest(files)
    print_manifest_summary(manifest)


if __name__ == "__main__":
    main()
