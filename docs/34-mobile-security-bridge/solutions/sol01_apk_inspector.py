#!/usr/bin/env python3
"""
sol01_apk_inspector.py — Complete APK Inspector with AXML Decoder
Usage:
  python sol01.py <app.apk>
  python sol01.py <app.apk> --raw    (hex dump of manifest)
"""

import sys
import struct
import zipfile
import io
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Chunk type constants
# ─────────────────────────────────────────────────────────────────────────────

CHUNK_FILE_XML         = 0x00080003
CHUNK_STRING_POOL      = 0x001C0001
CHUNK_RESOURCE_MAP     = 0x00080180
CHUNK_XML_START_NS     = 0x00100100
CHUNK_XML_END_NS       = 0x00100101
CHUNK_XML_START_ELEM   = 0x00100102
CHUNK_XML_END_ELEM     = 0x00100103
CHUNK_XML_CDATA        = 0x00100104

# Attribute data types
TYPE_NULL      = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING    = 0x03
TYPE_FLOAT     = 0x04
TYPE_DIMENSION = 0x05
TYPE_FRACTION  = 0x06
TYPE_INT_DEC   = 0x10
TYPE_INT_HEX   = 0x11
TYPE_INT_BOOL  = 0x12


# ─────────────────────────────────────────────────────────────────────────────
# APK loader
# ─────────────────────────────────────────────────────────────────────────────

def load_apk(path):
    """Return dict {filename: bytes} from an APK file."""
    path = Path(path)
    if not path.exists():
        sys.exit(f"[!] File not found: {path}")
    try:
        with zipfile.ZipFile(str(path)) as apk:
            entries = apk.infolist()
            print(f"[+] Opened APK: {path.name}  ({len(entries)} entries)")
            files = {e.filename: apk.read(e.filename) for e in entries}
            return files, entries
    except zipfile.BadZipFile:
        sys.exit(f"[!] Not a valid ZIP/APK: {path}")


def print_apk_listing(entries):
    print(f"\n  {'Filename':<60} {'Size':>10} {'Compressed':>12} {'Method':>10}")
    print(f"  {'─'*60} {'─'*10} {'─'*12} {'─'*10}")
    for e in entries:
        method = {0: "stored", 8: "deflate"}.get(e.compress_type, f"type={e.compress_type}")
        print(f"  {e.filename:<60} {e.file_size:>10,} {e.compress_size:>12,} {method:>10}")


# ─────────────────────────────────────────────────────────────────────────────
# String Pool parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_string_pool(data, pool_offset):
    """
    Parse a String Pool chunk starting at pool_offset.
    Returns list of strings.
    """
    base  = pool_offset
    ctype = struct.unpack_from('<I', data, base)[0]
    if ctype != CHUNK_STRING_POOL:
        return []

    chunk_size    = struct.unpack_from('<I', data, base + 4)[0]
    string_count  = struct.unpack_from('<I', data, base + 8)[0]
    style_count   = struct.unpack_from('<I', data, base + 12)[0]
    flags         = struct.unpack_from('<I', data, base + 16)[0]
    strings_start = struct.unpack_from('<I', data, base + 20)[0]
    # styles_start = struct.unpack_from('<I', data, base + 24)[0]

    use_utf8 = bool(flags & 0x100)
    offsets_base = base + 28  # offsets array starts right after the 7-field header

    strings = []
    for i in range(string_count):
        str_offset = struct.unpack_from('<I', data, offsets_base + i * 4)[0]
        abs_offset = base + strings_start + str_offset

        try:
            if use_utf8:
                # UTF-8 encoded strings
                # 1-or-2 byte: UTF-16 length (number of chars)
                b0 = data[abs_offset]
                if b0 & 0x80:
                    char_len = ((b0 & 0x7F) << 8) | data[abs_offset + 1]
                    abs_offset += 2
                else:
                    char_len = b0
                    abs_offset += 1
                # 1-or-2 byte: byte length
                b0 = data[abs_offset]
                if b0 & 0x80:
                    byte_len = ((b0 & 0x7F) << 8) | data[abs_offset + 1]
                    abs_offset += 2
                else:
                    byte_len = b0
                    abs_offset += 1
                raw = data[abs_offset:abs_offset + byte_len]
                strings.append(raw.decode("utf-8", errors="replace"))
            else:
                # UTF-16LE encoded strings
                char_len = struct.unpack_from('<H', data, abs_offset)[0]
                abs_offset += 2
                raw = data[abs_offset:abs_offset + char_len * 2]
                strings.append(raw.decode("utf-16-le", errors="replace"))
        except Exception:
            strings.append(f"<string_{i}>")

    return strings


# ─────────────────────────────────────────────────────────────────────────────
# AXML parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_axml(data):
    """
    Parse binary AXML data. Returns a list of (event, name, attrs, lineno) tuples.
    Events: "start_ns", "end_ns", "start_element", "end_element", "cdata"
    attrs is a list of (ns, name, value_str) tuples.
    """
    if len(data) < 8:
        return [], []

    magic = struct.unpack_from('<I', data, 0)[0]
    if magic != CHUNK_FILE_XML:
        print(f"[!] Unexpected AXML magic: 0x{magic:08X} (expected 0x{CHUNK_FILE_XML:08X})")

    strings = []
    events  = []
    offset  = 8  # skip file header (type + file_size)

    while offset < len(data) - 8:
        ctype = struct.unpack_from('<I', data, offset)[0]
        csize = struct.unpack_from('<I', data, offset + 4)[0]

        if csize < 8 or offset + csize > len(data):
            break

        if ctype == CHUNK_STRING_POOL:
            strings = parse_string_pool(data, offset)

        elif ctype == CHUNK_XML_START_ELEM:
            lineno   = struct.unpack_from('<I', data, offset + 8)[0]
            ns_idx   = struct.unpack_from('<i', data, offset + 16)[0]
            name_idx = struct.unpack_from('<i', data, offset + 20)[0]
            # attr_start = struct.unpack_from('<H', data, offset + 24)[0]
            attr_size  = struct.unpack_from('<H', data, offset + 28)[0]
            attr_count = struct.unpack_from('<H', data, offset + 30)[0]

            attrs = []
            attr_base = offset + 36  # 8(hdr) + 4(line) + 4(comment) + 4(ns) + 4(name) + 4(attr_start) + 2(attr_size) + 2(count) + 2 + 2 + 2 = 36 ... actually:
            # Standard layout: offset+8=line, +12=comment, +16=ns, +20=name, +24=attr_start, +28=attr_size, +30=attr_count, +32=id, +34=class, +36=style, +38=attrs
            attr_base = offset + 38

            for a in range(attr_count):
                a_off   = attr_base + a * attr_size
                if a_off + 20 > len(data):
                    break
                a_ns    = struct.unpack_from('<i', data, a_off)[0]
                a_name  = struct.unpack_from('<i', data, a_off + 4)[0]
                a_raw   = struct.unpack_from('<i', data, a_off + 8)[0]
                a_dtype = struct.unpack_from('<I', data, a_off + 12)[0]
                a_data  = struct.unpack_from('<I', data, a_off + 16)[0]

                ns_str   = strings[a_ns]  if 0 <= a_ns  < len(strings) else ""
                name_str = strings[a_name] if 0 <= a_name < len(strings) else f"<{a_name}>"

                # Resolve value
                dtype = (a_dtype >> 24) & 0xFF
                if dtype == TYPE_STRING and 0 <= a_raw < len(strings):
                    val_str = strings[a_raw]
                elif dtype in (TYPE_INT_DEC,):
                    val_str = str(struct.unpack('<i', struct.pack('<I', a_data))[0])
                elif dtype == TYPE_INT_BOOL:
                    val_str = "true" if a_data != 0 else "false"
                elif dtype == TYPE_INT_HEX:
                    val_str = f"0x{a_data:08X}"
                elif dtype == TYPE_REFERENCE:
                    val_str = f"@0x{a_data:08X}"
                else:
                    val_str = f"0x{a_data:08X}"

                attrs.append((ns_str, name_str, val_str))

            name_str = strings[name_idx] if 0 <= name_idx < len(strings) else f"<{name_idx}>"
            events.append(("start_element", name_str, attrs, lineno))

        elif ctype == CHUNK_XML_END_ELEM:
            lineno   = struct.unpack_from('<I', data, offset + 8)[0]
            name_idx = struct.unpack_from('<i', data, offset + 20)[0]
            name_str = strings[name_idx] if 0 <= name_idx < len(strings) else f"<{name_idx}>"
            events.append(("end_element", name_str, [], lineno))

        elif ctype == CHUNK_XML_START_NS:
            # namespace prefix/uri
            prefix_idx = struct.unpack_from('<i', data, offset + 16)[0]
            uri_idx    = struct.unpack_from('<i', data, offset + 20)[0]
            prefix = strings[prefix_idx] if 0 <= prefix_idx < len(strings) else ""
            uri    = strings[uri_idx]    if 0 <= uri_idx    < len(strings) else ""
            events.append(("start_ns", prefix, [(uri, "", "")], 0))

        offset += csize

    return strings, events


def print_xml_tree(events):
    """Print the parsed XML events as a readable indented tree."""
    indent = 0
    for event, name, attrs, lineno in events:
        if event == "start_element":
            attr_str = " ".join(f'{aname}="{aval}"' for _, aname, aval in attrs)
            prefix = "  " * indent
            if attr_str:
                print(f"{prefix}<{name} {attr_str}>")
            else:
                print(f"{prefix}<{name}>")
            indent += 1
        elif event == "end_element":
            indent = max(0, indent - 1)
            prefix = "  " * indent
            print(f"{prefix}</{name}>")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    raw_mode = "--raw" in sys.argv
    args     = [a for a in sys.argv[1:] if not a.startswith("--")]

    if not args:
        print(f"Usage: python {sys.argv[0]} <app.apk> [--raw]")
        sys.exit(1)

    files, entries = load_apk(args[0])

    print("\n" + "=" * 72)
    print("  APK Contents")
    print("=" * 72)
    print_apk_listing(entries)

    # Extract manifest
    if "AndroidManifest.xml" not in files:
        sys.exit("[!] AndroidManifest.xml not found")

    manifest_data = files["AndroidManifest.xml"]
    print(f"\n[+] AndroidManifest.xml: {len(manifest_data):,} bytes")

    magic = struct.unpack_from('<I', manifest_data, 0)[0]
    print(f"[+] AXML magic: 0x{magic:08X} — {'OK' if magic == CHUNK_FILE_XML else 'UNEXPECTED'}")
    print(f"[*] First 32 bytes: {' '.join(f'{b:02X}' for b in manifest_data[:32])}")

    if raw_mode:
        print("\n[*] Raw hex dump (first 256 bytes):")
        for i in range(0, min(256, len(manifest_data)), 16):
            row = manifest_data[i:i+16]
            hex_part  = " ".join(f"{b:02X}" for b in row)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else '.' for b in row)
            print(f"  {i:04X}  {hex_part:<48}  {ascii_part}")
        return

    # Parse and print
    print("\n" + "=" * 72)
    print("  AndroidManifest.xml (decoded)")
    print("=" * 72 + "\n")

    strings, events = parse_axml(manifest_data)
    print(f"[+] String pool: {len(strings)} strings")
    print_xml_tree(events)


if __name__ == "__main__":
    main()
