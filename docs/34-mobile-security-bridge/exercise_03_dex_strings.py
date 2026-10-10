#!/usr/bin/env python3
"""
exercise_03_dex_strings.py — DEX String Extractor (Skeleton)
Usage: python exercise_03_dex_strings.py <file.apk_or_dex>

Goal: parse the DEX file format from scratch, extract all strings, and
print those matching a URL pattern.
"""

import sys
import struct
import zipfile
import io
from pathlib import Path

DEX_MAGIC_PREFIXES = (b"dex\n035\0", b"dex\n036\0", b"dex\n037\0", b"dex\n038\0")


def load_dex(path):
    """Load classes.dex bytes from a .dex file or from a .apk."""
    path = Path(path)
    if not path.exists():
        sys.exit(f"[!] File not found: {path}")

    data = path.read_bytes()

    # If it's an APK (ZIP), extract classes.dex
    if data[:2] == b'PK':
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as apk:
                if "classes.dex" not in apk.namelist():
                    sys.exit("[!] classes.dex not found in APK")
                dex_data = apk.read("classes.dex")
                print(f"[+] Extracted classes.dex ({len(dex_data):,} bytes) from APK")
                return dex_data
        except zipfile.BadZipFile:
            pass

    return data


def check_dex_magic(data):
    """Verify DEX magic bytes at offset 0."""
    if len(data) < 8:
        sys.exit("[!] File too small to be a DEX")
    magic = data[:8]
    for prefix in DEX_MAGIC_PREFIXES:
        if magic == prefix:
            print(f"[+] DEX magic OK: {magic!r}")
            return True
    print(f"[!] Unexpected magic: {magic!r}")
    return False


def parse_dex_header(data):
    """
    Parse the DEX header (112 bytes at offset 0).
    Return a dict with key header fields.

    Header layout (all little-endian):
      0:  8  magic
      8:  4  checksum (Adler-32)
      12: 20 sha1_hash
      32: 4  file_size
      36: 4  header_size (always 0x70 = 112)
      40: 4  endian_tag  (0x12345678 = LE)
      44: 4  link_size
      48: 4  link_off
      52: 4  map_off
      56: 4  string_ids_size   ← count of strings
      60: 4  string_ids_off    ← offset to string ID array
      64: 4  type_ids_size
      68: 4  type_ids_off
      72: 4  proto_ids_size
      76: 4  proto_ids_off
      80: 4  field_ids_size
      84: 4  field_ids_off
      88: 4  method_ids_size
      92: 4  method_ids_off
      96: 4  class_defs_size
      100: 4 class_defs_off
      104: 4 data_size
      108: 4 data_off
    """
    if len(data) < 112:
        sys.exit("[!] DEX file too small to have a valid header")

    hdr = {}
    hdr["magic"]           = data[:8]
    hdr["file_size"]       = struct.unpack_from('<I', data, 32)[0]
    hdr["header_size"]     = struct.unpack_from('<I', data, 36)[0]
    hdr["endian_tag"]      = struct.unpack_from('<I', data, 40)[0]
    hdr["string_ids_size"] = struct.unpack_from('<I', data, 56)[0]
    hdr["string_ids_off"]  = struct.unpack_from('<I', data, 60)[0]
    hdr["type_ids_size"]   = struct.unpack_from('<I', data, 64)[0]
    hdr["class_defs_size"] = struct.unpack_from('<I', data, 96)[0]
    return hdr


def read_uleb128(data, offset):
    """
    TODO: Implement ULEB128 (Unsigned Little-Endian Base 128) decoder.

    ULEB128 rules:
    - Read one byte at a time from `data` starting at `offset`.
    - Each byte contributes 7 bits to the result (low 7 bits of the byte).
    - If the high bit (bit 7) of a byte is 1, more bytes follow.
    - If the high bit is 0, this is the final byte.
    - Bits are placed starting at shift=0, then shift+=7 for each byte.

    Return (value, new_offset) where new_offset is the position after the
    last byte of the ULEB128 sequence.

    Example:
      data = bytes([0x01]) → value = 1, consumed 1 byte
      data = bytes([0x80, 0x01]) → value = 128, consumed 2 bytes
      data = bytes([0xE5, 0x8E, 0x26]) → value = 624485, consumed 3 bytes
    """
    # TODO: implement
    raise NotImplementedError("read_uleb128 not yet implemented")


def read_string(data, string_data_off):
    """
    TODO: Implement string_data_item reader.

    A string_data_item at `string_data_off` consists of:
    1. ULEB128-encoded character count (number of UTF-16 code units, NOT byte count)
    2. MUTF-8 encoded string data (Modified UTF-8)
    3. Null terminator byte 0x00

    Steps:
    1. Call read_uleb128(data, string_data_off) to get (char_count, offset_after_len)
    2. Read bytes from offset_after_len until you hit a 0x00 byte (or char_count runs out)
    3. Decode the bytes as UTF-8 (use errors='replace' to handle MUTF-8 edge cases)
    4. Return the decoded string

    Hint: MUTF-8 is very close to UTF-8 for ASCII content. For the purpose of
    this exercise, decode with errors='replace' to handle the edge cases.
    """
    # TODO: implement
    raise NotImplementedError("read_string not yet implemented")


def extract_all_strings(data):
    """
    Extract all strings from the DEX file using the string ID table.

    The string_ids_off points to an array of string_ids_size uint32 values.
    Each uint32 is an offset into the file pointing to a string_data_item.

    Return a list of strings.
    """
    hdr = parse_dex_header(data)
    count  = hdr["string_ids_size"]
    offset = hdr["string_ids_off"]

    print(f"[*] String table: {count:,} strings at offset 0x{offset:08X}")

    strings = []
    for i in range(count):
        # Each string ID is a uint32 offset to string_data_item
        string_data_off = struct.unpack_from('<I', data, offset + i * 4)[0]
        try:
            s = read_string(data, string_data_off)
            strings.append(s)
        except NotImplementedError:
            strings.append(f"<not implemented: string #{i}>")
        except Exception as e:
            strings.append(f"<error: {e}>")
    return strings


def filter_urls(strings):
    """
    TODO: Filter strings to find URL patterns.

    Return a list of strings that look like URLs:
    - Start with "http://", "https://", or "ftp://"
    - At least 10 characters long
    """
    # TODO: implement
    return [s for s in strings if False]  # replace False with your condition


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <file.apk_or_dex>")
        sys.exit(1)

    dex_data = load_dex(sys.argv[1])

    # Verify magic
    if not check_dex_magic(dex_data):
        sys.exit("[!] Not a valid DEX file")

    # Parse header
    hdr = parse_dex_header(dex_data)
    print(f"[*] DEX header:")
    print(f"    file_size    : {hdr['file_size']:,} bytes")
    print(f"    string_count : {hdr['string_ids_size']:,}")
    print(f"    type_count   : {hdr['type_ids_size']:,}")
    print(f"    class_count  : {hdr['class_defs_size']:,}")

    # Extract strings
    print(f"\n[*] Extracting strings...")
    try:
        strings = extract_all_strings(dex_data)
        print(f"[+] Extracted {len(strings):,} strings")
    except NotImplementedError as e:
        print(f"[!] {e}")
        print("    Implement read_uleb128() and read_string() to continue.")
        return

    # Filter URLs
    urls = filter_urls(strings)
    print(f"\n[*] URL strings found: {len(urls)}")
    for url in urls:
        print(f"    {url}")

    if not urls:
        print("    (none found — implement filter_urls() or check the DEX content)")


if __name__ == "__main__":
    main()
