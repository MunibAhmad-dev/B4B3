# Module 32 — Firmware Analysis

## 1. What Is Firmware and Why Analyze It?

Firmware is persistent code stored in non-volatile memory that initializes hardware before an operating system loads. On modern x86 PCs this means UEFI (Unified Extensible Firmware Interface), which replaced legacy BIOS around 2010. Firmware runs at a higher privilege level than the OS kernel and persists across reinstalls, making it the highest-value implant location for advanced adversaries. Analyzing firmware lets defenders verify integrity, find backdoors, and reverse engineer boot-time drivers that hook OS services before anti-malware loads.

---

## 2. SPI Flash Layout

The main firmware chip is a SPI (Serial Peripheral Interface) NOR flash, typically 8–32 MB. Intel platforms divide this into named regions described by the Flash Descriptor at offset 0:

```
Offset 0x0000: Flash Descriptor (4 KB)
  - Master Access Section: which host can read/write each region
  - Region Section: base/limit of each region (4 KB granularity)

Region 0: Flash Descriptor (read-only after manufacturing)
Region 1: BIOS Region (UEFI firmware)
Region 2: Intel ME (Management Engine firmware)
Region 3: GbE (Gigabit Ethernet NVM, MAC address, config)
Region 4: Platform Data (board-specific data, may be absent)
```

The BIOS region contains one or more UEFI Firmware Volumes. The ME region contains a separate proprietary x86 firmware running on a dedicated microcontroller — it is always powered even when the host is off, and cannot be easily modified without signing keys.

### 2.1 Finding Region Boundaries

The Flash Descriptor at offset 0 starts with the signature `0x5AA5F00F` at offset 0x10. The FLMAP0 register encodes region base addresses as `base << 12`. A simple scanner searches for `5A A5 F0 0F` then decodes `FRBA` (Flash Region Base Address) to find each region's start/end.

---

## 3. UEFI Firmware Volume (FV)

A Firmware Volume is a logical container holding firmware files. Multiple FVs can exist in a single SPI flash image, stacked end-to-end or at fixed offsets.

### 3.1 EFI_FIRMWARE_VOLUME_HEADER

Defined in `MdePkg/Include/Pi/PiFirmwareVolume.h` in the EDK2 source:

```c
typedef struct {
    UINT8                   ZeroVector[16];   // Usually all zeros
    EFI_GUID                FileSystemGuid;   // Volume type GUID
    UINT64                  FvLength;         // Total volume size in bytes
    UINT32                  Signature;        // 0x4856465F = "_FVH"
    EFI_FV_ATTRIBUTES       Attributes;       // See attributes table below
    UINT16                  HeaderLength;     // Size of this header + block map
    UINT16                  Checksum;         // 16-bit checksum of header
    UINT16                  ExtHeaderOffset;  // Offset to EFI_FIRMWARE_VOLUME_EXT_HEADER, 0 if none
    UINT8                   Reserved;         // Must be zero
    UINT8                   Revision;         // Header format revision (2 for PI spec)
    EFI_FV_BLOCK_MAP_ENTRY  BlockMap[1];      // Variable-length block map array
} EFI_FIRMWARE_VOLUME_HEADER;
```

**Signature bytes in memory**: The string "_FVH" occupies bytes at offset 40 (0x28) from the start of the header. In memory this is `5F 46 56 48`. As a little-endian UINT32, the value is `0x4856465F`.

**Checksum**: 2-byte ones-complement sum of all UINT16 words in the header must equal 0. Verify by summing all words including the Checksum field and checking the result is 0.

### 3.2 EFI_FV_BLOCK_MAP_ENTRY

```c
typedef struct {
    UINT32  NumBlocks;   // Number of blocks of this size (0 = end of map)
    UINT32  Length;      // Size of each block in bytes
} EFI_FV_BLOCK_MAP_ENTRY;
```

The BlockMap is a variable-length array terminated by a `{0, 0}` entry. Total FV size = sum of `NumBlocks * Length` across all non-terminating entries. This must equal `FvLength`.

### 3.3 Common FileSystem GUIDs

| GUID | Meaning |
|---|---|
| `8C8CE578-8A3D-4F1C-9935-896185C32DD3` | EFI_FIRMWARE_FILE_SYSTEM2_GUID (FFS2, most common) |
| `5473C07A-3DCB-4DCA-BD6F-1E9689E7349A` | EFI_FIRMWARE_FILE_SYSTEM3_GUID (FFS3, large files) |
| `AAF32C78-947B-439A-A180-2E144EC37792` | NVRAM variable store |

### 3.4 Attributes Flags

| Bit | Meaning |
|---|---|
| 0x0001 | EFI_FVB2_READ_DISABLED_CAP |
| 0x0002 | EFI_FVB2_READ_ENABLED_CAP |
| 0x0004 | EFI_FVB2_READ_STATUS |
| 0x0008 | EFI_FVB2_WRITE_DISABLED_CAP |
| 0x0010 | EFI_FVB2_WRITE_ENABLED_CAP |
| 0x0020 | EFI_FVB2_WRITE_STATUS |
| 0x0040 | EFI_FVB2_LOCK_CAP |
| 0x0080 | EFI_FVB2_LOCK_STATUS |
| 0x0800 | EFI_FVB2_ALIGNMENT (base must be power-of-2 aligned) |
| 0x8000 | EFI_FVB2_WEAK_ALIGNMENT |

---

## 4. UEFI Firmware File System (FFS)

Inside a Firmware Volume, files are stored using the Firmware File System. Each file has a header followed by sections.

### 4.1 EFI_FFS_FILE_HEADER

```c
typedef struct {
    EFI_GUID                Name;            // File GUID (unique ID for this file)
    EFI_FFS_INTEGRITY_CHECK IntegrityCheck;  // 2 bytes: Header checksum + File checksum
    EFI_FV_FILETYPE         Type;            // File type byte
    EFI_FFS_FILE_ATTRIBUTES Attributes;      // File attributes byte
    UINT8                   Size[3];         // File size (including header), little-endian
    EFI_FFS_FILE_STATE      State;           // File state machine flags
} EFI_FFS_FILE_HEADER;
```

**Parsing Size[3]**: `uint32_t size = hdr.Size[0] | (hdr.Size[1] << 8) | (hdr.Size[2] << 16);`

**Alignment**: Each file starts at an 8-byte aligned offset within the FV. After reading a file, advance: `offset = ALIGN_UP(offset + size, 8)`.

**End of FFS**: When the GUID bytes are all 0xFF, you have reached unused (erased) flash space. Stop iterating.

### 4.2 File Type Values

| Value | Name | Description |
|---|---|---|
| 0x01 | EFI_FV_FILETYPE_RAW | Binary data |
| 0x02 | EFI_FV_FILETYPE_FREEFORM | Unstructured data |
| 0x03 | EFI_FV_FILETYPE_SECURITY_CORE | SEC phase core |
| 0x04 | EFI_FV_FILETYPE_PEI_CORE | PEI phase core |
| 0x05 | EFI_FV_FILETYPE_DXE_CORE | DXE phase core |
| 0x06 | EFI_FV_FILETYPE_PEIM | PEI module |
| 0x07 | EFI_FV_FILETYPE_DRIVER | DXE driver |
| 0x08 | EFI_FV_FILETYPE_COMBINED_PEIM_DRIVER | Dual-phase module |
| 0x09 | EFI_FV_FILETYPE_APPLICATION | UEFI application (.efi) |
| 0x0A | EFI_FV_FILETYPE_SMM | SMM module |
| 0x0B | EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE | Nested FV |
| 0x0C | EFI_FV_FILETYPE_COMBINED_SMM_DXE | Combined SMM/DXE |
| 0x0D | EFI_FV_FILETYPE_SMM_CORE | SMM core |
| 0xFF | EFI_FV_FILETYPE_FFS_PAD | Padding file |

### 4.3 File State Flags

The State byte uses an inverted bitfield (0 = set, because flash erases to 0xFF):

| Inverted bit | Meaning |
|---|---|
| 0x01 | EFI_FILE_HEADER_CONSTRUCTION |
| 0x02 | EFI_FILE_HEADER_VALID |
| 0x04 | EFI_FILE_DATA_VALID |
| 0x08 | EFI_FILE_MARKED_FOR_UPDATE |
| 0x10 | EFI_FILE_DELETED |
| 0x20 | EFI_FILE_HEADER_INVALID |

A valid file ready for use has `State & ~0x04 == 0xFB` (bits 0,1,3 inverted = set; bit 2 not inverted = clear means DATA_VALID is set).

---

## 5. EFI Sections

Each FFS file contains one or more sections. Sections have a common header:

### 5.1 EFI_COMMON_SECTION_HEADER

```c
typedef struct {
    UINT8   Size[3];   // Section size including header, little-endian
    UINT8   Type;      // Section type
} EFI_COMMON_SECTION_HEADER;
```

**Extended size**: When `Size[0..2] == 0xFFFFFF`, the section uses an extended header:

```c
typedef struct {
    UINT8    Size[3];         // Must be 0xFFFFFF
    UINT8    Type;
    UINT32   ExtendedSize;    // Actual size including this 8-byte header
} EFI_COMMON_SECTION_HEADER2;
```

Parse: `if (Size[0]==0xFF && Size[1]==0xFF && Size[2]==0xFF) use ExtendedSize; else size = Size[0]|(Size[1]<<8)|(Size[2]<<16);`

### 5.2 Section Type Values

| Value | Name | Contents |
|---|---|---|
| 0x01 | EFI_SECTION_COMPRESSION | Compressed payload, see CompressionType byte |
| 0x02 | EFI_SECTION_GUID_DEFINED | GUID-defined encoding |
| 0x10 | EFI_SECTION_PE32 | PE32 executable image |
| 0x11 | EFI_SECTION_PIC | Position-independent code |
| 0x12 | EFI_SECTION_TE | Terse Executable (stripped PE32) |
| 0x13 | EFI_SECTION_DXE_DEPEX | DXE dependency expression |
| 0x14 | EFI_SECTION_VERSION | Version string (UTF-16) |
| 0x15 | EFI_SECTION_USER_INTERFACE | Module name string (UTF-16) |
| 0x16 | EFI_SECTION_COMPATIBILITY16 | IA-32 legacy 16-bit code |
| 0x17 | EFI_SECTION_FIRMWARE_VOLUME_IMAGE | Nested FV |
| 0x18 | EFI_SECTION_FREEFORM_SUBTYPE_GUID | Freeform with GUID |
| 0x19 | EFI_SECTION_RAW | Raw binary data |
| 0x1B | EFI_SECTION_SMM_DEPEX | SMM dependency expression |

### 5.3 Compression Section (0x01)

After the 4-byte common header, a compression section has:

```c
typedef struct {
    UINT32  UncompressedLength;
    UINT8   CompressionType;   // 0x00 = no compression, 0x01 = EFI standard, 0x02 = LZMA
} EFI_COMPRESSION_SECTION;
```

**EFI Standard Compression** (CompressionType=1): A variant of LZ77 used in early UEFI. Replaced in most modern firmware.

**LZMA Compression** (CompressionType=2, also via GUID_DEFINED sections): The 7-zip LZMA algorithm. Header format: 5-byte LZMA properties + 8-byte uncompressed size, then compressed data. Most large DXE cores and drivers are LZMA-compressed. Tools: `lzma -d` from p7zip, or `python-lzma`.

---

## 6. PE32 Images Inside FFS

A PE32 section contains a standard Windows PE (Portable Executable) file starting immediately after the 4-byte section header. UEFI PE images differ slightly from Windows PE:

- **Machine types**: AMD64 (0x8664), IA-32 (0x014C), ARM64 (0xAA64), EBC (0x0EBC — EFI Byte Code, architecture-neutral)
- **Subsystem**: IMAGE_SUBSYSTEM_EFI_APPLICATION (10), EFI_BOOT_SERVICE_DRIVER (11), EFI_RUNTIME_DRIVER (12), EFI_ROM (13)
- **No DOS stub**: The MZ header is present but the DOS stub is absent (16 bytes of zeros)
- **Base address**: Typically 0 — UEFI loader relocates using the relocation table
- **Imports**: UEFI modules rarely have an IAT; they receive protocol interfaces via UEFI services, not DLL imports. Exceptions: shell applications that import from the UEFI shell.

To extract: read bytes from `(uint8_t*)section_header + 4` for `section_size - 4` bytes and write to a `.efi` file.

---

## 7. NVRAM / UEFI Variable Store

UEFI variables (e.g., BootOrder, SecureBoot, platform keys) are stored in a special FV with the NVRAM GUID. Layout:

```
EFI_FIRMWARE_VOLUME_HEADER (with NVRAM GUID)
VARIABLE_STORE_HEADER:
    Signature   GUID  // {AAF32C78-947B-439A-A180-2E144EC37792}
    Size        UINT32
    Format      UINT8  // 0x5A = initialized
    State       UINT8  // 0xFE = healthy
    Reserved    UINT16
    Reserved1   UINT32
[VARIABLE_HEADER entries...]
```

Each variable entry:

```c
typedef struct {
    UINT16   StartId;      // 0x55AA
    UINT8    State;        // 0x3F=added, 0x3C=deleted
    UINT8    Reserved;
    UINT32   Attributes;   // EFI_VARIABLE_* flags
    UINT32   NameSize;     // Byte length of UTF-16 name (including null)
    UINT32   DataSize;     // Byte length of data
    EFI_GUID VendorGuid;
    // UTF-16 name follows
    // Variable data follows (aligned to 4 bytes)
} VARIABLE_HEADER;
```

**Security-relevant variables**:
- `SecureBoot` (GUID `8BE4DF61...`): UINT8, 1=enabled
- `SetupMode`: UINT8, 1=no PK enrolled (secure boot unenforced)
- `PK`, `KEK`, `db`, `dbx`: Signature databases (EFI_SIGNATURE_LIST format)
- `BootOrder`: UINT16 array of boot option numbers
- `Boot####`: EFI_LOAD_OPTION, contains file path to bootloader

---

## 8. Terse Executable (TE) Format

TE is a stripped PE32 format used for SEC and PEI phase modules to save space in early boot:

```c
typedef struct {
    UINT16   Signature;        // 'VZ' = 0x5A56
    UINT16   Machine;
    UINT8    NumberOfSections;
    UINT8    Subsystem;
    UINT16   StrippedSize;     // How many bytes were stripped from PE header
    UINT32   AddressOfEntryPoint;
    UINT32   BaseOfCode;
    UINT64   ImageBase;
    IMAGE_DATA_DIRECTORY DataDirectory[2]; // reloc + debug only
    // Sections follow directly
} EFI_TE_IMAGE_HEADER;
```

When reversing a TE file, add `StrippedSize - sizeof(EFI_TE_IMAGE_HEADER)` to all RVAs to get the original PE addresses. IDA Pro and Ghidra handle TE natively.

---

## 9. Reverse Engineering Workflow

### 9.1 Acquisition

```
# Physical: use a SPI programmer (Bus Pirate, CH341A, flashrom)
flashrom -p ch341a_spi -r firmware.bin

# From vendor: download BIOS update package, extract .bin from self-extracting exe
7z x BIOSUpdate.exe
binwalk -e BIOSUpdate.rom

# From running system (if flash protections allow):
# Linux: /dev/mem or /sys/kernel/debug/acpi/... or chipsec
chipsec_util spi read 0 0x1000000 firmware.bin
```

### 9.2 Tools

| Tool | Purpose |
|---|---|
| binwalk | Signature scan, entropy analysis, auto-extract |
| UEFITool | GUI browser for FV/FFS/section hierarchy |
| uefi-firmware-parser (Python) | CLI FFS walker, section extractor |
| ifdtool (from coreboot) | Decode Intel Flash Descriptor regions |
| me_cleaner | Analyze/neuter Intel ME region |
| fiano (Go) | Google's UEFI toolkit: UTK command |
| Ghidra + efiSeek | Reverse engineer extracted .efi files |
| IDA Pro + EFISwissKnife | Protocol/GUID annotation for UEFI modules |

### 9.3 Security Checks

1. **Secure Boot keys**: extract `db`, `dbx`, `KEK`, `PK` from NVRAM; verify against known-good baseline
2. **Writable+executable sections**: any PE32 section with both WRITE and EXECUTE flags set is suspicious
3. **Hardcoded IPs/domains**: grep RAW sections for IPv4 patterns (`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
4. **High entropy non-PE data**: entropy > 7.0 in a RAW section suggests encrypted payload or compressed overlay
5. **Unknown GUIDs**: compare all FFS GUIDs against the EDK2 GUID database; unknown ones warrant manual review
6. **SMM modules**: files of type 0x0A run in System Management Mode (ring -2); any SMM module not in the baseline is critical
7. **Boot script**: stored in NVRAM, can be leveraged for S3 resume attacks (CVE-2015-3692)
8. **Reflash lock**: check SPI protected range registers (PR0–PR4 in PCH) are set to prevent runtime reflash

### 9.4 Known Implant Techniques

- **LoJax (2018)**: First in-the-wild UEFI rootkit; inserted a rogue DXE driver that re-infected the OS on every boot
- **CosmicStrand (2022)**: Modified DXE driver to hook ExitBootServices and inject shellcode into the OS kernel
- **BlackLotus (2023)**: UEFI bootkit that bypassed Secure Boot by exploiting an unpatched vulnerability in shim/grub
- **Persistence mechanism**: All insert a new FFS file of type DRIVER (0x07) or APPLICATION (0x09) into the BIOS region, or patch an existing driver's PE32 section

---

## 10. LZMA in UEFI

Most modern UEFI firmware compresses the DXE core and large driver collections using LZMA inside a `GUID_DEFINED` section with GUID `EE4E5898-3914-4259-9D6E-DC7BD79403CF` (LZMA_CUSTOM_DECOMPRESS_GUID). The section data after the 20-byte GUID_DEFINED header is raw LZMA stream:

```
Bytes 0-4:   LZMA properties (lc, lp, pb encoded)
Bytes 5-12:  Uncompressed size (UINT64, little-endian)
Bytes 13+:   LZMA compressed data
```

To decompress manually:
```python
import lzma
data = open('section_raw.bin','rb').read()
props = data[:5]
uncompressed_size = int.from_bytes(data[5:13], 'little')
compressed = data[13:]
# Reconstruct standard LZMA stream
stream = props + uncompressed_size.to_bytes(8,'little') + compressed
out = lzma.decompress(stream, format=lzma.FORMAT_ALONE)
```

---

## Key Takeaways

- Firmware runs before and below the OS; a compromised firmware survives OS reinstallation
- The SPI flash has multiple regions; the BIOS region contains UEFI Firmware Volumes
- FFS files are identified by GUID and type; each file contains typed sections
- PE32 sections hold the actual executable code; extract them as `.efi` files for disassembly
- NVRAM holds Secure Boot keys and boot configuration; these are high-value targets
- SMM modules run at ring -2 and are the most privileged code in the system
- Analysis pipeline: acquire binary → find FV headers → walk FFS → extract PE32/TE → disassemble in Ghidra/IDA
