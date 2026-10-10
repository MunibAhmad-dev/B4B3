// exercise_02_ffs_walk.cpp
// Module 32 — Firmware Analysis, Exercise 2
//
// Goal: Iterate through FFS (Firmware File System) files inside a Firmware Volume.
//       For each file, print its GUID, type name, and size.
//
// Compile: g++ -std=c++17 -Wall -o ex02.exe exercise_02_ffs_walk.cpp
// Run:     ex02.exe <firmware.bin>
//
// Prerequisites: understand exercise_01_fw_header.cpp first.
// The FFS area begins immediately after the FV header (at offset hdr->HeaderLength).
// Files are 8-byte aligned. Stop when GUID bytes are all 0xFF (erased flash).

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>

#pragma pack(1)

struct EFI_GUID {
    uint8_t Data[16];
};

struct EFI_FV_BLOCK_MAP_ENTRY {
    uint32_t NumBlocks;
    uint32_t Length;
};

struct EFI_FIRMWARE_VOLUME_HEADER {
    uint8_t                  ZeroVector[16];
    EFI_GUID                 FileSystemGuid;
    uint64_t                 FvLength;
    uint32_t                 Signature;
    uint32_t                 Attributes;
    uint16_t                 HeaderLength;
    uint16_t                 Checksum;
    uint16_t                 ExtHeaderOffset;
    uint8_t                  Reserved;
    uint8_t                  Revision;
    EFI_FV_BLOCK_MAP_ENTRY   BlockMap[1];
};

// -------------------------------------------------------------------
// EFI_FFS_FILE_HEADER — 24 bytes
// -------------------------------------------------------------------
struct EFI_FFS_FILE_HEADER {
    EFI_GUID  Name;             // 16 bytes: file GUID
    uint8_t   IntegrityCheck[2];// Header checksum, file checksum
    uint8_t   Type;             // EFI_FV_FILETYPE_*
    uint8_t   Attributes;       // File attributes flags
    uint8_t   Size[3];          // File size (including this header), little-endian 24-bit
    uint8_t   State;            // File state machine
};

#pragma pack()

#define FVH_SIGNATURE  0x4856465Fu
#define SEARCH_WINDOW  (64 * 1024)
#define ALIGN_UP(v, a) (((v) + ((a)-1)) & ~((a)-1))

// Decode 24-bit little-endian size
static inline uint32_t ffsSize(const uint8_t sz[3]) {
    return (uint32_t)sz[0] | ((uint32_t)sz[1] << 8) | ((uint32_t)sz[2] << 16);
}

// Check if a GUID is all 0xFF (erased flash = end of FFS)
static bool isFFGUID(const EFI_GUID& g) {
    for (int i = 0; i < 16; i++)
        if (g.Data[i] != 0xFF) return false;
    return true;
}

// Check if a GUID is all 0x00 (uninitialized)
static bool isZeroGUID(const EFI_GUID& g) {
    for (int i = 0; i < 16; i++)
        if (g.Data[i] != 0x00) return false;
    return true;
}

static void printGUID(const EFI_GUID& g) {
    printf("{%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        g.Data[3], g.Data[2], g.Data[1], g.Data[0],
        g.Data[5], g.Data[4],
        g.Data[7], g.Data[6],
        g.Data[8], g.Data[9],
        g.Data[10], g.Data[11], g.Data[12], g.Data[13], g.Data[14], g.Data[15]);
}

// -------------------------------------------------------------------
// TODO: Implement this function.
//
// fileTypeName(type) — return a human-readable string for a file type byte.
//
// Type values to handle:
//   0x01 = RAW
//   0x02 = FREEFORM
//   0x03 = SECURITY_CORE
//   0x04 = PEI_CORE
//   0x05 = DXE_CORE
//   0x06 = PEIM
//   0x07 = DXE_DRIVER
//   0x08 = COMBINED_PEIM_DRIVER
//   0x09 = APPLICATION
//   0x0A = SMM
//   0x0B = FIRMWARE_VOLUME_IMAGE
//   0x0C = COMBINED_SMM_DXE
//   0x0D = SMM_CORE
//   0xFF = FFS_PAD
//   default: return "UNKNOWN"
// -------------------------------------------------------------------
static const char* fileTypeName(uint8_t type) {
    // TODO: implement switch statement
    (void)type;
    return "TODO";
}

// -------------------------------------------------------------------
// TODO: Implement this function.
//
// walkFFS(base, fvHdr) — iterate all FFS files in the FV.
//
// Algorithm:
//   1. Start offset = fvHdr->HeaderLength  (end of FV header / block map)
//   2. While offset < fvHdr->FvLength:
//      a. Cast (base + offset) to EFI_FFS_FILE_HEADER*
//      b. If GUID is all-0xFF, break (erased space / end)
//      c. If GUID is all-0x00, advance by 8 and continue (padding)
//      d. Decode size from hdr->Size[3] using ffsSize()
//      e. If size < sizeof(EFI_FFS_FILE_HEADER) or size > remaining, break
//      f. Print: GUID, type name, size
//      g. Advance offset by ALIGN_UP(size, 8)
//
// Expected output per file:
//   "  GUID: {XXXXXXXX-...}  Type: DXE_DRIVER  Size: 0x1234\n"
// -------------------------------------------------------------------
static void walkFFS(const uint8_t* base, const EFI_FIRMWARE_VOLUME_HEADER* fvHdr) {
    // TODO: implement
    (void)base;
    (void)fvHdr;
    printf("  TODO: implement walkFFS\n");
}

// Locate the first FV header in a buffer (search first SEARCH_WINDOW bytes)
static long findFVHeader(const uint8_t* buf, long bufLen) {
    long limit = bufLen < SEARCH_WINDOW ? bufLen : SEARCH_WINDOW;
    for (long i = 0; i <= limit - 4; i++) {
        uint32_t sig;
        memcpy(&sig, buf + i, 4);
        if (sig == FVH_SIGNATURE) {
            long hdrStart = i - 40;
            if (hdrStart >= 0) return hdrStart;
        }
    }
    return -1;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <firmware.bin>\n", argv[0]);
        return 1;
    }

    FILE* f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    long fileSize = ftell(f);
    rewind(f);

    std::vector<uint8_t> buf(fileSize);
    if (fread(buf.data(), 1, fileSize, f) != (size_t)fileSize) {
        fprintf(stderr, "Read error\n");
        fclose(f);
        return 1;
    }
    fclose(f);

    long fvOff = findFVHeader(buf.data(), fileSize);
    if (fvOff < 0) {
        fprintf(stderr, "No EFI Firmware Volume header found.\n");
        return 1;
    }

    const auto* fvHdr = reinterpret_cast<const EFI_FIRMWARE_VOLUME_HEADER*>(buf.data() + fvOff);
    printf("Firmware Volume at offset 0x%lX, FvLength=0x%llX\n\n",
           fvOff, (unsigned long long)fvHdr->FvLength);

    printf("Walking FFS files...\n");
    walkFFS(buf.data() + fvOff, fvHdr);

    return 0;
}
