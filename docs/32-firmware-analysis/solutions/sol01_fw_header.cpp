// solutions/sol01_fw_header.cpp
// Module 32 — Firmware Analysis, Solution 1
//
// Complete solution: open firmware binary, locate EFI_FIRMWARE_VOLUME_HEADER,
// validate "_FVH" signature, print all fields, walk block map, verify FvLength.
//
// Compile: g++ -std=c++17 -Wall -o sol01.exe sol01_fw_header.cpp
// Run:     sol01.exe <firmware.bin>

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <string>

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
    uint32_t                 Signature;       // 0x4856465F = "_FVH"
    uint32_t                 Attributes;
    uint16_t                 HeaderLength;
    uint16_t                 Checksum;
    uint16_t                 ExtHeaderOffset;
    uint8_t                  Reserved;
    uint8_t                  Revision;
    EFI_FV_BLOCK_MAP_ENTRY   BlockMap[1];     // variable-length, ends with {0,0}
};

#pragma pack()

#define FVH_SIGNATURE  0x4856465Fu
#define SEARCH_WINDOW  (64u * 1024u)

// Known FileSystem GUIDs
static struct { const uint8_t guid[16]; const char* name; } knownFSGuids[] = {
    { {0x78, 0xE5, 0x8C, 0x8C, 0x3D, 0x8A, 0x1C, 0x4F, 0x99, 0x35, 0x89, 0x61, 0x85, 0xC3, 0x2D, 0xD3},
      "EFI_FIRMWARE_FILE_SYSTEM2_GUID (FFS2)" },
    { {0x7A, 0xC0, 0x73, 0x54, 0xCB, 0x3D, 0xCA, 0x4D, 0xBD, 0x6F, 0x1E, 0x96, 0x89, 0xE7, 0x34, 0x9A},
      "EFI_FIRMWARE_FILE_SYSTEM3_GUID (FFS3)" },
    { {0x78, 0x2C, 0xF3, 0xAA, 0x7B, 0x94, 0x9A, 0x43, 0xA1, 0x80, 0x2E, 0x14, 0x4E, 0xC3, 0x77, 0x92},
      "NVRAM Variable Store" },
};

static void printGUID(const EFI_GUID& g) {
    printf("{%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        g.Data[3], g.Data[2], g.Data[1], g.Data[0],
        g.Data[5], g.Data[4],
        g.Data[7], g.Data[6],
        g.Data[8], g.Data[9],
        g.Data[10], g.Data[11], g.Data[12], g.Data[13], g.Data[14], g.Data[15]);
}

static const char* lookupFSGuid(const EFI_GUID& g) {
    for (auto& e : knownFSGuids) {
        if (memcmp(g.Data, e.guid, 16) == 0) return e.name;
    }
    return "Unknown GUID";
}

// Decode attribute flags to a string
static std::string decodeAttributes(uint32_t attr) {
    std::string s;
    auto add = [&](uint32_t mask, const char* name) {
        if (attr & mask) { if (!s.empty()) s += " | "; s += name; }
    };
    add(0x0004, "READ_STATUS");
    add(0x0020, "WRITE_STATUS");
    add(0x0080, "LOCK_STATUS");
    add(0x0800, "ALIGNMENT");
    add(0x8000, "WEAK_ALIGNMENT");
    if (s.empty()) s = "(none)";
    return s;
}

// Validate header checksum: sum of all UINT16 words in the header must be 0
static bool validateChecksum(const EFI_FIRMWARE_VOLUME_HEADER* hdr) {
    const uint16_t* words = reinterpret_cast<const uint16_t*>(hdr);
    uint16_t sum = 0;
    for (size_t i = 0; i < hdr->HeaderLength / 2; i++)
        sum = (uint16_t)(sum + words[i]);
    return sum == 0;
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

    if (fileSize < (long)sizeof(EFI_FIRMWARE_VOLUME_HEADER)) {
        fprintf(stderr, "File too small.\n");
        fclose(f);
        return 1;
    }

    std::vector<uint8_t> buf((size_t)fileSize);
    if (fread(buf.data(), 1, (size_t)fileSize, f) != (size_t)fileSize) {
        fprintf(stderr, "Read error.\n");
        fclose(f);
        return 1;
    }
    fclose(f);

    // Search first 64 KB for the "_FVH" signature
    // The signature sits at byte offset 40 inside the header structure
    long searchEnd = (long)buf.size() < SEARCH_WINDOW ? (long)buf.size() : SEARCH_WINDOW;
    long fvOffset = -1;

    for (long i = 0; i <= searchEnd - 4; i++) {
        uint32_t sig;
        memcpy(&sig, buf.data() + i, 4);
        if (sig == FVH_SIGNATURE) {
            long hdrStart = i - 40;  // signature is at offset 40 in the header
            if (hdrStart >= 0 &&
                hdrStart + (long)sizeof(EFI_FIRMWARE_VOLUME_HEADER) <= fileSize) {
                fvOffset = hdrStart;
                break;
            }
        }
    }

    if (fvOffset < 0) {
        fprintf(stderr, "ERROR: No EFI_FIRMWARE_VOLUME_HEADER found in first %u bytes.\n",
                SEARCH_WINDOW);
        return 1;
    }

    const auto* hdr = reinterpret_cast<const EFI_FIRMWARE_VOLUME_HEADER*>(
        buf.data() + fvOffset);

    // Validate header doesn't overrun buffer
    if (fvOffset + hdr->HeaderLength > fileSize) {
        fprintf(stderr, "ERROR: Header extends beyond file.\n");
        return 1;
    }

    printf("=== EFI Firmware Volume Header ===\n");
    printf("File offset        : 0x%lX\n", fvOffset);
    printf("Signature          : 0x%08X (_FVH) -- valid\n", hdr->Signature);
    printf("Revision           : %u\n", (unsigned)hdr->Revision);
    printf("FvLength           : 0x%016llX  (%llu bytes)\n",
           (unsigned long long)hdr->FvLength, (unsigned long long)hdr->FvLength);
    printf("Attributes         : 0x%08X  [%s]\n",
           hdr->Attributes, decodeAttributes(hdr->Attributes).c_str());
    printf("HeaderLength       : %u bytes\n", hdr->HeaderLength);
    printf("Checksum           : 0x%04X  [%s]\n",
           hdr->Checksum, validateChecksum(hdr) ? "VALID" : "INVALID");
    printf("ExtHeaderOffset    : 0x%04X%s\n",
           hdr->ExtHeaderOffset, hdr->ExtHeaderOffset ? "" : " (none)");
    printf("FileSystem GUID    : ");
    printGUID(hdr->FileSystemGuid);
    printf("\n                     %s\n", lookupFSGuid(hdr->FileSystemGuid));

    // Walk the BlockMap
    printf("\n--- Block Map ---\n");
    uint64_t totalFromMap = 0;
    int mapIdx = 0;

    // BlockMap starts right after the fixed fields.
    // Since HeaderLength includes the variable-length block map, we read entries
    // until we hit the {0, 0} terminator.
    const EFI_FV_BLOCK_MAP_ENTRY* entry = hdr->BlockMap;

    // Safety: BlockMap starts at offset 56 in the header. We can't go past HeaderLength.
    const uint8_t* hdrBase = reinterpret_cast<const uint8_t*>(hdr);
    const uint8_t* hdrEnd  = hdrBase + hdr->HeaderLength;

    while (reinterpret_cast<const uint8_t*>(entry) + sizeof(EFI_FV_BLOCK_MAP_ENTRY) <= hdrEnd) {
        if (entry->NumBlocks == 0 && entry->Length == 0) {
            printf("  [%d] Terminator {0, 0}\n", mapIdx);
            break;
        }
        uint64_t span = (uint64_t)entry->NumBlocks * entry->Length;
        totalFromMap += span;
        printf("  [%d] NumBlocks=%-6u  BlockSize=0x%05X  Span=%llu bytes (0x%llX)\n",
               mapIdx,
               entry->NumBlocks,
               entry->Length,
               (unsigned long long)span,
               (unsigned long long)span);
        entry++;
        mapIdx++;
    }

    printf("\n--- Size Verification ---\n");
    printf("Total size from BlockMap : 0x%llX  (%llu bytes)\n",
           (unsigned long long)totalFromMap, (unsigned long long)totalFromMap);
    printf("FvLength in header       : 0x%llX  (%llu bytes)\n",
           (unsigned long long)hdr->FvLength, (unsigned long long)hdr->FvLength);
    printf("Match                    : %s\n",
           (totalFromMap == hdr->FvLength) ? "YES" : "NO (inconsistency!)");

    if (hdr->FvLength > (uint64_t)(fileSize - fvOffset)) {
        printf("\nWARNING: FvLength (0x%llX) exceeds remaining file size (0x%lX).\n"
               "         The binary may be incomplete or truncated.\n",
               (unsigned long long)hdr->FvLength, fileSize - fvOffset);
    }

    return 0;
}
