// exercise_01_fw_header.cpp
// Module 32 — Firmware Analysis, Exercise 1
//
// Goal: Open a UEFI firmware binary, locate the EFI_FIRMWARE_VOLUME_HEADER,
//       validate its "_FVH" signature, and print basic volume information.
//
// Compile: g++ -std=c++17 -Wall -o ex01.exe exercise_01_fw_header.cpp
// Run:     ex01.exe <firmware.bin>
//
// The "_FVH" signature (0x4856465F) lives at byte offset 40 within the header.
// The header may not be at file offset 0 — search the first 64 KB.

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>

// -------------------------------------------------------------------
// UEFI structure definitions (from UEFI PI spec / EDK2 headers)
// -------------------------------------------------------------------

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
    EFI_FV_BLOCK_MAP_ENTRY   BlockMap[1];     // variable-length; ends with {0,0}
};

#pragma pack()

#define FVH_SIGNATURE  0x4856465Fu
#define SEARCH_WINDOW  (64 * 1024)

// Print a GUID in the standard {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX} format
static void printGUID(const EFI_GUID& g) {
    // GUID fields: Data1(4), Data2(2), Data3(2), Data4(8) — first 8 bytes little-endian words
    printf("{%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        g.Data[3], g.Data[2], g.Data[1], g.Data[0],
        g.Data[5], g.Data[4],
        g.Data[7], g.Data[6],
        g.Data[8], g.Data[9],
        g.Data[10], g.Data[11], g.Data[12], g.Data[13], g.Data[14], g.Data[15]);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <firmware.bin>\n", argv[0]);
        return 1;
    }

    // Open and read the file
    FILE* f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long fileSize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fileSize < (long)sizeof(EFI_FIRMWARE_VOLUME_HEADER)) {
        fprintf(stderr, "File too small to contain a firmware volume header.\n");
        fclose(f);
        return 1;
    }

    // Read entire file (or first SEARCH_WINDOW bytes for the signature scan)
    long readLen = fileSize < (long)SEARCH_WINDOW ? fileSize : (long)SEARCH_WINDOW;
    std::vector<uint8_t> buf(fileSize);
    if (fread(buf.data(), 1, fileSize, f) != (size_t)fileSize) {
        fprintf(stderr, "Failed to read file.\n");
        fclose(f);
        return 1;
    }
    fclose(f);

    // -------------------------------------------------------------------
    // Locate the "_FVH" signature.
    // The signature sits at offset 40 (0x28) within EFI_FIRMWARE_VOLUME_HEADER.
    // We scan the first SEARCH_WINDOW bytes for the 4-byte pattern.
    // -------------------------------------------------------------------
    long fvOffset = -1;
    for (long i = 0; i <= readLen - 4; i++) {
        uint32_t sig;
        memcpy(&sig, buf.data() + i, 4);
        if (sig == FVH_SIGNATURE) {
            // The signature is at offset 40 inside the header,
            // so the header starts 40 bytes before this position.
            long hdrStart = i - 40;
            if (hdrStart >= 0) {
                fvOffset = hdrStart;
                break;
            }
        }
    }

    if (fvOffset < 0) {
        fprintf(stderr, "No valid EFI Firmware Volume header found in first %d bytes.\n",
                SEARCH_WINDOW);
        return 1;
    }

    printf("Found EFI_FIRMWARE_VOLUME_HEADER at file offset 0x%lX\n\n", fvOffset);

    const auto* hdr = reinterpret_cast<const EFI_FIRMWARE_VOLUME_HEADER*>(buf.data() + fvOffset);

    // Basic validation
    if (hdr->Signature != FVH_SIGNATURE) {
        fprintf(stderr, "Signature mismatch (unexpected).\n");
        return 1;
    }

    // Print header fields
    printf("Signature   : 0x%08X (_FVH)\n", hdr->Signature);
    printf("Revision    : %u\n", hdr->Revision);
    printf("FvLength    : 0x%016llX (%llu bytes)\n",
           (unsigned long long)hdr->FvLength, (unsigned long long)hdr->FvLength);
    printf("Attributes  : 0x%08X\n", hdr->Attributes);
    printf("HeaderLength: %u bytes\n", hdr->HeaderLength);
    printf("Checksum    : 0x%04X\n", hdr->Checksum);
    printf("ExtHdrOffset: 0x%04X\n", hdr->ExtHeaderOffset);
    printf("FileSystem  : ");
    printGUID(hdr->FileSystemGuid);
    printf("\n\n");

    // -------------------------------------------------------------------
    // TODO 1: Walk the BlockMap array and print each entry.
    //
    // The BlockMap starts at hdr->BlockMap[0] and ends when an entry
    // has NumBlocks == 0 AND Length == 0.
    //
    // For each non-terminating entry, print:
    //   "  Block entry: NumBlocks=%u, BlockSize=0x%X, Span=%llu bytes\n"
    //
    // Hint: access entries as hdr->BlockMap[i] while both fields are non-zero.
    // -------------------------------------------------------------------

    // TODO 2: Sum all (NumBlocks * Length) values across the block map
    //         and compare to hdr->FvLength. Print whether they match.
    //         Example output:
    //   "Total size from BlockMap : 0x%llX\n"
    //   "FvLength in header       : 0x%llX\n"
    //   "Match: YES / NO\n"

    return 0;
}
