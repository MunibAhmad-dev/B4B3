// solutions/sol02_ffs_walk.cpp
// Module 32 — Firmware Analysis, Solution 2
//
// Complete FFS walker: locates the FV header, iterates all FFS files,
// prints GUID, type name, and size for each file.
//
// Compile: g++ -std=c++17 -Wall -o sol02.exe sol02_ffs_walk.cpp
// Run:     sol02.exe <firmware.bin>

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>

#pragma pack(1)

struct EFI_GUID { uint8_t Data[16]; };

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

// FFS file header — 24 bytes
struct EFI_FFS_FILE_HEADER {
    EFI_GUID  Name;               // 16 bytes
    uint8_t   IntegrityCheck[2];  // [0]=header checksum, [1]=file checksum (or 0xAA)
    uint8_t   Type;               // EFI_FV_FILETYPE_*
    uint8_t   Attributes;         // file attributes
    uint8_t   Size[3];            // 24-bit LE size including this header
    uint8_t   State;              // file state machine flags
};

#pragma pack()

#define FVH_SIGNATURE  0x4856465Fu
#define SEARCH_WINDOW  (64u * 1024u)
#define ALIGN_UP(v, a) (((v) + ((a) - 1u)) & ~((a) - 1u))

// Decode 24-bit LE size field
static inline uint32_t ffsFileSize(const uint8_t sz[3]) {
    return (uint32_t)sz[0] | ((uint32_t)sz[1] << 8) | ((uint32_t)sz[2] << 16);
}

static bool isAllFF(const uint8_t* p, size_t n) {
    for (size_t i = 0; i < n; i++) if (p[i] != 0xFF) return false;
    return true;
}

static bool isAllZero(const uint8_t* p, size_t n) {
    for (size_t i = 0; i < n; i++) if (p[i] != 0x00) return false;
    return true;
}

static void printGUID(const EFI_GUID& g) {
    printf("{%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        g.Data[3], g.Data[2], g.Data[1], g.Data[0],
        g.Data[5], g.Data[4],
        g.Data[7], g.Data[6],
        g.Data[8], g.Data[9],
        g.Data[10], g.Data[11], g.Data[12],
        g.Data[13], g.Data[14], g.Data[15]);
}

// Return human-readable file type name
static const char* fileTypeName(uint8_t type) {
    switch (type) {
        case 0x01: return "RAW";
        case 0x02: return "FREEFORM";
        case 0x03: return "SECURITY_CORE";
        case 0x04: return "PEI_CORE";
        case 0x05: return "DXE_CORE";
        case 0x06: return "PEIM";
        case 0x07: return "DXE_DRIVER";
        case 0x08: return "COMBINED_PEIM_DRIVER";
        case 0x09: return "APPLICATION";
        case 0x0A: return "SMM";
        case 0x0B: return "FIRMWARE_VOLUME_IMAGE";
        case 0x0C: return "COMBINED_SMM_DXE";
        case 0x0D: return "SMM_CORE";
        case 0xFF: return "FFS_PAD";
        default:   return "UNKNOWN";
    }
}

// Return decoded attributes as a string
static const char* fileAttrDesc(uint8_t attr) {
    // EFI_FFS_FILE_ATTRIBUTES bits
    static char buf[64];
    buf[0] = 0;
    if (attr & 0x01) strncat(buf, "LARGE_FILE ", sizeof(buf)-strlen(buf)-1);
    if (attr & 0x04) strncat(buf, "DATA_ALIGNMENT ", sizeof(buf)-strlen(buf)-1);
    if (attr & 0x08) strncat(buf, "FIXED ", sizeof(buf)-strlen(buf)-1);
    if (attr & 0x40) strncat(buf, "CHECKSUM ", sizeof(buf)-strlen(buf)-1);
    return buf[0] ? buf : "(none)";
}

// Walk all FFS files in one Firmware Volume
static int walkFFS(const uint8_t* fvBase, const EFI_FIRMWARE_VOLUME_HEADER* fvHdr) {
    uint64_t fvLen = fvHdr->FvLength;
    uint32_t startOff = fvHdr->HeaderLength;
    int fileCount = 0;

    if (startOff >= fvLen) {
        printf("  (FV header length equals or exceeds FvLength — empty volume)\n");
        return 0;
    }

    uint64_t offset = startOff;

    while (offset + sizeof(EFI_FFS_FILE_HEADER) <= fvLen) {
        const auto* fhdr = reinterpret_cast<const EFI_FFS_FILE_HEADER*>(fvBase + offset);

        // Erased flash: GUID all 0xFF means end of populated FFS area
        if (isAllFF(fhdr->Name.Data, 16)) {
            printf("  [0x%06llX] End of FFS (erased flash)\n", (unsigned long long)offset);
            break;
        }

        // All-zero GUID: alignment/padding bytes, advance by 8
        if (isAllZero(fhdr->Name.Data, 16)) {
            offset += 8;
            continue;
        }

        // Decode the 24-bit file size
        uint32_t fileSize = ffsFileSize(fhdr->Size);

        // Sanity checks
        if (fileSize < sizeof(EFI_FFS_FILE_HEADER)) {
            printf("  [0x%06llX] WARNING: file size (%u) smaller than header (%zu), stopping\n",
                   (unsigned long long)offset, fileSize, sizeof(EFI_FFS_FILE_HEADER));
            break;
        }
        if (offset + fileSize > fvLen) {
            printf("  [0x%06llX] WARNING: file extends beyond FV (size=0x%X), stopping\n",
                   (unsigned long long)offset, fileSize);
            break;
        }

        // Print file information
        fileCount++;
        printf("  [0x%06llX] GUID: ", (unsigned long long)offset);
        printGUID(fhdr->Name);
        printf("\n             Type: 0x%02X (%s)  Size: 0x%06X (%u bytes)  State: 0x%02X  Attr: %s\n",
               fhdr->Type, fileTypeName(fhdr->Type),
               fileSize, fileSize,
               fhdr->State,
               fileAttrDesc(fhdr->Attributes));

        // FFS files are 8-byte aligned
        uint64_t nextOff = ALIGN_UP((uint64_t)(offset + fileSize), 8u);
        if (nextOff <= offset) break;   // overflow guard
        offset = nextOff;
    }

    return fileCount;
}

// Search first SEARCH_WINDOW bytes for an FV header
static long findFVHeader(const uint8_t* buf, long bufLen) {
    long limit = bufLen < (long)SEARCH_WINDOW ? bufLen : (long)SEARCH_WINDOW;
    for (long i = 0; i <= limit - 4; i++) {
        uint32_t sig;
        memcpy(&sig, buf + i, 4);
        if (sig == FVH_SIGNATURE) {
            long h = i - 40;
            if (h >= 0 && h + (long)sizeof(EFI_FIRMWARE_VOLUME_HEADER) <= bufLen)
                return h;
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

    std::vector<uint8_t> buf((size_t)fileSize);
    if (fread(buf.data(), 1, (size_t)fileSize, f) != (size_t)fileSize) {
        fprintf(stderr, "Read error.\n");
        fclose(f);
        return 1;
    }
    fclose(f);

    // Find the first FV
    long fvOff = findFVHeader(buf.data(), fileSize);
    if (fvOff < 0) {
        fprintf(stderr, "No EFI Firmware Volume header found.\n");
        return 1;
    }

    const auto* fvHdr = reinterpret_cast<const EFI_FIRMWARE_VOLUME_HEADER*>(
        buf.data() + fvOff);

    // Validate FV doesn't overrun the file
    uint64_t fvLen = fvHdr->FvLength;
    if ((uint64_t)fvOff + fvLen > (uint64_t)fileSize) {
        printf("WARNING: FvLength (0x%llX) extends past file end. Clamping.\n",
               (unsigned long long)fvLen);
        fvLen = (uint64_t)(fileSize - fvOff);
    }

    printf("Firmware Volume at file offset 0x%lX\n", fvOff);
    printf("FvLength    : 0x%llX (%llu bytes)\n",
           (unsigned long long)fvHdr->FvLength,
           (unsigned long long)fvHdr->FvLength);
    printf("HeaderLength: %u bytes\n\n", fvHdr->HeaderLength);
    printf("Walking FFS files:\n");
    printf("%-10s %-50s %-25s %-10s\n", "Offset", "GUID", "Type", "Size");
    printf("%s\n", std::string(100, '-').c_str());

    int n = walkFFS(buf.data() + fvOff, fvHdr);
    printf("\nTotal FFS files found: %d\n", n);
    return 0;
}
