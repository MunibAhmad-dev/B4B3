// exercise_03_section_extract.cpp
// Module 32 — Firmware Analysis, Exercise 3
//
// Goal: Recurse into FFS files, find PE32 sections (type 0x10),
//       and save each to outdir/<guid_hex>_<seq>.efi
//
// Compile: g++ -std=c++17 -Wall -o ex03.exe exercise_03_section_extract.cpp
// Run:     ex03.exe <firmware.bin> <outdir>
//
// UEFI section types of interest:
//   0x01 = COMPRESSED   (contains a compression type byte + data)
//   0x10 = PE32         (raw PE/COFF image — save as .efi)
//   0x15 = USER_INTERFACE (UTF-16 module name)
//   0x19 = RAW

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <string>
#include <sys/stat.h>

#ifdef _WIN32
#  include <direct.h>
#  define MKDIR(p) _mkdir(p)
#else
#  define MKDIR(p) mkdir((p), 0755)
#endif

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

struct EFI_FFS_FILE_HEADER {
    EFI_GUID  Name;
    uint8_t   IntegrityCheck[2];
    uint8_t   Type;
    uint8_t   Attributes;
    uint8_t   Size[3];
    uint8_t   State;
};

// Standard 4-byte section header
struct EFI_COMMON_SECTION_HEADER {
    uint8_t  Size[3];   // section size including this header (24-bit LE)
    uint8_t  Type;      // section type
};

// Extended 8-byte section header (used when Size[0..2] == 0xFFFFFF)
struct EFI_COMMON_SECTION_HEADER2 {
    uint8_t  Size[3];       // must be 0xFF 0xFF 0xFF
    uint8_t  Type;
    uint32_t ExtendedSize;  // actual size including this 8-byte header
};

#pragma pack()

#define FVH_SIGNATURE  0x4856465Fu
#define SEARCH_WINDOW  (64 * 1024)
#define ALIGN_UP(v, a) (((v) + ((a)-1)) & ~((a)-1))

// Section type constants
#define EFI_SECTION_COMPRESSION    0x01
#define EFI_SECTION_PE32           0x10
#define EFI_SECTION_USER_INTERFACE 0x15
#define EFI_SECTION_RAW            0x19

static inline uint32_t ffsSize(const uint8_t sz[3]) {
    return (uint32_t)sz[0] | ((uint32_t)sz[1] << 8) | ((uint32_t)sz[2] << 16);
}

static bool isFFGUID(const EFI_GUID& g) {
    for (int i = 0; i < 16; i++) if (g.Data[i] != 0xFF) return false;
    return true;
}
static bool isZeroGUID(const EFI_GUID& g) {
    for (int i = 0; i < 16; i++) if (g.Data[i] != 0x00) return false;
    return true;
}

static std::string guidToHex(const EFI_GUID& g) {
    char buf[64];
    snprintf(buf, sizeof(buf),
        "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        g.Data[3], g.Data[2], g.Data[1], g.Data[0],
        g.Data[5], g.Data[4], g.Data[7], g.Data[6],
        g.Data[8], g.Data[9], g.Data[10], g.Data[11],
        g.Data[12], g.Data[13], g.Data[14], g.Data[15]);
    return std::string(buf);
}

// -------------------------------------------------------------------
// TODO: Implement extractSections()
//
// Parameters:
//   ffsData    — pointer to start of EFI_FFS_FILE_HEADER
//   ffsSize    — total size of the FFS file (from Size[3])
//   outdir     — output directory path
//   guidStr    — file's GUID as hex string (for output filenames)
//   seqInOut   — pointer to a counter, increment each time you write a .efi file
//
// Algorithm:
//   1. offset = sizeof(EFI_FFS_FILE_HEADER)
//   2. While offset < ffsSize:
//      a. Read EFI_COMMON_SECTION_HEADER at (ffsData + offset)
//      b. Check if Size[0..2] == {0xFF,0xFF,0xFF}:
//           - If yes: this is an extended section header (EFI_COMMON_SECTION_HEADER2)
//             actual size = EFI_COMMON_SECTION_HEADER2::ExtendedSize
//             payload starts at offset + 8
//           - If no:  size = ffsSize(hdr->Size), payload starts at offset + 4
//      c. If size < 4 or offset+size > ffsSize, break
//      d. Switch on section Type:
//           0x10 (PE32):
//             write bytes from payload start, length = (size - header_size)
//             to file: outdir/<guidStr>_<*seqInOut>.efi
//             increment *seqInOut
//             print: "  [PE32] Saved <filename> (%u bytes)\n"
//           0x15 (USER_INTERFACE):
//             the payload is a UTF-16LE string (module name)
//             print up to 64 chars, converting each uint16_t to char
//             print: "  [UI] Module name: <name>\n"
//           0x19 (RAW):
//             print: "  [RAW] %u bytes\n", payload size
//           0x01 (COMPRESSED):
//             first byte of payload is CompressionType (0=none, 1=EFI, 2=LZMA)
//             print: "  [COMPRESSED] type=%u, compressed size=%u\n"
//           default:
//             print: "  [SECTION type=0x%02X] %u bytes\n"
//      e. Advance offset by ALIGN_UP(size, 4)
// -------------------------------------------------------------------
static void extractSections(const uint8_t* ffsData, uint32_t ffsTotalSize,
                             const std::string& outdir, const std::string& guidStr,
                             int* seqInOut) {
    // TODO: implement
    (void)ffsData; (void)ffsTotalSize; (void)outdir; (void)guidStr; (void)seqInOut;
    printf("  TODO: implement extractSections\n");
}

static long findFVHeader(const uint8_t* buf, long bufLen) {
    long limit = bufLen < SEARCH_WINDOW ? bufLen : SEARCH_WINDOW;
    for (long i = 0; i <= limit - 4; i++) {
        uint32_t sig; memcpy(&sig, buf + i, 4);
        if (sig == FVH_SIGNATURE) {
            long h = i - 40;
            if (h >= 0) return h;
        }
    }
    return -1;
}

// -------------------------------------------------------------------
// TODO: Implement walkFFS()
//
// Same algorithm as exercise_02, but for each valid FFS file call:
//   extractSections(filePtr, fileSize, outdir, guidStr, &seq)
// Print "File: <GUID>  Type: <hex>  Size: <hex>\n" for each file found.
// -------------------------------------------------------------------
static void walkFFS(const uint8_t* base, const EFI_FIRMWARE_VOLUME_HEADER* fvHdr,
                    const std::string& outdir) {
    // TODO: implement
    (void)base; (void)fvHdr; (void)outdir;
    printf("TODO: implement walkFFS\n");
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <firmware.bin> <outdir>\n", argv[0]);
        return 1;
    }
    const char* fwPath = argv[1];
    const char* outdir = argv[2];

    MKDIR(outdir);

    FILE* f = fopen(fwPath, "rb");
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
    printf("FV at 0x%lX, FvLength=0x%llX\n\n",
           fvOff, (unsigned long long)fvHdr->FvLength);

    walkFFS(buf.data() + fvOff, fvHdr, std::string(outdir));
    return 0;
}
