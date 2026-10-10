// solutions/sol03_section_extract.cpp
// Module 32 — Firmware Analysis, Solution 3
//
// Complete section extractor: finds all PE32 sections in all FFS files
// and writes them to outdir/<GUID>_<seq>.efi
//
// Compile: g++ -std=c++17 -Wall -o sol03.exe sol03_section_extract.cpp
// Run:     sol03.exe <firmware.bin> <outdir>

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
    uint8_t  Size[3];
    uint8_t  Type;
};

// Extended 8-byte section header (Size[0..2] == 0xFFFFFF)
struct EFI_COMMON_SECTION_HEADER2 {
    uint8_t  Size[3];
    uint8_t  Type;
    uint32_t ExtendedSize;
};

#pragma pack()

// Section type constants
#define SEC_COMPRESSED    0x01
#define SEC_PE32          0x10
#define SEC_PIC           0x11
#define SEC_TE            0x12
#define SEC_USER_INTERFACE 0x15
#define SEC_RAW           0x19

#define FVH_SIGNATURE  0x4856465Fu
#define SEARCH_WINDOW  (64u * 1024u)
#define ALIGN_UP(v, a) (((v) + ((a) - 1u)) & ~((a) - 1u))

static inline uint32_t decode24(const uint8_t sz[3]) {
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

static std::string guidToStr(const EFI_GUID& g) {
    char buf[64];
    snprintf(buf, sizeof(buf),
        "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        g.Data[3], g.Data[2], g.Data[1], g.Data[0],
        g.Data[5], g.Data[4], g.Data[7], g.Data[6],
        g.Data[8], g.Data[9], g.Data[10], g.Data[11],
        g.Data[12], g.Data[13], g.Data[14], g.Data[15]);
    return std::string(buf);
}

static bool writeFile(const std::string& path, const uint8_t* data, size_t len) {
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) return false;
    bool ok = fwrite(data, 1, len, f) == len;
    fclose(f);
    return ok;
}

// Extract UTF-16LE string from section payload (USER_INTERFACE section)
static std::string readUTF16(const uint8_t* data, size_t maxBytes) {
    std::string result;
    for (size_t i = 0; i + 1 < maxBytes && i < 128; i += 2) {
        uint16_t ch = data[i] | ((uint16_t)data[i+1] << 8);
        if (ch == 0) break;
        result += (ch < 0x80) ? (char)ch : '?';
    }
    return result;
}

// Process all sections within one FFS file
static int extractSections(const uint8_t* ffsBase, uint32_t ffsTotalSize,
                            const std::string& outdir, const std::string& guidStr,
                            int* seqInOut) {
    const size_t FFS_HDR = sizeof(EFI_FFS_FILE_HEADER);
    uint32_t offset = (uint32_t)FFS_HDR;
    int extracted = 0;

    while (offset + sizeof(EFI_COMMON_SECTION_HEADER) <= ffsTotalSize) {
        const auto* shdr = reinterpret_cast<const EFI_COMMON_SECTION_HEADER*>(
            ffsBase + offset);

        bool extended = (shdr->Size[0] == 0xFF && shdr->Size[1] == 0xFF && shdr->Size[2] == 0xFF);
        uint32_t secSize;
        uint32_t payloadOff;  // offset within ffsBase where payload starts

        if (extended) {
            // 8-byte extended header
            if (offset + sizeof(EFI_COMMON_SECTION_HEADER2) > ffsTotalSize) break;
            const auto* shdr2 = reinterpret_cast<const EFI_COMMON_SECTION_HEADER2*>(
                ffsBase + offset);
            secSize    = shdr2->ExtendedSize;
            payloadOff = offset + (uint32_t)sizeof(EFI_COMMON_SECTION_HEADER2);
        } else {
            secSize    = decode24(shdr->Size);
            payloadOff = offset + (uint32_t)sizeof(EFI_COMMON_SECTION_HEADER);
        }

        if (secSize < (extended ? sizeof(EFI_COMMON_SECTION_HEADER2)
                                 : sizeof(EFI_COMMON_SECTION_HEADER))) break;
        if (offset + secSize > ffsTotalSize) break;

        uint32_t hdrSize    = payloadOff - offset;
        uint32_t payloadLen = secSize - hdrSize;

        switch (shdr->Type) {
            case SEC_PE32:
            case SEC_PIC:
            case SEC_TE: {
                // Save PE32 / PIC / TE images as .efi
                char fname[256];
                const char* ext = (shdr->Type == SEC_TE) ? "te" : "efi";
                snprintf(fname, sizeof(fname), "%s_%d.%s", guidStr.c_str(), *seqInOut, ext);
                std::string fullPath = outdir + "/" + fname;

                if (writeFile(fullPath, ffsBase + payloadOff, payloadLen)) {
                    printf("  [%s] Saved: %s  (%u bytes)\n",
                           shdr->Type == SEC_TE ? "TE " : "PE32", fname, payloadLen);
                    (*seqInOut)++;
                    extracted++;
                } else {
                    printf("  [PE32] ERROR writing %s\n", fullPath.c_str());
                }
                break;
            }

            case SEC_USER_INTERFACE: {
                std::string name = readUTF16(ffsBase + payloadOff, payloadLen);
                printf("  [UI  ] Module name: \"%s\"\n", name.c_str());
                break;
            }

            case SEC_RAW:
                printf("  [RAW ] %u bytes\n", payloadLen);
                break;

            case SEC_COMPRESSED: {
                if (payloadLen >= 5) {
                    // EFI_COMPRESSION_SECTION: UINT32 UncompressedLength + UINT8 CompressionType
                    uint32_t uncompLen;
                    memcpy(&uncompLen, ffsBase + payloadOff, 4);
                    uint8_t compType = ffsBase[payloadOff + 4];
                    const char* typeName =
                        (compType == 0) ? "none" :
                        (compType == 1) ? "EFI_standard" :
                        (compType == 2) ? "LZMA" : "unknown";
                    printf("  [COMP] type=%u (%s)  uncompressed=%u bytes  compressed=%u bytes\n",
                           compType, typeName, uncompLen, payloadLen - 5);
                }
                break;
            }

            default:
                printf("  [0x%02X] %u bytes\n", shdr->Type, payloadLen);
                break;
        }

        // Sections are 4-byte aligned within an FFS file
        uint32_t next = ALIGN_UP(offset + secSize, 4u);
        if (next <= offset) break;   // overflow guard
        offset = next;
    }
    return extracted;
}

static long findFVHeader(const uint8_t* buf, long bufLen) {
    long limit = bufLen < (long)SEARCH_WINDOW ? bufLen : (long)SEARCH_WINDOW;
    for (long i = 0; i <= limit - 4; i++) {
        uint32_t sig; memcpy(&sig, buf + i, 4);
        if (sig == FVH_SIGNATURE) {
            long h = i - 40;
            if (h >= 0 && h + (long)sizeof(EFI_FIRMWARE_VOLUME_HEADER) <= bufLen)
                return h;
        }
    }
    return -1;
}

static int walkFFS(const uint8_t* fvBase, const EFI_FIRMWARE_VOLUME_HEADER* fvHdr,
                    const std::string& outdir) {
    uint64_t fvLen   = fvHdr->FvLength;
    uint32_t offset  = fvHdr->HeaderLength;
    int totalPE = 0;

    while ((uint64_t)offset + sizeof(EFI_FFS_FILE_HEADER) <= fvLen) {
        const auto* fhdr = reinterpret_cast<const EFI_FFS_FILE_HEADER*>(fvBase + offset);

        if (isAllFF(fhdr->Name.Data, 16)) break;
        if (isAllZero(fhdr->Name.Data, 16)) { offset += 8; continue; }

        uint32_t fileSize = decode24(fhdr->Size);
        if (fileSize < sizeof(EFI_FFS_FILE_HEADER)) break;
        if ((uint64_t)offset + fileSize > fvLen) break;

        std::string gs = guidToStr(fhdr->Name);
        printf("File: %s  type=0x%02X  size=0x%X\n",
               gs.c_str(), fhdr->Type, fileSize);

        int seq = 0;
        int pe = extractSections(fvBase + offset, fileSize, outdir, gs, &seq);
        totalPE += pe;

        uint64_t next = ALIGN_UP((uint64_t)offset + fileSize, 8u);
        if (next <= offset) break;
        offset = (uint32_t)next;
    }
    return totalPE;
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

    std::vector<uint8_t> buf((size_t)fileSize);
    if (fread(buf.data(), 1, (size_t)fileSize, f) != (size_t)fileSize) {
        fprintf(stderr, "Read error\n");
        fclose(f); return 1;
    }
    fclose(f);

    long fvOff = findFVHeader(buf.data(), fileSize);
    if (fvOff < 0) {
        fprintf(stderr, "No EFI Firmware Volume header found.\n");
        return 1;
    }

    const auto* fvHdr = reinterpret_cast<const EFI_FIRMWARE_VOLUME_HEADER*>(buf.data() + fvOff);
    printf("Firmware Volume at 0x%lX, FvLength=0x%llX\n\n",
           fvOff, (unsigned long long)fvHdr->FvLength);

    int total = walkFFS(buf.data() + fvOff, fvHdr, std::string(outdir));
    printf("\nExtracted %d PE32/TE image(s) to: %s\n", total, outdir);
    return 0;
}
