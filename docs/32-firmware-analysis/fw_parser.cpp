// fw_parser.cpp — UEFI Firmware Parser
// Module 32 — Firmware Analysis
//
// Single self-contained UEFI firmware analysis tool. No external dependencies.
//
// Commands:
//   fw_parser.exe list    <fw.bin>          -- list all FFS files
//   fw_parser.exe extract <fw.bin> <outdir> -- extract all PE32/TE sections as .efi/.te
//   fw_parser.exe info    <fw.bin>          -- print all FV headers and block maps
//   fw_parser.exe scan    <fw.bin>          -- security scan (WX sections, IPs, entropy, names)
//
// Handles multiple FVs (scans entire file for all _FVH occurrences).
//
// Compile: g++ -std=c++17 -Wall -o fw_parser.exe fw_parser.cpp
// Windows-only (uses _mkdir).

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <cctype>
#include <vector>
#include <string>
#include <algorithm>

#ifdef _WIN32
#  include <direct.h>
#  define MKDIR(p) _mkdir(p)
#else
#  include <sys/stat.h>
#  define MKDIR(p) mkdir((p), 0755)
#endif

// =====================================================================
// UEFI structure definitions
// =====================================================================

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
    uint32_t                 Signature;       // 0x4856465F
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

struct EFI_COMMON_SECTION_HEADER {
    uint8_t  Size[3];
    uint8_t  Type;
};

struct EFI_COMMON_SECTION_HEADER2 {
    uint8_t  Size[3];
    uint8_t  Type;
    uint32_t ExtendedSize;
};

// PE headers (subset needed for scan)
struct MY_DOS_HDR  { uint16_t e_magic; uint8_t pad[58]; uint32_t e_lfanew; };
struct MY_FILE_HDR { uint16_t Machine; uint16_t NumSections; uint32_t TS;
                     uint32_t PSymTab; uint32_t NSyms; uint16_t SzOptHdr; uint16_t Chars; };
struct MY_SEC_HDR  { char Name[8]; uint32_t VS; uint32_t VA; uint32_t SzRaw;
                     uint32_t PtrRaw; uint32_t PtrReloc; uint32_t PtrLines;
                     uint16_t NReloc; uint16_t NLines; uint32_t Chars; };
struct MY_DATADIR  { uint32_t VA; uint32_t Size; };

struct MY_OPT32 {
    uint16_t Magic; uint8_t ML; uint8_t ML2; uint32_t SzCode;
    uint32_t SzInit; uint32_t SzUninit; uint32_t EntryPoint; uint32_t BaseCode;
    uint32_t BaseData; uint32_t ImageBase; uint32_t SecAlign; uint32_t FileAlign;
    uint16_t MajOS; uint16_t MinOS; uint16_t MajImg; uint16_t MinImg;
    uint16_t MajSub; uint16_t MinSub; uint32_t Win32V; uint32_t SzImage;
    uint32_t SzHdrs; uint32_t CheckSum; uint16_t Subsystem; uint16_t DllChars;
    uint32_t SzStackR; uint32_t SzStackC; uint32_t SzHeapR; uint32_t SzHeapC;
    uint32_t LoaderFlags; uint32_t NumDirs; MY_DATADIR DataDir[16];
};

struct MY_OPT64 {
    uint16_t Magic; uint8_t ML; uint8_t ML2; uint32_t SzCode;
    uint32_t SzInit; uint32_t SzUninit; uint32_t EntryPoint; uint32_t BaseCode;
    uint64_t ImageBase; uint32_t SecAlign; uint32_t FileAlign;
    uint16_t MajOS; uint16_t MinOS; uint16_t MajImg; uint16_t MinImg;
    uint16_t MajSub; uint16_t MinSub; uint32_t Win32V; uint32_t SzImage;
    uint32_t SzHdrs; uint32_t CheckSum; uint16_t Subsystem; uint16_t DllChars;
    uint64_t SzStackR; uint64_t SzStackC; uint64_t SzHeapR; uint64_t SzHeapC;
    uint32_t LoaderFlags; uint32_t NumDirs; MY_DATADIR DataDir[16];
};

struct MY_NT32 { uint32_t Sig; MY_FILE_HDR FH; MY_OPT32 OH; };
struct MY_NT64 { uint32_t Sig; MY_FILE_HDR FH; MY_OPT64 OH; };

struct MY_IMPORT_DESC {
    uint32_t OrigFirstThunk; uint32_t TS; uint32_t FwdChain;
    uint32_t Name; uint32_t FirstThunk;
};

#pragma pack()

// =====================================================================
// Constants
// =====================================================================

#define FVH_SIGNATURE    0x4856465Fu
#define ALIGN_UP(v, a)   (((v) + ((a)-1u)) & ~((a)-1u))
#define SEC_MEM_WRITE    0x80000000u
#define SEC_MEM_EXEC     0x20000000u

// =====================================================================
// Utility functions
// =====================================================================

static inline uint32_t dec24(const uint8_t s[3]) {
    return (uint32_t)s[0] | ((uint32_t)s[1]<<8) | ((uint32_t)s[2]<<16);
}

static bool isAllFF(const uint8_t* p, size_t n) {
    for (size_t i=0;i<n;i++) if (p[i]!=0xFF) return false; return true;
}
static bool isAllZero(const uint8_t* p, size_t n) {
    for (size_t i=0;i<n;i++) if (p[i]!=0x00) return false; return true;
}

static std::string guidStr(const EFI_GUID& g) {
    char b[64];
    snprintf(b,sizeof(b),
        "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        g.Data[3],g.Data[2],g.Data[1],g.Data[0],
        g.Data[5],g.Data[4],g.Data[7],g.Data[6],
        g.Data[8],g.Data[9],g.Data[10],g.Data[11],
        g.Data[12],g.Data[13],g.Data[14],g.Data[15]);
    return b;
}

static const char* fileTypeName(uint8_t t) {
    switch(t){
        case 0x01: return "RAW";            case 0x02: return "FREEFORM";
        case 0x03: return "SECURITY_CORE";  case 0x04: return "PEI_CORE";
        case 0x05: return "DXE_CORE";       case 0x06: return "PEIM";
        case 0x07: return "DXE_DRIVER";     case 0x08: return "COMBINED_PEIM_DRIVER";
        case 0x09: return "APPLICATION";    case 0x0A: return "SMM";
        case 0x0B: return "FV_IMAGE";       case 0x0C: return "COMBINED_SMM_DXE";
        case 0x0D: return "SMM_CORE";       case 0xFF: return "FFS_PAD";
        default:   return "UNKNOWN";
    }
}

// Shannon entropy over a byte array
static double shannonEntropy(const uint8_t* data, size_t len) {
    if (len == 0) return 0.0;
    uint64_t freq[256] = {};
    for (size_t i=0;i<len;i++) freq[data[i]]++;
    double e = 0.0;
    for (int i=0;i<256;i++) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / (double)len;
        e -= p * log2(p);
    }
    return e;
}

// Extract UTF-16LE string (up to maxChars) into ASCII (best effort)
static std::string utf16le(const uint8_t* p, size_t byteLen) {
    std::string r;
    for (size_t i=0; i+1<byteLen && r.size()<64; i+=2) {
        uint16_t c = p[i] | ((uint16_t)p[i+1]<<8);
        if (c==0) break;
        r += (c<128) ? (char)c : '?';
    }
    return r;
}

// Try to find an IPv4 address in a raw byte range
static std::vector<std::string> findIPv4(const uint8_t* data, size_t len) {
    std::vector<std::string> found;
    if (len < 7) return found;
    for (size_t i=0; i+4<len; i++) {
        // Heuristic: 4 consecutive bytes where each is 1-254
        // and the sequence forms a plausible IP (not 0.0.0.0, not 255.x.x.x broadcast range)
        // Also look for printable "a.b.c.d" text
        if (isdigit(data[i])) {
            // Scan for text IP
            char buf[20]={};
            size_t j=i, blen=0;
            while (j<len && blen<18 && (isdigit(data[j])||data[j]=='.')) {
                buf[blen++]=(char)data[j++];
            }
            if (blen>=7) {
                // Validate as IP
                int a,b,c,d;
                if (sscanf(buf,"%d.%d.%d.%d",&a,&b,&c,&d)==4 &&
                    a>=1 && a<=254 && b>=0 && b<=255 &&
                    c>=0 && c<=255 && d>=1 && d<=254) {
                    std::string ip = buf;
                    if (std::find(found.begin(),found.end(),ip)==found.end())
                        found.push_back(ip);
                }
            }
        }
    }
    return found;
}

// Check if a PE image at `data` of size `len` has any W+X sections
static bool peHasWXSection(const uint8_t* data, size_t len, std::string& detail) {
    if (len < 64) return false;
    const auto* dos = reinterpret_cast<const MY_DOS_HDR*>(data);
    if (dos->e_magic != 0x5A4D) return false;
    if (dos->e_lfanew + 4 > (uint32_t)len) return false;
    uint32_t ntSig; memcpy(&ntSig, data+dos->e_lfanew, 4);
    if (ntSig != 0x00004550u) return false;

    uint16_t optMagic; memcpy(&optMagic, data+dos->e_lfanew+4+sizeof(MY_FILE_HDR), 2);
    uint16_t numSec;
    const MY_SEC_HDR* secHdrs = nullptr;
    size_t fhOffset = dos->e_lfanew + 4;
    MY_FILE_HDR fh; memcpy(&fh, data+fhOffset, sizeof(fh));
    numSec = fh.NumSections;

    secHdrs = reinterpret_cast<const MY_SEC_HDR*>(
        data + fhOffset + sizeof(MY_FILE_HDR) + fh.SzOptHdr);

    for (uint16_t i=0; i<numSec && i<32; i++) {
        if ((secHdrs[i].Chars & SEC_MEM_WRITE) && (secHdrs[i].Chars & SEC_MEM_EXEC)) {
            char name[9]={};
            memcpy(name, secHdrs[i].Name, 8);
            detail = name;
            return true;
        }
    }
    return false;
}

// Backdoor module name heuristic (known suspicious UEFI module names)
static const char* knownBadNames[] = {
    "SmmBackdoor","PrivilegedShell","SMM_HACK","CoreDriverHook",
    "PersistentBootkit","RawPELoader","HiddenAgent","FirmwareRat",
    "IntelMEHook","EmbeddedShell","BackdoorSMM",
    nullptr
};

static bool isSuspiciousName(const std::string& name) {
    std::string upper = name;
    for (auto& c : upper) c = (char)toupper((unsigned char)c);
    for (int i=0; knownBadNames[i]; i++) {
        std::string kn = knownBadNames[i];
        for (auto& c : kn) c = (char)toupper((unsigned char)c);
        if (upper.find(kn) != std::string::npos) return true;
    }
    return false;
}

static bool writeFile(const std::string& path, const uint8_t* d, size_t n) {
    FILE* f = fopen(path.c_str(),"wb");
    if (!f) return false;
    bool ok = fwrite(d,1,n,f)==n;
    fclose(f); return ok;
}

// =====================================================================
// Section-level processing
// =====================================================================

struct SectionVisitor {
    virtual void onPE32(const uint8_t* data, uint32_t size, const EFI_GUID& fileGuid, int seq) = 0;
    virtual void onTE  (const uint8_t* data, uint32_t size, const EFI_GUID& fileGuid, int seq) = 0;
    virtual void onUI  (const std::string& name, const EFI_GUID& fileGuid) = 0;
    virtual void onRaw (const uint8_t* data, uint32_t size, const EFI_GUID& fileGuid) = 0;
    virtual ~SectionVisitor() {}
};

static void walkSections(const uint8_t* ffsBase, uint32_t ffsTotalSize,
                          const EFI_GUID& fileGuid, SectionVisitor& vis) {
    uint32_t offset = (uint32_t)sizeof(EFI_FFS_FILE_HEADER);
    int seq = 0;

    while (offset + sizeof(EFI_COMMON_SECTION_HEADER) <= ffsTotalSize) {
        const auto* sh = reinterpret_cast<const EFI_COMMON_SECTION_HEADER*>(ffsBase+offset);
        bool ext = (sh->Size[0]==0xFF && sh->Size[1]==0xFF && sh->Size[2]==0xFF);
        uint32_t secSize, payOff;

        if (ext) {
            if (offset + sizeof(EFI_COMMON_SECTION_HEADER2) > ffsTotalSize) break;
            const auto* sh2 = reinterpret_cast<const EFI_COMMON_SECTION_HEADER2*>(ffsBase+offset);
            secSize = sh2->ExtendedSize;
            payOff  = offset + (uint32_t)sizeof(EFI_COMMON_SECTION_HEADER2);
        } else {
            secSize = dec24(sh->Size);
            payOff  = offset + (uint32_t)sizeof(EFI_COMMON_SECTION_HEADER);
        }

        uint32_t minHdr = ext ? (uint32_t)sizeof(EFI_COMMON_SECTION_HEADER2)
                               : (uint32_t)sizeof(EFI_COMMON_SECTION_HEADER);
        if (secSize < minHdr || offset+secSize > ffsTotalSize) break;
        uint32_t payLen = secSize - (payOff - offset);

        switch (sh->Type) {
            case 0x10: // PE32
                vis.onPE32(ffsBase+payOff, payLen, fileGuid, seq++); break;
            case 0x12: // TE
                vis.onTE(ffsBase+payOff, payLen, fileGuid, seq++); break;
            case 0x15: { // USER_INTERFACE
                std::string n = utf16le(ffsBase+payOff, payLen);
                vis.onUI(n, fileGuid); break;
            }
            case 0x19: // RAW
                vis.onRaw(ffsBase+payOff, payLen, fileGuid); break;
            default: break;
        }

        uint32_t next = ALIGN_UP(offset+secSize, 4u);
        if (next <= offset) break;
        offset = next;
    }
}

// =====================================================================
// FFS walker with visitor pattern
// =====================================================================

struct FileVisitor {
    virtual void onFile(const uint8_t* fileBase, uint32_t fileSize,
                        const EFI_GUID& guid, uint8_t type, uint64_t fvRelOff) = 0;
    virtual ~FileVisitor() {}
};

static void walkFV(const uint8_t* fvBase, uint64_t fvLen, uint32_t hdrLen,
                   FileVisitor& vis) {
    uint64_t offset = hdrLen;
    while (offset + sizeof(EFI_FFS_FILE_HEADER) <= fvLen) {
        const auto* fh = reinterpret_cast<const EFI_FFS_FILE_HEADER*>(fvBase+offset);
        if (isAllFF(fh->Name.Data, 16)) break;
        if (isAllZero(fh->Name.Data, 16)) { offset += 8; continue; }

        uint32_t fsize = dec24(fh->Size);
        if (fsize < sizeof(EFI_FFS_FILE_HEADER)) break;
        if (offset + fsize > fvLen) break;

        vis.onFile(fvBase+(size_t)offset, fsize, fh->Name, fh->Type, offset);

        uint64_t next = ALIGN_UP(offset+(uint64_t)fsize, 8u);
        if (next <= offset) break;
        offset = next;
    }
}

// Find all FV headers in the image, return their byte offsets
static std::vector<size_t> findAllFVHeaders(const uint8_t* buf, size_t bufLen) {
    std::vector<size_t> offsets;
    for (size_t i=0; i+44 <= bufLen; i++) {
        uint32_t sig; memcpy(&sig, buf+i, 4);
        if (sig == FVH_SIGNATURE) {
            // sig is at offset 40 inside the FV header
            if (i >= 40) {
                size_t hdrStart = i-40;
                offsets.push_back(hdrStart);
                // Skip ahead to avoid overlapping hits within same FV
                const auto* fvHdr = reinterpret_cast<const EFI_FIRMWARE_VOLUME_HEADER*>(buf+hdrStart);
                if (fvHdr->FvLength > 0x100 && hdrStart+fvHdr->FvLength <= bufLen)
                    i = hdrStart + (size_t)fvHdr->FvLength - 4;
            }
        }
    }
    return offsets;
}

// =====================================================================
// Command: info
// =====================================================================

static void cmdInfo(const std::vector<uint8_t>& buf) {
    auto fvOffsets = findAllFVHeaders(buf.data(), buf.size());
    if (fvOffsets.empty()) {
        printf("No EFI Firmware Volume headers found.\n");
        return;
    }
    printf("Found %zu Firmware Volume(s)\n\n", fvOffsets.size());

    int idx=0;
    for (size_t fvOff : fvOffsets) {
        const auto* hdr = reinterpret_cast<const EFI_FIRMWARE_VOLUME_HEADER*>(buf.data()+fvOff);
        printf("=== FV #%d at file offset 0x%zX ===\n", idx++, fvOff);
        printf("  FvLength      : 0x%016llX\n", (unsigned long long)hdr->FvLength);
        printf("  Revision      : %u\n", hdr->Revision);
        printf("  Attributes    : 0x%08X\n", hdr->Attributes);
        printf("  HeaderLength  : %u bytes\n", hdr->HeaderLength);
        printf("  Checksum      : 0x%04X\n", hdr->Checksum);
        printf("  GUID          : %s\n", guidStr(hdr->FileSystemGuid).c_str());

        // Block map
        const EFI_FV_BLOCK_MAP_ENTRY* e = hdr->BlockMap;
        const uint8_t* hdrEnd = (const uint8_t*)hdr + hdr->HeaderLength;
        uint64_t total=0;
        int bi=0;
        while ((const uint8_t*)(e+1) <= hdrEnd && (e->NumBlocks||e->Length)) {
            uint64_t span = (uint64_t)e->NumBlocks * e->Length;
            total += span;
            printf("  BlockMap[%d]   : %u blocks x 0x%X bytes = 0x%llX bytes\n",
                   bi++, e->NumBlocks, e->Length, (unsigned long long)span);
            e++;
        }
        printf("  BlockMap total: 0x%llX  FvLength match: %s\n\n",
               (unsigned long long)total,
               total==hdr->FvLength ? "YES" : "NO");
    }
}

// =====================================================================
// Command: list
// =====================================================================

struct ListVisitor : FileVisitor {
    int count = 0;
    void onFile(const uint8_t* fb, uint32_t fs,
                const EFI_GUID& g, uint8_t t, uint64_t off) override {
        (void)fb;
        printf("  [0x%06llX] %s  %-22s  0x%06X bytes\n",
               (unsigned long long)off, guidStr(g).c_str(), fileTypeName(t), fs);
        count++;
    }
};

static void cmdList(const std::vector<uint8_t>& buf) {
    auto fvOffsets = findAllFVHeaders(buf.data(), buf.size());
    if (fvOffsets.empty()) { printf("No Firmware Volumes found.\n"); return; }

    int total=0, fvIdx=0;
    for (size_t fvOff : fvOffsets) {
        const auto* hdr = reinterpret_cast<const EFI_FIRMWARE_VOLUME_HEADER*>(buf.data()+fvOff);
        uint64_t fvLen = hdr->FvLength;
        if (fvOff+fvLen > buf.size()) fvLen = buf.size()-fvOff;

        printf("\nFV #%d at 0x%zX  (FvLength=0x%llX)\n",
               fvIdx++, fvOff, (unsigned long long)hdr->FvLength);
        printf("%-10s %-47s %-22s %s\n","Offset","GUID","Type","Size");
        printf("%s\n",std::string(90,'-').c_str());

        ListVisitor vis;
        walkFV(buf.data()+fvOff, fvLen, hdr->HeaderLength, vis);
        total += vis.count;
    }
    printf("\nTotal FFS files: %d\n", total);
}

// =====================================================================
// Command: extract
// =====================================================================

struct ExtractVisitor : FileVisitor {
    std::string outdir;
    int extracted = 0;
    std::string lastName;

    struct SEC : SectionVisitor {
        std::string outdir;
        int* extracted;
        std::string* lastName;

        void onPE32(const uint8_t* d, uint32_t sz, const EFI_GUID& g, int seq) override {
            std::string fn = guidStr(g)+"_"+std::to_string(seq)+".efi";
            std::string fp = outdir+"/"+fn;
            if (writeFile(fp, d, sz)) {
                printf("  [PE32] %s  (%u bytes)\n", fn.c_str(), sz);
                (*extracted)++;
            }
        }
        void onTE(const uint8_t* d, uint32_t sz, const EFI_GUID& g, int seq) override {
            std::string fn = guidStr(g)+"_"+std::to_string(seq)+".te";
            std::string fp = outdir+"/"+fn;
            if (writeFile(fp, d, sz)) {
                printf("  [TE  ] %s  (%u bytes)\n", fn.c_str(), sz);
                (*extracted)++;
            }
        }
        void onUI(const std::string& n, const EFI_GUID&) override {
            *lastName = n;
        }
        void onRaw(const uint8_t*, uint32_t, const EFI_GUID&) override {}
    } secVis;

    ExtractVisitor(const std::string& dir) : outdir(dir) {
        secVis.outdir = dir;
        secVis.extracted = &extracted;
        secVis.lastName = &lastName;
    }

    void onFile(const uint8_t* fb, uint32_t fs,
                const EFI_GUID& g, uint8_t type, uint64_t off) override {
        lastName.clear();
        walkSections(fb, fs, g, secVis);
        if (!lastName.empty())
            printf("    (name: %s)\n", lastName.c_str());
        (void)type; (void)off;
    }
};

static void cmdExtract(const std::vector<uint8_t>& buf, const char* outdir) {
    MKDIR(outdir);
    auto fvOffsets = findAllFVHeaders(buf.data(), buf.size());
    if (fvOffsets.empty()) { printf("No Firmware Volumes found.\n"); return; }

    int total=0, fvIdx=0;
    for (size_t fvOff : fvOffsets) {
        const auto* hdr = reinterpret_cast<const EFI_FIRMWARE_VOLUME_HEADER*>(buf.data()+fvOff);
        uint64_t fvLen = hdr->FvLength;
        if (fvOff+fvLen > buf.size()) fvLen = buf.size()-fvOff;

        printf("FV #%d at 0x%zX\n", fvIdx++, fvOff);
        ExtractVisitor vis(std::string(outdir));
        walkFV(buf.data()+fvOff, fvLen, hdr->HeaderLength, vis);
        total += vis.extracted;
    }
    printf("\nExtracted %d image(s) to: %s\n", total, outdir);
}

// =====================================================================
// Command: scan
// =====================================================================

struct ScanFinding {
    std::string fvOff;
    std::string fileGuid;
    std::string type;
    std::string detail;
};

static std::vector<ScanFinding> gFindings;

static void addFinding(const std::string& fv, const EFI_GUID& g,
                       const std::string& type, const std::string& detail) {
    gFindings.push_back({fv, guidStr(g), type, detail});
}

struct ScanVisitor : FileVisitor {
    std::string fvTag;
    std::string lastName;

    struct SEC : SectionVisitor {
        std::string* fvTag;
        std::string* lastName;
        EFI_GUID fileGuid;

        void onPE32(const uint8_t* d, uint32_t sz, const EFI_GUID& g, int) override {
            // Check W+X sections
            std::string detail;
            if (peHasWXSection(d, sz, detail))
                addFinding(*fvTag, g, "WRITE+EXEC SECTION",
                           "PE32 section '"+detail+"' has W+X permissions");

            // Check for suspicious import names (shell access in DXE driver)
            // Basic entropy on the entire PE image
            double ent = shannonEntropy(d, sz);
            if (ent > 7.5)
                addFinding(*fvTag, g, "HIGH ENTROPY PE32",
                           "Shannon entropy="+std::to_string(ent).substr(0,5)
                           +" (possible encrypted payload or packer)");
        }
        void onTE(const uint8_t* d, uint32_t sz, const EFI_GUID& g, int) override {
            double ent = shannonEntropy(d, sz);
            if (ent > 7.5)
                addFinding(*fvTag, g, "HIGH ENTROPY TE",
                           "Shannon entropy="+std::to_string(ent).substr(0,5));
        }
        void onUI(const std::string& n, const EFI_GUID& g) override {
            *lastName = n;
            if (isSuspiciousName(n))
                addFinding(*fvTag, g, "SUSPICIOUS MODULE NAME",
                           "UI name='"+n+"' matches known backdoor pattern");
        }
        void onRaw(const uint8_t* d, uint32_t sz, const EFI_GUID& g) override {
            // Check entropy
            double ent = shannonEntropy(d, sz);
            if (ent > 7.0 && sz > 64)
                addFinding(*fvTag, g, "HIGH ENTROPY RAW",
                           "Shannon entropy="+std::to_string(ent).substr(0,5)
                           +" size="+std::to_string(sz));

            // Scan for IPv4 addresses
            auto ips = findIPv4(d, sz);
            for (auto& ip : ips)
                addFinding(*fvTag, g, "HARDCODED IPv4",
                           "Found IP address: "+ip);
        }
    } secVis;

    ScanVisitor() {
        secVis.fvTag    = &fvTag;
        secVis.lastName = &lastName;
    }

    void onFile(const uint8_t* fb, uint32_t fs,
                const EFI_GUID& g, uint8_t type, uint64_t) override {
        // SMM files get flagged automatically as high-privilege
        if (type == 0x0A) {
            addFinding(fvTag, g, "SMM MODULE",
                       "File type=0x0A (SMM). SMM runs at ring -2. Verify this is expected.");
        }
        secVis.fileGuid = g;
        lastName.clear();
        walkSections(fb, fs, g, secVis);
    }
};

static void cmdScan(const std::vector<uint8_t>& buf) {
    auto fvOffsets = findAllFVHeaders(buf.data(), buf.size());
    if (fvOffsets.empty()) { printf("No Firmware Volumes found.\n"); return; }

    int fvIdx=0;
    for (size_t fvOff : fvOffsets) {
        const auto* hdr = reinterpret_cast<const EFI_FIRMWARE_VOLUME_HEADER*>(buf.data()+fvOff);
        uint64_t fvLen = hdr->FvLength;
        if (fvOff+fvLen > buf.size()) fvLen = buf.size()-fvOff;

        ScanVisitor vis;
        vis.fvTag = "FV#"+std::to_string(fvIdx)+"@0x"+[&]{
            char b[32]; snprintf(b,sizeof(b),"%zX",fvOff); return std::string(b); }();
        walkFV(buf.data()+fvOff, fvLen, hdr->HeaderLength, vis);
        fvIdx++;
    }

    printf("=== Security Scan Results: %zu finding(s) ===\n\n", gFindings.size());
    if (gFindings.empty()) {
        printf("  No suspicious patterns found.\n");
        return;
    }

    int n=1;
    for (auto& f : gFindings) {
        printf("[%d] TYPE    : %s\n", n++, f.type.c_str());
        printf("    FV      : %s\n", f.fvOff.c_str());
        printf("    GUID    : %s\n", f.fileGuid.c_str());
        printf("    DETAIL  : %s\n\n", f.detail.c_str());
    }

    // Summary by type
    printf("--- Summary ---\n");
    struct { const char* cat; int count; } cats[] = {
        {"WRITE+EXEC SECTION",0},{"HIGH ENTROPY",0},{"HARDCODED IPv4",0},
        {"SUSPICIOUS MODULE NAME",0},{"SMM MODULE",0},{nullptr,0}
    };
    for (auto& f : gFindings)
        for (int i=0; cats[i].cat; i++)
            if (f.type.find(cats[i].cat) != std::string::npos) cats[i].count++;

    for (int i=0; cats[i].cat; i++)
        if (cats[i].count)
            printf("  %-30s : %d\n", cats[i].cat, cats[i].count);
}

// =====================================================================
// Entry point
// =====================================================================

static void usage(const char* prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s list    <fw.bin>          -- list all FFS files\n"
        "  %s extract <fw.bin> <outdir> -- extract PE32/TE sections\n"
        "  %s info    <fw.bin>          -- print FV headers and block maps\n"
        "  %s scan    <fw.bin>          -- security scan\n",
        prog,prog,prog,prog);
}

int main(int argc, char* argv[]) {
    if (argc < 3) { usage(argv[0]); return 1; }

    const char* cmd = argv[1];
    const char* fw  = argv[2];

    FILE* f = fopen(fw, "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f); rewind(f);
    if (sz <= 0) { fprintf(stderr,"Empty file\n"); fclose(f); return 1; }

    std::vector<uint8_t> buf((size_t)sz);
    if (fread(buf.data(),1,(size_t)sz,f) != (size_t)sz) {
        fprintf(stderr,"Read error\n"); fclose(f); return 1;
    }
    fclose(f);

    printf("File: %s  (%ld bytes)\n\n", fw, sz);

    if      (strcmp(cmd,"info")==0)    cmdInfo(buf);
    else if (strcmp(cmd,"list")==0)    cmdList(buf);
    else if (strcmp(cmd,"extract")==0) {
        if (argc < 4) { fprintf(stderr,"extract requires <outdir>\n"); return 1; }
        cmdExtract(buf, argv[3]);
    }
    else if (strcmp(cmd,"scan")==0)    cmdScan(buf);
    else {
        fprintf(stderr,"Unknown command: %s\n", cmd);
        usage(argv[0]); return 1;
    }
    return 0;
}
