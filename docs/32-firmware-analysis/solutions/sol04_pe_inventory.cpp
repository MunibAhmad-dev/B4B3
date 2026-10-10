// solutions/sol04_pe_inventory.cpp
// Module 32 — Firmware Analysis, Solution 4
//
// Complete PE inventory: scans all .efi files in a directory,
// prints machine type, subsystem, entry point, sections, and imports.
//
// Compile: g++ -std=c++17 -Wall -o sol04.exe sol04_pe_inventory.cpp
// Run:     sol04.exe <directory>

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <windows.h>

// =====================================================================
// PE data structures
// =====================================================================

#define IMAGE_DOS_SIGNATURE   0x5A4D
#define IMAGE_NT_SIGNATURE    0x00004550

#define IMAGE_FILE_MACHINE_I386   0x014C
#define IMAGE_FILE_MACHINE_AMD64  0x8664
#define IMAGE_FILE_MACHINE_ARM64  0xAA64
#define IMAGE_FILE_MACHINE_EBC    0x0EBC

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10B
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20B

#define IMAGE_SUBSYSTEM_EFI_APPLICATION         10
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER 11
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER      12
#define IMAGE_SUBSYSTEM_EFI_ROM                 13

#define IMAGE_DIRECTORY_ENTRY_IMPORT 1

#pragma pack(1)

struct MY_IMAGE_DOS_HEADER {
    uint16_t e_magic;
    uint8_t  _pad[58];
    uint32_t e_lfanew;
};

struct MY_IMAGE_FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct MY_IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
};

// PE32 optional header (32-bit)
struct MY_IMAGE_OPTIONAL_HEADER32 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    MY_IMAGE_DATA_DIRECTORY DataDirectory[16];
};

// PE32+ optional header (64-bit)
struct MY_IMAGE_OPTIONAL_HEADER64 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    MY_IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct MY_IMAGE_NT_HEADERS32 {
    uint32_t                    Signature;
    MY_IMAGE_FILE_HEADER        FileHeader;
    MY_IMAGE_OPTIONAL_HEADER32  OptionalHeader;
};

struct MY_IMAGE_NT_HEADERS64 {
    uint32_t                    Signature;
    MY_IMAGE_FILE_HEADER        FileHeader;
    MY_IMAGE_OPTIONAL_HEADER64  OptionalHeader;
};

struct MY_IMAGE_SECTION_HEADER {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

struct MY_IMAGE_IMPORT_DESCRIPTOR {
    uint32_t OriginalFirstThunk;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;            // RVA of DLL name string
    uint32_t FirstThunk;
};

struct MY_IMAGE_IMPORT_BY_NAME {
    uint16_t Hint;
    char     Name[1];
};

#pragma pack()

#define SEC_CHAR_MEM_EXECUTE 0x20000000
#define SEC_CHAR_MEM_WRITE   0x80000000

// =====================================================================

static const char* machineName(uint16_t m) {
    switch (m) {
        case IMAGE_FILE_MACHINE_I386:  return "I386 (IA-32)";
        case IMAGE_FILE_MACHINE_AMD64: return "AMD64 (x86-64)";
        case IMAGE_FILE_MACHINE_ARM64: return "AArch64 (ARM64)";
        case IMAGE_FILE_MACHINE_EBC:   return "EFI Byte Code (EBC)";
        default: {
            static char buf[32];
            snprintf(buf, sizeof(buf), "Unknown(0x%04X)", m);
            return buf;
        }
    }
}

static const char* subsystemName(uint16_t s) {
    switch (s) {
        case IMAGE_SUBSYSTEM_EFI_APPLICATION:         return "EFI_APPLICATION";
        case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: return "EFI_BOOT_SERVICE_DRIVER";
        case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:      return "EFI_RUNTIME_DRIVER";
        case IMAGE_SUBSYSTEM_EFI_ROM:                 return "EFI_ROM";
        default: {
            static char buf[32];
            snprintf(buf, sizeof(buf), "Other(%u)", s);
            return buf;
        }
    }
}

// Convert RVA to a pointer into the mapped file
// Returns nullptr if the RVA falls outside any section or raw data
static const uint8_t* rvaToPtr(const uint8_t* base, uint32_t rva,
                                 const MY_IMAGE_SECTION_HEADER* sections,
                                 uint16_t numSections, size_t fileSize) {
    for (uint16_t i = 0; i < numSections; i++) {
        const auto& s = sections[i];
        if (rva >= s.VirtualAddress && rva < s.VirtualAddress + s.SizeOfRawData) {
            uint32_t fileOff = s.PointerToRawData + (rva - s.VirtualAddress);
            if (fileOff < (uint32_t)fileSize)
                return base + fileOff;
        }
    }
    return nullptr;
}

static void scanPE(const std::string& filePath) {
    printf("%-70s\n", ("  " + filePath.substr(filePath.find_last_of("/\\") + 1)).c_str());

    // Read entire file
    FILE* f = fopen(filePath.c_str(), "rb");
    if (!f) { printf("    ERROR: cannot open\n\n"); return; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f); rewind(f);
    if (sz < 64) { printf("    ERROR: file too small\n\n"); fclose(f); return; }
    std::vector<uint8_t> buf((size_t)sz);
    fread(buf.data(), 1, (size_t)sz, f);
    fclose(f);

    const uint8_t* base = buf.data();
    const auto* dos = reinterpret_cast<const MY_IMAGE_DOS_HEADER*>(base);

    // MZ check
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        // Try TE (Terse Executable): signature 'VZ' = 0x5A56
        uint16_t teSig;
        memcpy(&teSig, base, 2);
        if (teSig == 0x5A56) {
            printf("    Format     : Terse Executable (TE)\n\n");
        } else {
            printf("    ERROR: not a PE or TE image (magic=0x%04X)\n\n",
                   dos->e_magic);
        }
        return;
    }

    if (dos->e_lfanew + sizeof(uint32_t) > (uint32_t)sz) {
        printf("    ERROR: e_lfanew out of range\n\n");
        return;
    }

    uint32_t ntSig;
    memcpy(&ntSig, base + dos->e_lfanew, 4);
    if (ntSig != IMAGE_NT_SIGNATURE) {
        printf("    ERROR: NT signature invalid (0x%08X)\n\n", ntSig);
        return;
    }

    // Determine 32-bit or 64-bit from OptionalHeader.Magic
    uint16_t optMagic;
    size_t optOff = dos->e_lfanew + 4 + sizeof(MY_IMAGE_FILE_HEADER);
    memcpy(&optMagic, base + optOff, 2);

    bool is64 = (optMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    uint16_t machine, numSections, subsystem;
    uint32_t entryPoint;
    MY_IMAGE_DATA_DIRECTORY importDir = {0, 0};

    const MY_IMAGE_SECTION_HEADER* secHdrs = nullptr;

    if (is64) {
        const auto* nth = reinterpret_cast<const MY_IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        machine      = nth->FileHeader.Machine;
        numSections  = nth->FileHeader.NumberOfSections;
        subsystem    = nth->OptionalHeader.Subsystem;
        entryPoint   = nth->OptionalHeader.AddressOfEntryPoint;
        if (nth->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT)
            importDir = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        secHdrs = reinterpret_cast<const MY_IMAGE_SECTION_HEADER*>(
            (const uint8_t*)&nth->OptionalHeader + nth->FileHeader.SizeOfOptionalHeader);
    } else {
        const auto* nth = reinterpret_cast<const MY_IMAGE_NT_HEADERS32*>(base + dos->e_lfanew);
        machine      = nth->FileHeader.Machine;
        numSections  = nth->FileHeader.NumberOfSections;
        subsystem    = nth->OptionalHeader.Subsystem;
        entryPoint   = nth->OptionalHeader.AddressOfEntryPoint;
        if (nth->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT)
            importDir = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        secHdrs = reinterpret_cast<const MY_IMAGE_SECTION_HEADER*>(
            (const uint8_t*)&nth->OptionalHeader + nth->FileHeader.SizeOfOptionalHeader);
    }

    printf("    Format     : %s\n", is64 ? "PE32+ (64-bit)" : "PE32 (32-bit)");
    printf("    Machine    : %s\n", machineName(machine));
    printf("    Subsystem  : %s\n", subsystemName(subsystem));
    printf("    EntryPoint : 0x%08X (RVA)\n", entryPoint);
    printf("    Sections   : %u\n", numSections);

    // Print section details and flag W+X sections
    bool wxFound = false;
    for (uint16_t i = 0; i < numSections && i < 32; i++) {
        const auto& s = secHdrs[i];
        char name[9] = {};
        memcpy(name, s.Name, 8);
        bool w = (s.Characteristics & SEC_CHAR_MEM_WRITE)   != 0;
        bool x = (s.Characteristics & SEC_CHAR_MEM_EXECUTE) != 0;
        if (w && x) {
            printf("    [!WX]  Section %-8s  VA=0x%08X  Size=0x%X  (WRITE+EXECUTE!)\n",
                   name, s.VirtualAddress, s.SizeOfRawData);
            wxFound = true;
        }
    }
    if (!wxFound)
        printf("    Sections   : No WRITE+EXECUTE sections found\n");

    // Import table
    if (importDir.VirtualAddress == 0 || importDir.Size == 0) {
        printf("    Imports    : (none — uses UEFI protocols)\n");
    } else {
        const uint8_t* impPtr = rvaToPtr(base, importDir.VirtualAddress,
                                          secHdrs, numSections, (size_t)sz);
        if (!impPtr) {
            printf("    Imports    : (import table RVA unresolvable)\n");
        } else {
            int dllCount = 0;
            const auto* imp = reinterpret_cast<const MY_IMAGE_IMPORT_DESCRIPTOR*>(impPtr);
            while (imp->Name != 0 && dllCount < 20) {
                const uint8_t* namePtr = rvaToPtr(base, imp->Name,
                                                   secHdrs, numSections, (size_t)sz);
                const char* dllName = namePtr ? (const char*)namePtr : "<unresolvable>";
                printf("    Import DLL : %s\n", dllName);

                // Print first 3 imported functions
                if (imp->OriginalFirstThunk) {
                    const uint8_t* thunkPtr = rvaToPtr(base, imp->OriginalFirstThunk,
                                                        secHdrs, numSections, (size_t)sz);
                    int funcCount = 0;
                    if (thunkPtr) {
                        while (funcCount < 3) {
                            uint64_t thunkVal = 0;
                            if (is64) {
                                if (thunkPtr + 8 > base + sz) break;
                                memcpy(&thunkVal, thunkPtr, 8);
                                thunkPtr += 8;
                            } else {
                                if (thunkPtr + 4 > base + sz) break;
                                uint32_t v32; memcpy(&v32, thunkPtr, 4);
                                thunkVal = v32;
                                thunkPtr += 4;
                            }
                            if (thunkVal == 0) break;

                            bool byOrdinal = is64 ? ((thunkVal >> 63) & 1) : ((thunkVal >> 31) & 1);
                            if (byOrdinal) {
                                printf("      Ordinal  : %llu\n", (unsigned long long)(thunkVal & 0xFFFF));
                            } else {
                                const uint8_t* fptr = rvaToPtr(base, (uint32_t)thunkVal,
                                                                secHdrs, numSections, (size_t)sz);
                                if (fptr) {
                                    const auto* ibn = reinterpret_cast<const MY_IMAGE_IMPORT_BY_NAME*>(fptr);
                                    printf("      Function : %s\n", ibn->Name);
                                }
                            }
                            funcCount++;
                        }
                    }
                }
                imp++;
                dllCount++;
            }
            if (dllCount == 0)
                printf("    Imports    : (empty import table)\n");
        }
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <directory>\n", argv[0]);
        return 1;
    }

    std::string dir = argv[1];
    std::string pattern = dir + "\\*.efi";

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        // Try .te files too
        fprintf(stderr, "No .efi files found in: %s\n", dir.c_str());
        return 1;
    }

    printf("=== EFI PE Inventory: %s ===\n\n", dir.c_str());
    int count = 0;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            scanPE(dir + "\\" + fd.cFileName);
            count++;
        }
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);

    // Also scan .te files
    pattern = dir + "\\*.te";
    hFind = FindFirstFileA(pattern.c_str(), &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                scanPE(dir + "\\" + fd.cFileName);
                count++;
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }

    printf("Total: %d image(s) scanned\n", count);
    return 0;
}
