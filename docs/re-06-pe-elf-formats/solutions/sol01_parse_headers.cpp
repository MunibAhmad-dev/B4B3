// sol01_parse_headers.cpp — solution
// Compile: g++ -std=c++17 -o sol01.exe sol01_parse_headers.cpp
// Usage: sol01.exe <file>
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdio.h>
#include <string>

static const char* DIR_NAMES[] = {
    "Export","Import","Resource","Exception","Security","BaseReloc",
    "Debug","Architecture","GlobalPtr","TLS","LoadConfig","BoundImport",
    "IAT","DelayImport","COM","Reserved"
};

int main(int argc, char* argv[]) {
    if (argc < 2) { printf("Usage: sol01.exe <file>\n"); return 1; }
    HANDLE hf = CreateFileA(argv[1],GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);
    if (hf==INVALID_HANDLE_VALUE) { fprintf(stderr,"Cannot open\n"); return 1; }
    HANDLE hm = CreateFileMappingA(hf,nullptr,PAGE_READONLY,0,0,nullptr);
    const uint8_t* base = (const uint8_t*)MapViewOfFile(hm,FILE_MAP_READ,0,0,0);

    auto* dos = (IMAGE_DOS_HEADER*)base;
    auto* nth = (IMAGE_NT_HEADERS*)(base+dos->e_lfanew);
    auto& fh  = nth->FileHeader;
    auto& oh  = nth->OptionalHeader;
    bool b64  = oh.Magic == 0x20B;

    printf("=== %s ===\n\n", argv[1]);
    printf("Machine:          0x%04X  (%s)\n", fh.Machine,
           fh.Machine==0x8664?"x64":fh.Machine==0x14C?"x86":"other");
    printf("Sections:         %u\n", fh.NumberOfSections);
    printf("TimeDateStamp:    0x%08X\n", fh.TimeDateStamp);
    printf("Characteristics:  0x%04X\n", fh.Characteristics);
    printf("Magic:            0x%04X (%s)\n", oh.Magic, b64?"PE32+":"PE32");
    printf("ImageBase:        0x%llX\n", (unsigned long long)oh.ImageBase);
    printf("EntryPoint:       0x%08X\n", oh.AddressOfEntryPoint);
    printf("SectionAlign:     0x%X\n",  oh.SectionAlignment);
    printf("FileAlign:        0x%X\n",  oh.FileAlignment);

    printf("\nData Directories:\n");
    for (int i = 0; i < 16; ++i) {
        auto& d = oh.DataDirectory[i];
        if (d.VirtualAddress)
            printf("  [%2d] %-14s  RVA=0x%08X  Size=0x%X\n", i, DIR_NAMES[i], d.VirtualAddress, d.Size);
    }

    printf("\nSections:\n");
    auto* sec = IMAGE_FIRST_SECTION(nth);
    for (WORD i = 0; i < fh.NumberOfSections; ++i) {
        printf("  %-8.8s  VA=0x%08X  RawSz=0x%08X  Chars=0x%08X\n",
               (char*)sec[i].Name, sec[i].VirtualAddress,
               sec[i].SizeOfRawData, sec[i].Characteristics);
    }
    UnmapViewOfFile(base); CloseHandle(hm); CloseHandle(hf);
    return 0;
}
