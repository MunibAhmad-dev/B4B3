// pe_deep_parser.cpp — deep PE format parser
// Compile: g++ -std=c++17 -o pe_deep_parser.exe pe_deep_parser.cpp
// Usage: pe_deep_parser.exe headers <f> | imports <f> | exports <f> | sections <f>
//                           resources <f> | tls <f> | relocs <f> | all <f>

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <cmath>

static const char* DIR_NAMES[] = {
    "Export","Import","Resource","Exception","Security","BaseReloc",
    "Debug","Architecture","GlobalPtr","TLS","LoadConfig","BoundImport",
    "IAT","DelayImport","COM","Reserved"
};

struct FM {
    const uint8_t* base=nullptr; size_t size=0;
    HANDLE hf=INVALID_HANDLE_VALUE, hm=nullptr;
    bool open(const char* p) {
        hf=CreateFileA(p,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);
        if(hf==INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER sz{}; GetFileSizeEx(hf,&sz); size=(size_t)sz.QuadPart;
        hm=CreateFileMappingA(hf,nullptr,PAGE_READONLY,0,0,nullptr); if(!hm) return false;
        base=(const uint8_t*)MapViewOfFile(hm,FILE_MAP_READ,0,0,0); return base!=nullptr;
    }
    ~FM(){ if(base)UnmapViewOfFile(base); if(hm)CloseHandle(hm); if(hf!=INVALID_HANDLE_VALUE)CloseHandle(hf); }
    bool is_pe() const { return size>0x40 && *(uint16_t*)base==0x5A4D; }
};

static const uint8_t* rva2ptr(const uint8_t* base, DWORD rva) {
    auto* nth = (IMAGE_NT_HEADERS*)(base + ((IMAGE_DOS_HEADER*)base)->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nth);
    for (WORD i=0; i<nth->FileHeader.NumberOfSections; ++i)
        if (rva>=sec[i].VirtualAddress && rva<sec[i].VirtualAddress+sec[i].SizeOfRawData)
            return base+sec[i].PointerToRawData+(rva-sec[i].VirtualAddress);
    return nullptr;
}

static double shannon(const uint8_t* d, size_t n) {
    uint64_t f[256]{}; for(size_t i=0;i<n;++i) ++f[d[i]];
    double h=0; for(int i=0;i<256;++i){ if(!f[i])continue; double p=(double)f[i]/n; h-=p*log2(p); }
    return h;
}

static void cmd_headers(const FM& fm) {
    auto* dos = (IMAGE_DOS_HEADER*)fm.base;
    auto* nth = (IMAGE_NT_HEADERS*)(fm.base+dos->e_lfanew);
    auto& fh = nth->FileHeader; auto& oh = nth->OptionalHeader;
    printf("Machine:    0x%04X  %s\n", fh.Machine, fh.Machine==0x8664?"(x64)":fh.Machine==0x14C?"(x86)":"");
    printf("Sections:   %u\nTimestamp:  0x%08X\n", fh.NumberOfSections, fh.TimeDateStamp);
    printf("ImageBase:  0x%llX\nEntryPoint: 0x%08X\nMagic:      0x%04X (%s)\n",
           (unsigned long long)oh.ImageBase, oh.AddressOfEntryPoint, oh.Magic,
           oh.Magic==0x20B?"PE32+":"PE32");
    printf("\nData Directories:\n");
    for(int i=0;i<16;++i) { auto& d=oh.DataDirectory[i]; if(d.VirtualAddress)
        printf("  [%2d] %-14s RVA=0x%08X Size=0x%X\n",i,DIR_NAMES[i],d.VirtualAddress,d.Size); }
}

static void cmd_sections(const FM& fm) {
    auto* dos=(IMAGE_DOS_HEADER*)fm.base;
    auto* nth=(IMAGE_NT_HEADERS*)(fm.base+dos->e_lfanew);
    auto* sec=IMAGE_FIRST_SECTION(nth);
    printf("%-8s  %-10s  %-10s  %-10s  Entropy\n","Name","VA","RawSize","Chars");
    printf("%s\n",std::string(60,'-').c_str());
    for(WORD i=0;i<nth->FileHeader.NumberOfSections;++i) {
        double e=0; if(sec[i].SizeOfRawData) e=shannon(fm.base+sec[i].PointerToRawData,sec[i].SizeOfRawData);
        printf("%-8.8s  0x%08X  0x%08X  0x%08X  %.3f%s\n",
               (char*)sec[i].Name,sec[i].VirtualAddress,sec[i].SizeOfRawData,
               sec[i].Characteristics,e,e>7.0?"  <--HIGH":"");
    }
}

static void cmd_imports(const FM& fm) {
    auto* dos=(IMAGE_DOS_HEADER*)fm.base;
    auto* nth=(IMAGE_NT_HEADERS*)(fm.base+dos->e_lfanew);
    auto& dir=nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if(!dir.VirtualAddress){printf("No imports\n");return;}
    auto* idt=(IMAGE_IMPORT_DESCRIPTOR*)rva2ptr(fm.base,dir.VirtualAddress);
    if(!idt){printf("Cannot resolve import RVA\n");return;}
    for(;idt->Name;++idt) {
        const char* dll=(const char*)rva2ptr(fm.base,idt->Name);
        printf("  %s\n",dll?dll:"?");
        DWORD* thunk=(DWORD*)(idt->OriginalFirstThunk?rva2ptr(fm.base,idt->OriginalFirstThunk):rva2ptr(fm.base,idt->FirstThunk));
        if(!thunk) continue;
        bool b64=nth->FileHeader.Machine==0x8664;
        while(*thunk) {
            DWORD snap=b64?0:IMAGE_ORDINAL_FLAG32;
            if(!(*thunk&snap)) {
                auto* ibn=(IMAGE_IMPORT_BY_NAME*)rva2ptr(fm.base,*thunk&0x7FFFFFFF);
                if(ibn) printf("    %s\n",(char*)ibn->Name);
            } else printf("    ord %u\n",*thunk&0xFFFF);
            ++thunk;
        }
    }
}

static void cmd_exports(const FM& fm) {
    auto* dos=(IMAGE_DOS_HEADER*)fm.base;
    auto* nth=(IMAGE_NT_HEADERS*)(fm.base+dos->e_lfanew);
    auto& dir=nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if(!dir.VirtualAddress){printf("No exports\n");return;}
    auto* exp=(IMAGE_EXPORT_DIRECTORY*)(fm.base+dir.VirtualAddress);
    auto* names=(DWORD*)(fm.base+exp->AddressOfNames);
    auto* funcs=(DWORD*)(fm.base+exp->AddressOfFunctions);
    auto* ords=(WORD*)(fm.base+exp->AddressOfNameOrdinals);
    const char* dllname=(const char*)(fm.base+exp->Name);
    printf("DLL: %s  Base=%u  Named=%u  Total=%u\n",dllname,exp->Base,exp->NumberOfNames,exp->NumberOfFunctions);
    for(DWORD i=0;i<exp->NumberOfNames;++i)
        printf("  [%4u] 0x%08X  %s\n",exp->Base+ords[i],funcs[ords[i]],(const char*)(fm.base+names[i]));
}

static void cmd_tls(const FM& fm) {
    auto* dos=(IMAGE_DOS_HEADER*)fm.base;
    auto* nth=(IMAGE_NT_HEADERS*)(fm.base+dos->e_lfanew);
    auto& dir=nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if(!dir.VirtualAddress){printf("No TLS directory\n");return;}
    printf("TLS directory RVA: 0x%08X  Size: 0x%X\n",dir.VirtualAddress,dir.Size);
    auto* tls=(IMAGE_TLS_DIRECTORY*)rva2ptr(fm.base,dir.VirtualAddress);
    if(tls) {
        printf("  AddressOfCallBacks: 0x%llX  (check for anti-debug callbacks)\n",
               (unsigned long long)tls->AddressOfCallBacks);
        printf("  SizeOfZeroFill:     %u\n",tls->SizeOfZeroFill);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: pe_deep_parser.exe headers|sections|imports|exports|tls|all <file>\n");
        return 1;
    }
    FM fm; if(!fm.open(argv[2])||!fm.is_pe()){fprintf(stderr,"Not a PE or cannot open\n");return 1;}
    std::string cmd(argv[1]);
    bool all=(cmd=="all");
    if(all||cmd=="headers")  { printf("=== Headers ===\n");  cmd_headers(fm);  printf("\n"); }
    if(all||cmd=="sections") { printf("=== Sections ===\n"); cmd_sections(fm); printf("\n"); }
    if(all||cmd=="imports")  { printf("=== Imports ===\n");  cmd_imports(fm);  printf("\n"); }
    if(all||cmd=="exports")  { printf("=== Exports ===\n");  cmd_exports(fm);  printf("\n"); }
    if(all||cmd=="tls")      { printf("=== TLS ===\n");      cmd_tls(fm);      }
    return 0;
}
