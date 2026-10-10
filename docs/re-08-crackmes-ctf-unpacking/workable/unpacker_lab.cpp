// unpacker_lab.cpp — packer/unpacker demonstration
// Compile: g++ -std=c++17 -o unpacker_lab.exe unpacker_lab.cpp
// Usage: unpacker_lab.exe pack <in_exe> <out_exe> | unpack <packed_exe> | run-packed | detect <file>

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <fstream>
#include <cmath>

static const uint8_t PACK_KEY = 0xA5;
static const char*   PACK_SIG = "PKLAB001";

// ─── Shannon entropy ─────────────────────────────────────────────────────────

static double shannon(const uint8_t* d, size_t n) {
    if(!n) return 0;
    uint64_t f[256]{}; for(size_t i=0;i<n;++i) ++f[d[i]];
    double h=0; for(int i=0;i<256;++i){ if(!f[i])continue; double p=(double)f[i]/n; h-=p*log2(p); }
    return h;
}

// ─── pack: XOR-encode a binary ───────────────────────────────────────────────

static void cmd_pack(const char* in, const char* out) {
    std::ifstream fi(in, std::ios::binary);
    if (!fi) { fprintf(stderr,"Cannot open %s\n",in); return; }
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(fi)),{});
    fi.close();

    std::vector<uint8_t> encoded(data.size());
    for(size_t i=0;i<data.size();++i) encoded[i]=data[i]^PACK_KEY;

    std::ofstream fo(out, std::ios::binary);
    fo.write(PACK_SIG, 8);
    uint32_t orig_sz = (uint32_t)data.size();
    fo.write((const char*)&orig_sz, 4);
    fo.write((const char*)encoded.data(), encoded.size());
    printf("[+] Packed: %s (%zu) -> %s (%zu)\n", in, data.size(), out, encoded.size()+12);
    printf("    Entropy before: %.3f  after: %.3f\n",
           shannon(data.data(),data.size()),
           shannon(encoded.data(),encoded.size()));
}

// ─── unpack: XOR-decode back ─────────────────────────────────────────────────

static void cmd_unpack(const char* packed) {
    std::ifstream fi(packed, std::ios::binary);
    if (!fi) { fprintf(stderr,"Cannot open %s\n",packed); return; }
    std::vector<uint8_t> raw((std::istreambuf_iterator<char>(fi)),{});
    fi.close();

    if (raw.size() < 12 || memcmp(raw.data(), PACK_SIG, 8) != 0) {
        fprintf(stderr,"Not a PKLAB packed file\n"); return;
    }
    uint32_t orig_sz; memcpy(&orig_sz, raw.data()+8, 4);
    size_t payload_sz = raw.size()-12;
    if (payload_sz < orig_sz) { fprintf(stderr,"Truncated payload\n"); return; }

    std::vector<uint8_t> out(orig_sz);
    for(uint32_t i=0;i<orig_sz;++i) out[i]=raw[12+i]^PACK_KEY;

    std::string outname = std::string(packed) + ".unpacked";
    std::ofstream fo(outname, std::ios::binary);
    fo.write((const char*)out.data(), out.size());
    printf("[+] Unpacked %u bytes -> %s\n", orig_sz, outname.c_str());
    if (out.size()>=2 && out[0]=='M' && out[1]=='Z') printf("    [MZ header present — valid PE!]\n");
}

// ─── run-packed: self-contained demo of runtime decode ───────────────────────

static void cmd_run_packed() {
    printf("[*] Runtime decode demo\n");
    // A tiny 'payload' (just print a message via puts)
    // In a real packer: this would be actual shellcode/PE
    const char raw[] = "\xf3\xf0\xf2\xfe\xc2\xa5\xc7\xe4\xe0\xfe\xc9\xa5\xf0\xe0\xf7\xf0\xed\xf0\xa5\xfe\xe4\xf7\xf7\xe5\xe4\xe4\xa5\xed\xe0\xf6\xfe\xc7\xef\xa5\xf0\xe4\xa5\xe7\xe3\xe5\xf0\xa5\xf0\xe4\xf2\xf0\xfe\xe7\xed\xf0\xa5\xe0\xf6\xf7\xf0";
    size_t n = sizeof(raw)-1;
    std::vector<char> decoded(n+1, 0);
    for(size_t i=0;i<n;++i) decoded[i]=(char)((uint8_t)raw[i]^PACK_KEY);
    printf("[decoded] %s\n", decoded.data());
}

// ─── detect: identify packer/obfuscation indicators ──────────────────────────

static void cmd_detect(const char* path) {
    std::ifstream fi(path, std::ios::binary);
    if (!fi) { fprintf(stderr,"Cannot open %s\n",path); return; }
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(fi)),{});
    fi.close();

    printf("=== Packer Detection: %s ===\n\n", path);
    printf("  File size:     %zu bytes\n", data.size());
    printf("  Whole entropy: %.3f%s\n", shannon(data.data(),data.size()),
           shannon(data.data(),data.size())>7.0?" <-- HIGH (likely packed)":"");

    // Check our own PKLAB signature
    if (data.size()>=8 && memcmp(data.data(),PACK_SIG,8)==0) {
        printf("  PKLAB packed:  YES\n");
    }

    // PE check
    bool is_pe = data.size()>0x40 && data[0]=='M' && data[1]=='Z';
    if (is_pe) {
        auto* dos = (IMAGE_DOS_HEADER*)data.data();
        auto* nth = (IMAGE_NT_HEADERS*)(data.data()+dos->e_lfanew);
        auto* sec = IMAGE_FIRST_SECTION(nth);
        WORD nsec = nth->FileHeader.NumberOfSections;
        printf("  PE sections:\n");
        int ep_in_last = 0;
        DWORD ep = nth->OptionalHeader.AddressOfEntryPoint;
        for(WORD i=0;i<nsec;++i) {
            double e=0; if(sec[i].SizeOfRawData)
                e=shannon(data.data()+sec[i].PointerToRawData,sec[i].SizeOfRawData);
            bool ep_here = ep>=sec[i].VirtualAddress && ep<sec[i].VirtualAddress+sec[i].Misc.VirtualSize;
            printf("    %-8.8s  e=%.3f%s%s\n",(char*)sec[i].Name,e,
                   e>7.0?" [HIGH]":"", ep_here?" [EP]":"");
            if(ep_here && i==nsec-1) ep_in_last=1;
        }
        if(ep_in_last) printf("  [!] Entry point in LAST section — packer signature!\n");
        if(nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size < 20)
            printf("  [!] Very small import table — possible packer\n");
    }
}

int main(int argc, char* argv[]) {
    if(argc<2){
        printf("Usage:\n"
               "  unpacker_lab.exe pack        <in_exe> <out_exe>\n"
               "  unpacker_lab.exe unpack      <packed_exe>\n"
               "  unpacker_lab.exe run-packed\n"
               "  unpacker_lab.exe detect      <file>\n");
        return 1;
    }
    std::string cmd(argv[1]);
    if      (cmd=="pack"&&argc>=4)       cmd_pack(argv[2],argv[3]);
    else if (cmd=="unpack"&&argc>=3)     cmd_unpack(argv[2]);
    else if (cmd=="run-packed")          cmd_run_packed();
    else if (cmd=="detect"&&argc>=3)     cmd_detect(argv[2]);
    else { fprintf(stderr,"Unknown command\n"); return 1; }
    return 0;
}
