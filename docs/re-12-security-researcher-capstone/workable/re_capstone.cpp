// re_capstone.cpp — full RE workflow tool (capstone project)
// Compile: g++ -std=c++17 -o re_capstone.exe re_capstone.cpp -lbcrypt -ladvapi32
// Usage: re_capstone.exe triage <f> | static <f> | yara-gen <f> | decode-xor <f> <key_hex>
//        re_capstone.exe report <f> [--out <report.txt>] | ioc-check <f> | full <f>

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <bcrypt.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <cmath>
#include <regex>
#pragma comment(lib,"bcrypt.lib")
#pragma comment(lib,"advapi32.lib")

// ─── helpers ─────────────────────────────────────────────────────────────────

static double shannon(const uint8_t* d,size_t n){
    uint64_t f[256]{}; for(size_t i=0;i<n;++i)++f[d[i]];
    double h=0;for(int i=0;i<256;++i){if(!f[i])continue;double p=(double)f[i]/n;h-=p*log2(p);}
    return h;
}
static std::string hash_hex(const uint8_t* d,size_t n,const wchar_t* id){
    BCRYPT_ALG_HANDLE a=nullptr; BCRYPT_HASH_HANDLE h=nullptr;
    BCryptOpenAlgorithmProvider(&a,id,nullptr,0);
    DWORD ds=0,rs=0; BCryptGetProperty(a,BCRYPT_HASH_LENGTH,(PUCHAR)&ds,sizeof(ds),&rs,0);
    BCryptCreateHash(a,&h,nullptr,0,nullptr,0,0);
    BCryptHashData(h,(PUCHAR)d,(ULONG)n,0);
    std::vector<uint8_t> dig(ds); BCryptFinishHash(h,dig.data(),ds,0);
    BCryptDestroyHash(h); BCryptCloseAlgorithmProvider(a,0);
    std::string s; for(auto b:dig){char buf[3];sprintf(buf,"%02x",b);s+=buf;}
    return s;
}

struct FM {
    const uint8_t* base=nullptr; size_t size=0;
    HANDLE hf=INVALID_HANDLE_VALUE,hm=nullptr;
    bool open(const char* p){
        hf=CreateFileA(p,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);
        if(hf==INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER sz{}; GetFileSizeEx(hf,&sz); size=(size_t)sz.QuadPart;
        hm=CreateFileMappingA(hf,nullptr,PAGE_READONLY,0,0,nullptr); if(!hm) return false;
        base=(const uint8_t*)MapViewOfFile(hm,FILE_MAP_READ,0,0,0); return base!=nullptr;
    }
    ~FM(){if(base)UnmapViewOfFile(base);if(hm)CloseHandle(hm);if(hf!=INVALID_HANDLE_VALUE)CloseHandle(hf);}
    bool is_pe()const{return size>0x40&&*(uint16_t*)base==0x5A4D;}
};

static const char* SUSP_APIS[]={"VirtualAllocEx","WriteProcessMemory","CreateRemoteThread",
    "URLDownloadToFile","WinExec","ShellExecuteA","RegSetValueExA","NtUnmapViewOfSection",
    "GetAsyncKeyState","SetWindowsHookExA","CryptEncrypt","BCryptEncrypt",
    "HttpSendRequest","InternetOpenA","CreateProcessA","OpenProcess",nullptr};
static const char* PACKER_SIGS[]={"UPX0","UPX1","MPRESS1","MPRESS2",".nsp0",nullptr};

// ─── triage ──────────────────────────────────────────────────────────────────

static void cmd_triage(const char* path, FILE* out=stdout){
    FM fm; if(!fm.open(path)){fprintf(out,"Cannot open %s\n",path);return;}
    fprintf(out,"=== TRIAGE: %s ===\n",path);
    fprintf(out,"MD5:    %s\n",hash_hex(fm.base,fm.size,BCRYPT_MD5_ALGORITHM).c_str());
    fprintf(out,"SHA256: %s\n",hash_hex(fm.base,fm.size,BCRYPT_SHA256_ALGORITHM).c_str());
    double e=shannon(fm.base,fm.size);
    fprintf(out,"Size:   %zu  Entropy: %.3f%s\n",fm.size,e,e>7.0?" [PACKED/ENCRYPTED]":"");
    if(!fm.is_pe()){fprintf(out,"Type: not a PE\n");return;}
    auto* dos=(IMAGE_DOS_HEADER*)fm.base;
    auto* nth=(IMAGE_NT_HEADERS*)(fm.base+dos->e_lfanew);
    auto* sec=IMAGE_FIRST_SECTION(nth);
    fprintf(out,"Arch:   %s\n",nth->FileHeader.Machine==0x8664?"x64":"x86");
    bool packed=false;
    for(WORD i=0;i<nth->FileHeader.NumberOfSections;++i)
        for(int j=0;PACKER_SIGS[j];++j)
            if(!strncmp((char*)sec[i].Name,PACKER_SIGS[j],strlen(PACKER_SIGS[j]))){
                fprintf(out,"PACKER: %s detected\n",PACKER_SIGS[j]); packed=true;
            }
    if(!packed) fprintf(out,"Packer: none detected\n");
}

// ─── static ──────────────────────────────────────────────────────────────────

static void cmd_static(const char* path, FILE* out=stdout){
    FM fm; if(!fm.open(path)){fprintf(out,"Cannot open\n");return;}
    if(!fm.is_pe()){fprintf(out,"Not a PE\n");return;}
    fprintf(out,"=== STATIC: %s ===\n",path);
    auto* dos=(IMAGE_DOS_HEADER*)fm.base;
    auto* nth=(IMAGE_NT_HEADERS*)(fm.base+dos->e_lfanew);
    auto* sec=IMAGE_FIRST_SECTION(nth);
    auto rva2p=[&](DWORD rva)->const uint8_t*{
        for(WORD i=0;i<nth->FileHeader.NumberOfSections;++i)
            if(rva>=sec[i].VirtualAddress&&rva<sec[i].VirtualAddress+sec[i].SizeOfRawData)
                return fm.base+sec[i].PointerToRawData+(rva-sec[i].VirtualAddress);
        return nullptr;
    };
    fprintf(out,"Sections:\n");
    for(WORD i=0;i<nth->FileHeader.NumberOfSections;++i){
        if(!sec[i].SizeOfRawData) continue;
        double se=shannon(fm.base+sec[i].PointerToRawData,sec[i].SizeOfRawData);
        fprintf(out,"  %-8.8s  e=%.3f%s\n",(char*)sec[i].Name,se,se>7.0?" [HIGH]":"");
    }
    auto& idir=nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if(!idir.VirtualAddress){fprintf(out,"No imports\n");return;}
    fprintf(out,"Suspicious imports:\n");
    auto* idt=(IMAGE_IMPORT_DESCRIPTOR*)rva2p(idir.VirtualAddress);
    for(;idt&&idt->Name;++idt){
        DWORD* t=(DWORD*)(idt->OriginalFirstThunk?rva2p(idt->OriginalFirstThunk):rva2p(idt->FirstThunk));
        while(t&&*t){
            auto* ibn=(IMAGE_IMPORT_BY_NAME*)rva2p(*t&0x7FFFFFFF);
            if(ibn)for(int i=0;SUSP_APIS[i];++i)if(!strcmp((char*)ibn->Name,SUSP_APIS[i]))
                fprintf(out,"  [!] %s\n",(char*)ibn->Name);
            ++t;
        }
    }
}

// ─── ioc-check ───────────────────────────────────────────────────────────────

static std::vector<std::string> extract_iocs(const FM& fm){
    std::vector<std::string> iocs;
    std::string cur;
    std::regex url_rx(R"(https?://[^\s<>"']{4,80})");
    std::regex ip_rx(R"(\b(?:25[0-5]|2\d{2}|1\d{2}|[1-9]\d|\d)(?:\.(?:25[0-5]|2\d{2}|1\d{2}|[1-9]\d|\d)){3}\b)");
    std::regex reg_rx(R"(HK[A-Z_]{2,20}\\[^"'\s]{4,80})");
    std::set<std::string> seen;
    for(size_t i=0;i<fm.size;++i){
        uint8_t c=fm.base[i];
        if(c>=0x20&&c<0x7F) cur+=(char)c;
        else{
            if(cur.size()>=6&&seen.find(cur)==seen.end()){
                bool m=std::regex_search(cur,url_rx)||std::regex_search(cur,ip_rx)||std::regex_search(cur,reg_rx);
                if(m){iocs.push_back(cur);seen.insert(cur);}
            }
            cur.clear();
        }
    }
    return iocs;
}

static void cmd_ioc_check(const char* path, FILE* out=stdout){
    FM fm; if(!fm.open(path)){fprintf(out,"Cannot open\n");return;}
    fprintf(out,"=== IOCs: %s ===\n",path);
    auto iocs=extract_iocs(fm);
    for(auto& s:iocs) fprintf(out,"  [IOC] %s\n",s.c_str());
    if(iocs.empty()) fprintf(out,"  (none found)\n");
}

// ─── yara-gen ────────────────────────────────────────────────────────────────

static void cmd_yara_gen(const char* path, FILE* out=stdout){
    FM fm; if(!fm.open(path)){fprintf(out,"Cannot open\n");return;}
    auto iocs=extract_iocs(fm);
    std::string md5=hash_hex(fm.base,fm.size,BCRYPT_MD5_ALGORITHM);
    // Sanitize rule name from filename
    std::string rname="Sample_";
    const char* bn=strrchr(path,'\\');
    rname+=(bn?bn+1:path);
    std::replace_if(rname.begin(),rname.end(),[](char c){return !isalnum(c)&&c!='_';},'_');
    fprintf(out,"rule %s {\n",rname.c_str());
    fprintf(out,"  meta:\n    md5 = \"%s\"\n    auto_generated = true\n",md5.c_str());
    fprintf(out,"  strings:\n");
    int idx=0;
    for(auto& s:iocs){
        if(idx>=5) break;
        // Escape for YARA
        std::string safe; for(char c:s){if(c=='"'||c=='\\')safe+='\\';safe+=c;}
        fprintf(out,"    $ioc%d = \"%s\" ascii\n",idx,safe.c_str());
        ++idx;
    }
    if(fm.is_pe()){
        auto* dos=(IMAGE_DOS_HEADER*)fm.base;
        auto* nth=(IMAGE_NT_HEADERS*)(fm.base+dos->e_lfanew);
        auto* sec=IMAGE_FIRST_SECTION(nth);
        auto rva2p=[&](DWORD rva)->const uint8_t*{
            for(WORD i=0;i<nth->FileHeader.NumberOfSections;++i)
                if(rva>=sec[i].VirtualAddress&&rva<sec[i].VirtualAddress+sec[i].SizeOfRawData)
                    return fm.base+sec[i].PointerToRawData+(rva-sec[i].VirtualAddress);
            return nullptr;
        };
        auto& idir=nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if(idir.VirtualAddress){
            auto* idt=(IMAGE_IMPORT_DESCRIPTOR*)rva2p(idir.VirtualAddress);
            for(;idt&&idt->Name;++idt){
                DWORD* t=(DWORD*)(idt->OriginalFirstThunk?rva2p(idt->OriginalFirstThunk):rva2p(idt->FirstThunk));
                while(t&&*t){
                    auto* ibn=(IMAGE_IMPORT_BY_NAME*)rva2p(*t&0x7FFFFFFF);
                    if(ibn)for(int i=0;SUSP_APIS[i];++i)if(!strcmp((char*)ibn->Name,SUSP_APIS[i])&&idx<10){
                        fprintf(out,"    $api%d = \"%s\" ascii\n",idx,(char*)ibn->Name);++idx;
                    }
                    ++t;
                }
            }
        }
    }
    fprintf(out,"  condition:\n");
    fprintf(out,"    uint16(0) == 0x5A4D and filesize < 10MB and %d of them\n",idx>3?3:idx>0?1:0);
    fprintf(out,"}\n");
}

// ─── decode-xor ──────────────────────────────────────────────────────────────

static void cmd_decode_xor(const char* path, uint8_t key, FILE* out=stdout){
    FM fm; if(!fm.open(path)){fprintf(out,"Cannot open\n");return;}
    fprintf(out,"=== XOR-Decode (key=0x%02X): %s ===\n",key,path);
    std::string cur;
    for(size_t i=0;i<fm.size;++i){
        uint8_t c=(uint8_t)(fm.base[i]^key);
        if(c>=0x20&&c<0x7F) cur+=(char)c;
        else{
            if(cur.size()>=6){
                bool interesting=(cur.find("http")==0||cur.find("HKEY")==0||
                    cur.find("HKC")==0||cur.find("HKL")==0||cur.size()>15);
                if(interesting) fprintf(out,"  [XOR] %s\n",cur.c_str());
            }
            cur.clear();
        }
    }
}

// ─── full report ─────────────────────────────────────────────────────────────

static void cmd_full(const char* path, const char* outfile){
    FILE* out=outfile?fopen(outfile,"w"):stdout;
    if(!out){fprintf(stderr,"Cannot open output\n");return;}
    fprintf(out,"========================================\n");
    fprintf(out,"  RE CAPSTONE FULL REPORT\n");
    fprintf(out,"  %s\n",path);
    fprintf(out,"========================================\n\n");
    cmd_triage(path,out);  fprintf(out,"\n");
    cmd_static(path,out);  fprintf(out,"\n");
    cmd_ioc_check(path,out); fprintf(out,"\n");
    fprintf(out,"--- GENERATED YARA RULE ---\n");
    cmd_yara_gen(path,out);
    fprintf(out,"\n--- DETECTION RECOMMENDATIONS ---\n");
    fprintf(out,"  Sysmon Event 1: CommandLine contains binary name + parent anomaly\n");
    fprintf(out,"  Sysmon Event 3: Unexpected outbound on port 443/4444/8080\n");
    fprintf(out,"  Sysmon Event 13: Registry SetValue under Run* keys\n");
    fprintf(out,"  Sysmon Event 10: Process access to lsass.exe\n");
    if(outfile){fclose(out);printf("[+] Full report: %s\n",outfile);}
}

// ─── main ────────────────────────────────────────────────────────────────────

int main(int argc,char* argv[]){
    if(argc<2){
        printf("Usage: re_capstone.exe triage <f> | static <f> | yara-gen <f>\n");
        printf("                       ioc-check <f> | decode-xor <f> <key_hex>\n");
        printf("                       full <f> [--out <report.txt>]\n");
        return 1;
    }
    std::string cmd(argv[1]);
    if(cmd=="triage"&&argc>=3)          cmd_triage(argv[2]);
    else if(cmd=="static"&&argc>=3)     cmd_static(argv[2]);
    else if(cmd=="yara-gen"&&argc>=3)   cmd_yara_gen(argv[2]);
    else if(cmd=="ioc-check"&&argc>=3)  cmd_ioc_check(argv[2]);
    else if(cmd=="decode-xor"&&argc>=4) cmd_decode_xor(argv[2],(uint8_t)strtoul(argv[3],nullptr,16));
    else if(cmd=="full"&&argc>=3){
        const char* outfile=nullptr;
        for(int i=3;i<argc-1;++i) if(!strcmp(argv[i],"--out")) outfile=argv[i+1];
        cmd_full(argv[2],outfile);
    }
    else{fprintf(stderr,"Unknown command\n");return 1;}
    return 0;
}
