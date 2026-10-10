// sol01_static_pipeline.cpp — full static analysis pipeline solution
// Compile: g++ -std=c++17 -o sol01.exe sol01_static_pipeline.cpp -lbcrypt
// Usage: sol01.exe <binary>

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <set>
#include <cmath>
#include <regex>
#pragma comment(lib,"bcrypt.lib")

static const char* SUSP_APIS[]={"VirtualAllocEx","WriteProcessMemory","CreateRemoteThread",
    "URLDownloadToFile","WinExec","ShellExecuteA","RegSetValueExA","NtUnmapViewOfSection",
    "HttpSendRequest","InternetOpenUrl","GetAsyncKeyState","SetWindowsHookExA",
    "CryptEncrypt","BCryptEncrypt",nullptr};

static double shannon(const uint8_t* d,size_t n){
    uint64_t f[256]{}; for(size_t i=0;i<n;++i)++f[d[i]];
    double h=0; for(int i=0;i<256;++i){if(!f[i])continue;double p=(double)f[i]/n;h-=p*log2(p);}
    return h;
}

static std::string md5_hex(const uint8_t* data, size_t size) {
    BCRYPT_ALG_HANDLE alg=nullptr; BCRYPT_HASH_HANDLE hash=nullptr;
    BCryptOpenAlgorithmProvider(&alg,BCRYPT_MD5_ALGORITHM,nullptr,0);
    BCryptCreateHash(alg,&hash,nullptr,0,nullptr,0,0);
    BCryptHashData(hash,(PUCHAR)data,(ULONG)size,0);
    uint8_t dig[16]{}; BCryptFinishHash(hash,dig,16,0);
    BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(alg,0);
    char buf[33]{}; for(int i=0;i<16;++i) sprintf(buf+2*i,"%02x",dig[i]);
    return buf;
}

static const char* categorize_string(const std::string& s) {
    if(s.find("http")==0||s.find("ftp")==0) return "URL";
    static std::regex ip_rx(R"(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)");
    if(std::regex_search(s,ip_rx)) return "IP";
    if(s.find("HKEY")==0||s.find("CurrentVersion")!=std::string::npos) return "REGISTRY";
    if(s.find("C:\\")==0||s.find("\\\\")!=std::string::npos) return "PATH";
    return "GENERIC";
}

int main(int argc, char* argv[]) {
    if(argc<2){printf("Usage: sol01.exe <binary>\n");return 1;}
    HANDLE hf=CreateFileA(argv[1],GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);
    if(hf==INVALID_HANDLE_VALUE){fprintf(stderr,"Cannot open\n");return 1;}
    LARGE_INTEGER sz{}; GetFileSizeEx(hf,&sz);
    HANDLE hm=CreateFileMappingA(hf,nullptr,PAGE_READONLY,0,0,nullptr);
    const uint8_t* base=(const uint8_t*)MapViewOfFile(hm,FILE_MAP_READ,0,0,0);
    size_t n=(size_t)sz.QuadPart;

    printf("=== Static Analysis Pipeline: %s ===\n\n",argv[1]);
    printf("MD5:     %s\n",md5_hex(base,n).c_str());
    double e=shannon(base,n);
    printf("Entropy: %.3f%s\n",e,e>7.0?" [HIGH — likely packed]":"");
    printf("Size:    %zu bytes\n\n",n);

    // Strings
    std::string cur; int score=0;
    std::set<std::string> seen;
    printf("--- Strings (categorized) ---\n");
    for(size_t i=0;i<n;++i){
        uint8_t c=base[i];
        if(c>=0x20&&c<0x7F) cur+=(char)c;
        else{
            if(cur.size()>=6&&seen.find(cur)==seen.end()){
                const char* cat=categorize_string(cur);
                if(strcmp(cat,"GENERIC")) {
                    printf("  [%s] %s\n",cat,cur.c_str());
                    if(!strcmp(cat,"URL")||!strcmp(cat,"IP")) score+=5;
                }
                seen.insert(cur);
            }
            cur.clear();
        }
    }

    // Imports + capabilities
    int caps=0;
    printf("\n--- Capabilities ---\n");
    if(n>0x40&&*(uint16_t*)base==0x5A4D){
        auto* dos=(IMAGE_DOS_HEADER*)base;
        auto* nth=(IMAGE_NT_HEADERS*)(base+dos->e_lfanew);
        auto* sec=IMAGE_FIRST_SECTION(nth);
        auto rva2p=[&](DWORD rva)->const uint8_t*{
            for(WORD i=0;i<nth->FileHeader.NumberOfSections;++i)
                if(rva>=sec[i].VirtualAddress&&rva<sec[i].VirtualAddress+sec[i].SizeOfRawData)
                    return base+sec[i].PointerToRawData+(rva-sec[i].VirtualAddress);
            return nullptr;
        };
        auto& dir=nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if(dir.VirtualAddress){
            auto* idt=(IMAGE_IMPORT_DESCRIPTOR*)rva2p(dir.VirtualAddress);
            for(;idt&&idt->Name;++idt){
                DWORD* thunk=(DWORD*)(idt->OriginalFirstThunk?rva2p(idt->OriginalFirstThunk):rva2p(idt->FirstThunk));
                while(thunk&&*thunk){
                    auto* ibn=(IMAGE_IMPORT_BY_NAME*)rva2p(*thunk&0x7FFFFFFF);
                    if(ibn){for(int i=0;SUSP_APIS[i];++i)if(!strcmp((char*)ibn->Name,SUSP_APIS[i])){
                        printf("  [SUSPICIOUS] %s\n",(char*)ibn->Name);score+=10;++caps;
                    }}
                    ++thunk;
                }
            }
        }
    }
    if(e>7.0) score+=30;
    score=score>100?100:score;
    printf("\n--- Threat Score: %d/100 ---\n",score);
    if(score>70) printf("  [!] HIGH — likely malicious\n");
    else if(score>40) printf("  [?] MEDIUM — suspicious\n");
    else printf("  [OK] LOW\n");

    UnmapViewOfFile(base); CloseHandle(hm); CloseHandle(hf);
    return 0;
}
