// sol01_full_report.cpp — full analysis pipeline solution
// Compile: g++ -std=c++17 -o sol01.exe sol01_full_report.cpp -lbcrypt
// Usage: sol01.exe <binary> [--report <out.txt>]

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <cmath>
#include <regex>
#pragma comment(lib,"bcrypt.lib")

static double shannon(const uint8_t* d,size_t n){
    uint64_t f[256]{}; for(size_t i=0;i<n;++i)++f[d[i]];
    double h=0;for(int i=0;i<256;++i){if(!f[i])continue;double p=(double)f[i]/n;h-=p*log2(p);}
    return h;
}
static std::string hash_hex(const uint8_t* d,size_t n,const wchar_t* alg_id){
    BCRYPT_ALG_HANDLE a=nullptr; BCRYPT_HASH_HANDLE h=nullptr;
    BCryptOpenAlgorithmProvider(&a,alg_id,nullptr,0);
    DWORD ds=0,rs=0; BCryptGetProperty(a,BCRYPT_HASH_LENGTH,(PUCHAR)&ds,sizeof(ds),&rs,0);
    BCryptCreateHash(a,&h,nullptr,0,nullptr,0,0);
    BCryptHashData(h,(PUCHAR)d,(ULONG)n,0);
    std::vector<uint8_t> dig(ds); BCryptFinishHash(h,dig.data(),ds,0);
    BCryptDestroyHash(h); BCryptCloseAlgorithmProvider(a,0);
    std::string s; for(auto b:dig){char buf[3];sprintf(buf,"%02x",b);s+=buf;}
    return s;
}

static const char* SUSP_APIS[]={"VirtualAllocEx","WriteProcessMemory","CreateRemoteThread",
    "URLDownloadToFile","WinExec","ShellExecuteA","RegSetValueExA","NtUnmapViewOfSection",
    "GetAsyncKeyState","SetWindowsHookExA","CryptEncrypt","BCryptEncrypt","HttpSendRequest",
    "InternetOpenA","InternetOpenW",nullptr};
static const char* PACKER_SIGS[]={"UPX0","UPX1","UPX2",".nsp0",".nsp1","MPRESS1","MPRESS2",nullptr};

enum Cap { CAP_NONE=0,CAP_NETWORK=1,CAP_INJECT=2,CAP_PERSIST=4,CAP_CRYPTO=8,CAP_KEYLOG=16 };

int main(int argc,char* argv[]){
    if(argc<2){printf("Usage: sol01.exe <binary> [--report <out.txt>]\n");return 1;}
    const char* report_file=nullptr;
    for(int i=2;i<argc-1;++i) if(!strcmp(argv[i],"--report")) report_file=argv[i+1];
    FILE* rp=report_file?fopen(report_file,"w"):stdout;
    if(!rp){fprintf(stderr,"Cannot open report file\n");return 1;}

    HANDLE hf=CreateFileA(argv[1],GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);
    if(hf==INVALID_HANDLE_VALUE){fprintf(rp,"Cannot open %s\n",argv[1]);return 1;}
    LARGE_INTEGER sz{}; GetFileSizeEx(hf,&sz);
    HANDLE hm=CreateFileMappingA(hf,nullptr,PAGE_READONLY,0,0,nullptr);
    const uint8_t* base=(const uint8_t*)MapViewOfFile(hm,FILE_MAP_READ,0,0,0);
    size_t n=(size_t)sz.QuadPart;

    fprintf(rp,"====================================================\n");
    fprintf(rp,"  SECURITY ANALYSIS REPORT\n");
    fprintf(rp,"  Target: %s\n",argv[1]);
    fprintf(rp,"====================================================\n\n");

    // Phase 1 — Triage
    fprintf(rp,"--- PHASE 1: TRIAGE ---\n");
    fprintf(rp,"MD5:    %s\n",hash_hex(base,n,BCRYPT_MD5_ALGORITHM).c_str());
    fprintf(rp,"SHA256: %s\n",hash_hex(base,n,BCRYPT_SHA256_ALGORITHM).c_str());
    double e=shannon(base,n);
    fprintf(rp,"Size:   %zu bytes  Entropy: %.3f%s\n\n",n,e,e>7.0?" [PACKED/ENCRYPTED]":"");
    bool is_pe=n>0x40&&*(uint16_t*)base==0x5A4D;
    if(!is_pe){fprintf(rp,"Not a PE file.\n");goto done;}

    {
    auto* dos=(IMAGE_DOS_HEADER*)base;
    auto* nth=(IMAGE_NT_HEADERS*)(base+dos->e_lfanew);
    auto* sec=IMAGE_FIRST_SECTION(nth);
    // Packer check
    fprintf(rp,"Packer signatures: ");
    bool packed=false;
    for(WORD i=0;i<nth->FileHeader.NumberOfSections;++i)
        for(int j=0;PACKER_SIGS[j];++j)
            if(!strncmp((char*)sec[i].Name,PACKER_SIGS[j],strlen(PACKER_SIGS[j]))){fprintf(rp,"%s ",PACKER_SIGS[j]);packed=true;}
    if(!packed) fprintf(rp,"none detected");
    fprintf(rp,"\n\n");

    // Phase 2 — Static
    fprintf(rp,"--- PHASE 2: STATIC ANALYSIS ---\n");
    fprintf(rp,"Machine: 0x%04X  EP: 0x%08X  Sections: %u  Timestamp: 0x%08X\n",
            nth->FileHeader.Machine,nth->OptionalHeader.AddressOfEntryPoint,
            nth->FileHeader.NumberOfSections,nth->FileHeader.TimeDateStamp);
    for(WORD i=0;i<nth->FileHeader.NumberOfSections;++i){
        if(!sec[i].SizeOfRawData) continue;
        double se=shannon(base+sec[i].PointerToRawData,sec[i].SizeOfRawData);
        fprintf(rp,"  %-8.8s  e=%.3f%s\n",(char*)sec[i].Name,se,se>7.0?" [!]":"");
    }
    auto rva2p=[&](DWORD rva)->const uint8_t*{
        for(WORD i=0;i<nth->FileHeader.NumberOfSections;++i)
            if(rva>=sec[i].VirtualAddress&&rva<sec[i].VirtualAddress+sec[i].SizeOfRawData)
                return base+sec[i].PointerToRawData+(rva-sec[i].VirtualAddress);
        return nullptr;
    };
    int caps=0;
    std::vector<std::string> susp_found;
    auto& idir=nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if(idir.VirtualAddress){
        auto* idt=(IMAGE_IMPORT_DESCRIPTOR*)rva2p(idir.VirtualAddress);
        for(;idt&&idt->Name;++idt){
            DWORD* t=(DWORD*)(idt->OriginalFirstThunk?rva2p(idt->OriginalFirstThunk):rva2p(idt->FirstThunk));
            while(t&&*t){
                auto* ibn=(IMAGE_IMPORT_BY_NAME*)rva2p(*t&0x7FFFFFFF);
                if(ibn)for(int i=0;SUSP_APIS[i];++i)if(!strcmp((char*)ibn->Name,SUSP_APIS[i]))
                    susp_found.push_back((char*)ibn->Name);
                ++t;
            }
        }
    }
    fprintf(rp,"\nSuspicious imports:\n");
    for(auto& s:susp_found) fprintf(rp,"  [!] %s\n",s.c_str());

    // Phase 3 — Behavioral hints
    fprintf(rp,"\n--- PHASE 3: BEHAVIORAL HINTS (strings) ---\n");
    std::string cur; std::vector<std::string> iocs;
    std::regex url_rx(R"(https?://[^\s]{4,60})");
    std::regex ip_rx(R"(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)");
    std::regex reg_rx(R"(HK(EY|CU|LM|CR|U)[\\\\][^\s]{3,60})");
    for(size_t i=0;i<n;++i){
        uint8_t c=base[i];
        if(c>=0x20&&c<0x7F) cur+=(char)c;
        else{
            if(cur.size()>=6){
                bool is_ioc=std::regex_search(cur,url_rx)||std::regex_search(cur,ip_rx)||std::regex_search(cur,reg_rx);
                if(is_ioc) iocs.push_back(cur);
            }
            cur.clear();
        }
    }
    for(auto& s:iocs) fprintf(rp,"  [IOC] %s\n",s.c_str());

    // Phase 4 — YARA
    fprintf(rp,"\n--- PHASE 4: YARA RULE ---\n");
    fprintf(rp,"rule AutoGen_%s {\n",strrchr(argv[1],'\\')?(strrchr(argv[1],'\\')+1):"sample");
    fprintf(rp,"  meta:\n");
    fprintf(rp,"    md5 = \"%s\"\n",hash_hex(base,n,BCRYPT_MD5_ALGORITHM).c_str());
    fprintf(rp,"    description = \"Auto-generated via sol01_full_report\"\n");
    fprintf(rp,"  strings:\n");
    int yc=0;
    for(auto& s:iocs){if(yc>=5) break;fprintf(rp,"    $ioc%d = \"%s\" ascii\n",yc,s.c_str());++yc;}
    for(auto& s:susp_found){if(yc>=8) break;fprintf(rp,"    $api%d = \"%s\" ascii\n",yc,s.c_str());++yc;}
    fprintf(rp,"  condition:\n");
    fprintf(rp,"    uint16(0) == 0x5A4D and filesize < 10MB and %d of them\n",yc>2?3:yc>0?1:0);
    fprintf(rp,"}\n");

    // Phase 5 — Report summary
    fprintf(rp,"\n--- PHASE 5: SUMMARY ---\n");
    fprintf(rp,"Capability flags: NETWORK=%d INJECTION=%d PERSISTENCE=%d CRYPTO=%d KEYLOG=%d\n",
            (int)std::count_if(susp_found.begin(),susp_found.end(),[](auto&s){return s.find("Internet")!=std::string::npos||s.find("Http")!=std::string::npos;}),
            (int)std::count_if(susp_found.begin(),susp_found.end(),[](auto&s){return s.find("Virtual")!=std::string::npos||s.find("Remote")!=std::string::npos;}),
            (int)std::count_if(susp_found.begin(),susp_found.end(),[](auto&s){return s.find("Reg")!=std::string::npos;}),
            (int)std::count_if(susp_found.begin(),susp_found.end(),[](auto&s){return s.find("rypt")!=std::string::npos;}),
            (int)std::count_if(susp_found.begin(),susp_found.end(),[](auto&s){return s.find("Hook")!=std::string::npos||s.find("Key")!=std::string::npos;}));
    fprintf(rp,"IOCs found: %zu\n",(size_t)iocs.size());
    fprintf(rp,"VERDICT: %s\n",(!susp_found.empty()||!iocs.empty()||e>7.0)?"SUSPICIOUS":"CLEAN");
    }

done:
    UnmapViewOfFile(base); CloseHandle(hm); CloseHandle(hf);
    if(report_file){fclose(rp);printf("[+] Report written to %s\n",report_file);}
    return 0;
}
