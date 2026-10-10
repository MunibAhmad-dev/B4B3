// analysis_toolkit.cpp — combined static/dynamic/diff/timeline analysis toolkit
// Compile: g++ -std=c++17 -o analysis_toolkit.exe analysis_toolkit.cpp -lbcrypt -ladvapi32
// Usage: analysis_toolkit.exe static <f> | dynamic <pid> | diff <old> <new> | timeline | hooks

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <bcrypt.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <cmath>
#include <regex>
#pragma comment(lib,"bcrypt.lib")
#pragma comment(lib,"advapi32.lib")

static double shannon(const uint8_t* d,size_t n){
    uint64_t f[256]{}; for(size_t i=0;i<n;++i)++f[d[i]];
    double h=0; for(int i=0;i<256;++i){if(!f[i])continue;double p=(double)f[i]/n;h-=p*log2(p);}
    return h;
}

static std::string md5_file(const uint8_t* data,size_t size){
    BCRYPT_ALG_HANDLE alg=nullptr; BCRYPT_HASH_HANDLE hash=nullptr;
    BCryptOpenAlgorithmProvider(&alg,BCRYPT_MD5_ALGORITHM,nullptr,0);
    BCryptCreateHash(alg,&hash,nullptr,0,nullptr,0,0);
    BCryptHashData(hash,(PUCHAR)data,(ULONG)size,0);
    uint8_t dig[16]{}; BCryptFinishHash(hash,dig,16,0);
    BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(alg,0);
    char buf[33]{}; for(int i=0;i<16;++i) sprintf(buf+2*i,"%02x",dig[i]);
    return buf;
}

struct FM {
    const uint8_t* base=nullptr; size_t size=0;
    HANDLE hf=INVALID_HANDLE_VALUE,hm=nullptr;
    bool open(const char* p){
        hf=CreateFileA(p,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);
        if(hf==INVALID_HANDLE_VALUE)return false;
        LARGE_INTEGER sz{}; GetFileSizeEx(hf,&sz); size=(size_t)sz.QuadPart;
        hm=CreateFileMappingA(hf,nullptr,PAGE_READONLY,0,0,nullptr); if(!hm)return false;
        base=(const uint8_t*)MapViewOfFile(hm,FILE_MAP_READ,0,0,0); return base!=nullptr;
    }
    ~FM(){if(base)UnmapViewOfFile(base);if(hm)CloseHandle(hm);if(hf!=INVALID_HANDLE_VALUE)CloseHandle(hf);}
    bool is_pe()const{return size>0x40&&*(uint16_t*)base==0x5A4D;}
};

static uint32_t djb2_mem(const uint8_t* d,size_t n){
    uint32_t h=5381; for(size_t i=0;i<n;++i) h=((h<<5)+h)^d[i]; return h;
}

// ─── static ──────────────────────────────────────────────────────────────────

static const char* SUSP_APIS[]={"VirtualAllocEx","WriteProcessMemory","CreateRemoteThread",
    "URLDownloadToFile","WinExec","ShellExecuteA","RegSetValueExA","NtUnmapViewOfSection",
    "GetAsyncKeyState","SetWindowsHookExA","CryptEncrypt","BCryptEncrypt","HttpSendRequest",nullptr};

static void cmd_static(const char* path){
    FM fm; if(!fm.open(path)){fprintf(stderr,"Cannot open %s\n",path);return;}
    printf("=== Static Analysis: %s ===\n",path);
    printf("MD5:     %s\n",md5_file(fm.base,fm.size).c_str());
    double e=shannon(fm.base,fm.size);
    printf("Size:    %zu  Entropy: %.3f%s\n",fm.size,e,e>7.0?" [PACKED?]":"");
    if(!fm.is_pe()){printf("Not a PE\n");return;}
    auto* dos=(IMAGE_DOS_HEADER*)fm.base;
    auto* nth=(IMAGE_NT_HEADERS*)(fm.base+dos->e_lfanew);
    auto* sec=IMAGE_FIRST_SECTION(nth);
    printf("Machine: 0x%04X  EP: 0x%08X  Sections: %u\n",
           nth->FileHeader.Machine,nth->OptionalHeader.AddressOfEntryPoint,nth->FileHeader.NumberOfSections);
    for(WORD i=0;i<nth->FileHeader.NumberOfSections;++i){
        if(!sec[i].SizeOfRawData) continue;
        double se=shannon(fm.base+sec[i].PointerToRawData,sec[i].SizeOfRawData);
        printf("  %-8.8s  VA=0x%08X  size=%-8u  e=%.3f%s\n",
               (char*)sec[i].Name,sec[i].VirtualAddress,sec[i].SizeOfRawData,se,se>7.0?" [!]":"");
    }
    auto rva2p=[&](DWORD rva)->const uint8_t*{
        for(WORD i=0;i<nth->FileHeader.NumberOfSections;++i)
            if(rva>=sec[i].VirtualAddress&&rva<sec[i].VirtualAddress+sec[i].SizeOfRawData)
                return fm.base+sec[i].PointerToRawData+(rva-sec[i].VirtualAddress);
        return nullptr;
    };
    auto& dir=nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if(dir.VirtualAddress){
        printf("\nSuspicious imports:\n");
        auto* idt=(IMAGE_IMPORT_DESCRIPTOR*)rva2p(dir.VirtualAddress);
        for(;idt&&idt->Name;++idt){
            DWORD* t=(DWORD*)(idt->OriginalFirstThunk?rva2p(idt->OriginalFirstThunk):rva2p(idt->FirstThunk));
            while(t&&*t){
                auto* ibn=(IMAGE_IMPORT_BY_NAME*)rva2p(*t&0x7FFFFFFF);
                if(ibn)for(int i=0;SUSP_APIS[i];++i)if(!strcmp((char*)ibn->Name,SUSP_APIS[i]))
                    printf("  [!] %s\n",(char*)ibn->Name);
                ++t;
            }
        }
    }
}

// ─── dynamic ─────────────────────────────────────────────────────────────────

static void cmd_dynamic(DWORD pid){
    printf("=== Dynamic Snapshot: PID %lu ===\n",pid);
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,pid);
    if(snap!=INVALID_HANDLE_VALUE){
        MODULEENTRY32 me{sizeof(me)};
        printf("Modules:\n");
        if(Module32First(snap,&me))do{
            printf("  %-30s  base=%p  size=0x%X\n",me.szModule,(void*)me.modBaseAddr,me.modBaseSize);
        }while(Module32Next(snap,&me));
        CloseHandle(snap);
    }
    HANDLE hProc=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,pid);
    if(hProc){
        DWORD hc=0; GetProcessHandleCount(hProc,&hc);
        printf("\nHandle count: %lu\n",hc);
        // Check for RWX regions (injection indicator)
        printf("RWX memory regions:\n");
        MEMORY_BASIC_INFORMATION mbi{};
        for(SIZE_T addr=0;VirtualQueryEx(hProc,(LPCVOID)addr,&mbi,sizeof(mbi));addr+=(SIZE_T)mbi.RegionSize){
            if(mbi.Protect==PAGE_EXECUTE_READWRITE||mbi.Protect==PAGE_EXECUTE_WRITECOPY)
                printf("  [RWX] %p  size=0x%zX\n",mbi.BaseAddress,mbi.RegionSize);
        }
        CloseHandle(hProc);
    }
}

// ─── diff ────────────────────────────────────────────────────────────────────

static std::map<std::string,uint32_t> export_hashes(const FM& fm){
    std::map<std::string,uint32_t> m;
    if(!fm.is_pe()) return m;
    auto* dos=(IMAGE_DOS_HEADER*)fm.base;
    auto* nth=(IMAGE_NT_HEADERS*)(fm.base+dos->e_lfanew);
    auto* sec=IMAGE_FIRST_SECTION(nth);
    auto rva2p=[&](DWORD rva)->const uint8_t*{
        for(WORD i=0;i<nth->FileHeader.NumberOfSections;++i)
            if(rva>=sec[i].VirtualAddress&&rva<sec[i].VirtualAddress+sec[i].SizeOfRawData)
                return fm.base+sec[i].PointerToRawData+(rva-sec[i].VirtualAddress);
        return nullptr;
    };
    auto& ed=nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if(!ed.VirtualAddress) return m;
    auto* exp=(IMAGE_EXPORT_DIRECTORY*)rva2p(ed.VirtualAddress);
    if(!exp) return m;
    auto* names=(DWORD*)rva2p(exp->AddressOfNames);
    auto* funcs=(DWORD*)rva2p(exp->AddressOfFunctions);
    auto* ords=(WORD*)rva2p(exp->AddressOfNameOrdinals);
    if(!names||!funcs||!ords) return m;
    for(DWORD i=0;i<exp->NumberOfNames;++i){
        const char* name=(const char*)rva2p(names[i]);
        const uint8_t* fn=rva2p(funcs[ords[i]]);
        if(name&&fn) m[name]=djb2_mem(fn,64);
    }
    return m;
}

static void cmd_diff(const char* old_p,const char* new_p){
    FM fo,fn; fo.open(old_p); fn.open(new_p);
    printf("=== Binary Diff: %s vs %s ===\n\n",old_p,new_p);
    auto oh=export_hashes(fo), nh=export_hashes(fn);
    printf("Old exports: %zu  New exports: %zu\n\n",(size_t)oh.size(),(size_t)nh.size());
    int changed=0,added=0,removed=0;
    for(auto& [k,v]:oh){
        auto it=nh.find(k);
        if(it==nh.end()){printf("  [REMOVED] %s\n",k.c_str());++removed;}
        else if(it->second!=v){printf("  [CHANGED] %s  old=0x%08X  new=0x%08X\n",k.c_str(),v,it->second);++changed;}
    }
    for(auto& [k,v]:nh) if(oh.find(k)==oh.end()){printf("  [ADDED]   %s\n",k.c_str());++added;}
    printf("\nSummary: %d changed, %d added, %d removed\n",changed,added,removed);
}

// ─── timeline ────────────────────────────────────────────────────────────────

static void cmd_timeline(){
    printf("=== Forensic Timeline Artifacts ===\n\n");
    // Prefetch directory listing
    WIN32_FIND_DATAA fd{};
    HANDLE h=FindFirstFileA("C:\\Windows\\Prefetch\\*.pf",&fd);
    if(h!=INVALID_HANDLE_VALUE){
        printf("Prefetch files (last 10):\n");
        int cnt=0;
        do{
            FILETIME ft=fd.ftLastWriteTime; SYSTEMTIME st{};
            FileTimeToSystemTime(&ft,&st);
            printf("  %04d-%02d-%02d %02d:%02d  %s\n",
                   st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,fd.cFileName);
            if(++cnt>=10) break;
        }while(FindNextFileA(h,&fd));
        FindClose(h);
    } else printf("Prefetch dir not accessible (need elevation or prefetch disabled)\n");

    // Recent EVTX hint
    printf("\nKey EVTX logs for timeline:\n");
    printf("  Security.evtx   — Event 4688 (process create), 4624/4625 (logon)\n");
    printf("  System.evtx     — Event 7045 (service install), 7036 (service state)\n");
    printf("  Sysmon.evtx     — Events 1/3/11/13 (proc/net/file/reg)\n");
    printf("  Use: Get-WinEvent -LogName Security | Where-Object Id -eq 4688\n");
}

// ─── hooks demo ──────────────────────────────────────────────────────────────

typedef HANDLE(WINAPI*PCreateFileA)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
static PCreateFileA real_CreateFileA=nullptr;

static HANDLE WINAPI hook_CreateFileA(LPCSTR fn,DWORD acc,DWORD sh,LPSECURITY_ATTRIBUTES sa,DWORD cd,DWORD fa,HANDLE tmpl){
    printf("  [HOOK] CreateFileA(\"%s\", access=0x%X)\n",fn?fn:"<null>",acc);
    return real_CreateFileA(fn,acc,sh,sa,cd,fa,tmpl);
}

static bool install_iat_hook(){
    HMODULE self=GetModuleHandleA(nullptr);
    if(!self) return false;
    auto* dos=(IMAGE_DOS_HEADER*)self;
    auto* nth=(IMAGE_NT_HEADERS*)((uint8_t*)self+dos->e_lfanew);
    auto* sec=IMAGE_FIRST_SECTION(nth);
    auto rva2p=[&](DWORD rva)->void*{return(void*)((uint8_t*)self+rva);};
    auto& idir=nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if(!idir.VirtualAddress) return false;
    auto* idt=(IMAGE_IMPORT_DESCRIPTOR*)rva2p(idir.VirtualAddress);
    for(;idt->Name;++idt){
        const char* dname=(const char*)rva2p(idt->Name);
        if(_stricmp(dname,"KERNEL32.DLL")&&_stricmp(dname,"api-ms-win-core-file-l1-1-0.dll")) continue;
        DWORD* orig=(DWORD*)rva2p(idt->OriginalFirstThunk);
        DWORD* thnk=(DWORD*)rva2p(idt->FirstThunk);
        for(DWORD i=0;orig[i];++i){
            if(orig[i]&IMAGE_ORDINAL_FLAG32) continue;
            auto* ibn=(IMAGE_IMPORT_BY_NAME*)rva2p(orig[i]&0x7FFFFFFF);
            if(!_stricmp((char*)ibn->Name,"CreateFileA")){
                real_CreateFileA=(PCreateFileA)thnk[i];
                DWORD old; VirtualProtect(thnk+i,sizeof(DWORD),PAGE_READWRITE,&old);
                *(void**)(thnk+i)=(void*)hook_CreateFileA;
                VirtualProtect(thnk+i,sizeof(DWORD),old,&old);
                return true;
            }
        }
    }
    return false;
}

static void cmd_hooks(){
    printf("=== IAT Hook Demo ===\n");
    if(install_iat_hook()) printf("[+] CreateFileA IAT hook installed\n\n");
    else { printf("[-] Hook install failed (64-bit IAT DWORD size mismatch — use DWORD_PTR)\n\n"); }
    printf("Calling CreateFileA — watch for hook output:\n");
    HANDLE h=CreateFileA("hook_test.txt",GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(h!=INVALID_HANDLE_VALUE) CloseHandle(h);
    printf("Done. Restore hook by writing real_CreateFileA back to IAT entry.\n");
}

// ─── main ────────────────────────────────────────────────────────────────────

int main(int argc,char* argv[]){
    if(argc<2){printf("Usage: analysis_toolkit.exe static <f> | dynamic <pid> | diff <old> <new> | timeline | hooks\n");return 1;}
    std::string cmd(argv[1]);
    if      (cmd=="static"&&argc>=3)   cmd_static(argv[2]);
    else if (cmd=="dynamic"&&argc>=3)  cmd_dynamic((DWORD)strtoul(argv[2],nullptr,10));
    else if (cmd=="diff"&&argc>=4)     cmd_diff(argv[2],argv[3]);
    else if (cmd=="timeline")          cmd_timeline();
    else if (cmd=="hooks")             cmd_hooks();
    else { fprintf(stderr,"Unknown command\n"); return 1; }
    return 0;
}
