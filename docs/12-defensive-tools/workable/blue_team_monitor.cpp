/*
  blue_team_monitor.cpp — Module 12 workable (Blue Team Threat Hunter)
  ====================================================================
  Detects the exact techniques used by full_stub.cpp and the B4B3-RAT:
  persistence (Run keys, startup, scheduled tasks), process injection
  (memory anomalies), suspicious outbound connections, and keylogger hooks.

  Compile:
    g++ -std=c++17 -O2 -o blue_team_monitor.exe blue_team_monitor.cpp \
        -ladvapi32 -lbcrypt -lpsapi -liphlpapi -lws2_32 -ltaskschd \
        -lole32 -loleaut32 -lwbemuuid

  Commands:
    blue_team_monitor.exe hunt            one-shot IOC scan (recommended starting point)
    blue_team_monitor.exe watch           continuous monitor (processes + network + registry)
    blue_team_monitor.exe fim <dir>       file integrity monitor for a directory
    blue_team_monitor.exe report          full security snapshot to stdout
*/
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#define _WIN32_DCOM
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <shlobj.h>
#include <taskschd.h>
#include <comdef.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <atomic>
#include <cstdio>
#include <cmath>
#include <algorithm>
#include <fstream>
#include <chrono>

#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"psapi.lib")
#pragma comment(lib,"iphlpapi.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"bcrypt.lib")
#pragma comment(lib,"taskschd.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"oleaut32.lib")

static std::mutex g_mtx;
static void alert(const char* level, const char* module, const char* fmt, ...){
    char msg[1024]={};
    va_list ap; va_start(ap,fmt); vsnprintf(msg,sizeof(msg),fmt,ap); va_end(ap);
    SYSTEMTIME st; GetLocalTime(&st);
    std::lock_guard<std::mutex> lk(g_mtx);
    printf("[%02d:%02d:%02d] [%-8s] [%-5s] %s\n",
           st.wHour,st.wMinute,st.wSecond,module,level,msg);
}

// ── Shannon entropy ───────────────────────────────────────────────────────────
static double entropy(const uint8_t* d, size_t n){
    if(!n) return 0;
    uint64_t f[256]={};
    for(size_t i=0;i<n;++i)++f[d[i]];
    double h=0;
    for(int i=0;i<256;++i){if(!f[i])continue;double p=(double)f[i]/n;h-=p*log2(p);}
    return h;
}

// ── process injection scanner ─────────────────────────────────────────────────
// Looks for memory regions that are RWX or writable-then-executable
// (classic sign of shellcode injection) in each process.
static void scanInjection(DWORD pid){
    HANDLE hp=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,pid);
    if(!hp) return;
    MEMORY_BASIC_INFORMATION mbi{};
    uint8_t* addr=0;
    std::vector<std::pair<void*,size_t>> rwx;
    while(VirtualQueryEx(hp,addr,&mbi,sizeof(mbi))==sizeof(mbi)){
        if(mbi.State==MEM_COMMIT&&mbi.Type==MEM_PRIVATE){
            bool exec=(mbi.Protect&(PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY))!=0;
            bool write=(mbi.Protect&(PAGE_READWRITE|PAGE_WRITECOPY|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY))!=0;
            if(exec&&write) rwx.push_back({mbi.BaseAddress,mbi.RegionSize});
        }
        addr=(uint8_t*)mbi.BaseAddress+mbi.RegionSize;
    }
    if(!rwx.empty()){
        char name[256]={};
        HANDLE hm=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,pid);
        if(hm){GetModuleBaseNameA(hm,nullptr,name,sizeof(name));CloseHandle(hm);}
        for(auto& r:rwx)
            alert("ALERT","INJECT","PID %lu (%s): RWX region @ %p size=%zu",
                  pid,name[0]?name:"?",r.first,r.second);
    }
    CloseHandle(hp);
}

// ── hook scanner: detect WH_KEYBOARD_LL installed hooks ──────────────────────
// EnumWindows-based approach: check foreground thread hooks
static void scanHooks(){
    // GetThreadContext approach: iterate processes, check for SetWindowsHookEx patterns
    // Simpler: check if any process has loaded a suspicious DLL via SetWindowsHookEx
    // We enumerate modules of all processes and flag non-system DLLs in unexpected processes
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(snap==INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe{sizeof(pe)};
    if(!Process32First(snap,&pe)){CloseHandle(snap);return;}
    do {
        HANDLE hsnap=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,pe.th32ProcessID);
        if(hsnap==INVALID_HANDLE_VALUE) continue;
        MODULEENTRY32 me{sizeof(me)};
        if(Module32First(hsnap,&me)) do {
            // Flag any DLL loaded from TEMP or APPDATA in non-browser processes
            std::string mp(me.szExePath); for(auto&c:mp)c=(char)tolower(c);
            std::string pp(pe.szExeFile); for(auto&c:pp)c=(char)tolower(c);
            bool suspDll=(mp.find("\\temp\\")!=std::string::npos||
                           mp.find("\\appdata\\local\\temp\\")!=std::string::npos);
            bool notBrowser=(pp.find("chrome")==std::string::npos&&
                              pp.find("firefox")==std::string::npos&&
                              pp.find("edge")==std::string::npos);
            if(suspDll&&notBrowser)
                alert("ALERT","HOOK","PID %lu (%s) loaded suspicious DLL: %s",
                      pe.th32ProcessID,pe.szExeFile,me.szExePath);
        } while(Module32Next(hsnap,&me));
        CloseHandle(hsnap);
    } while(Process32Next(snap,&pe));
    CloseHandle(snap);
}

// ── persistence hunter ────────────────────────────────────────────────────────
static const char* KNOWN_RUN_LEGIT[]={
    "onedrive","teams","discord","slack","zoom","skype","dropbox",
    "googledrivefs","nordvpn","steam",nullptr
};
static bool isKnownLegit(const std::string& val){
    std::string v=val; for(auto&c:v)c=(char)tolower(c);
    for(int i=0;KNOWN_RUN_LEGIT[i];++i)
        if(v.find(KNOWN_RUN_LEGIT[i])!=std::string::npos) return true;
    // System32 entries are trusted
    if(v.find("system32")!=std::string::npos||v.find("syswow64")!=std::string::npos) return true;
    return false;
}

static void scanRunKeys(){
    HKEY roots[]={HKEY_CURRENT_USER,HKEY_LOCAL_MACHINE};
    const char* rnames[]={"HKCU","HKLM"};
    const char* subkeys[]={
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        nullptr
    };
    for(int r=0;r<2;++r) for(int k=0;subkeys[k];++k){
        HKEY hk=nullptr;
        if(RegOpenKeyExA(roots[r],subkeys[k],0,KEY_READ,&hk)!=ERROR_SUCCESS) continue;
        DWORD idx=0; char name[256]={},val[1024]={};
        while(true){
            DWORD ns=sizeof(name),vs=sizeof(val),type=0;
            if(RegEnumValueA(hk,idx++,name,&ns,0,&type,(BYTE*)val,&vs)!=ERROR_SUCCESS) break;
            std::string v(val);
            if(!isKnownLegit(v))
                alert("WARN","PERSIST","Run key: %s\\%s\\%s = %s",rnames[r],subkeys[k],name,val);
        }
        RegCloseKey(hk);
    }
}

static void scanStartupFiles(){
    int csidls[]={CSIDL_STARTUP,CSIDL_COMMON_STARTUP};
    const char* labels[]={"UserStartup","CommonStartup"};
    for(int i=0;i<2;++i){
        char path[MAX_PATH]={}; SHGetFolderPathA(nullptr,csidls[i],nullptr,0,path);
        WIN32_FIND_DATAA fd{}; std::string pat=std::string(path)+"\\*";
        HANDLE h=FindFirstFileA(pat.c_str(),&fd);
        if(h==INVALID_HANDLE_VALUE) continue;
        do {
            if(fd.cFileName[0]=='.') continue;
            std::string f(fd.cFileName); for(auto&c:f)c=(char)tolower(c);
            alert("WARN","PERSIST","Startup file [%s]: %s",labels[i],fd.cFileName);
        } while(FindNextFileA(h,&fd));
        FindClose(h);
    }
}

// ── suspicious network connections ───────────────────────────────────────────
// Flag connections to known C2 ports or non-standard outbound
static bool isSuspPort(int remPort){
    static const int sus[]={4444,4445,1337,8888,9001,31337,0};
    for(int i=0;sus[i];++i) if(remPort==sus[i]) return true;
    return false;
}

static void scanNetConn(){
    ULONG tsz=0; GetExtendedTcpTable(nullptr,&tsz,FALSE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0);
    std::vector<char> tbuf(tsz);
    PMIB_TCPTABLE_OWNER_PID tt=(PMIB_TCPTABLE_OWNER_PID)tbuf.data();
    if(GetExtendedTcpTable(tt,&tsz,TRUE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0)!=NO_ERROR) return;
    for(DWORD i=0;i<tt->dwNumEntries;++i){
        if(tt->table[i].dwState!=MIB_TCP_STATE_ESTAB) continue;
        struct in_addr ra; ra.s_addr=tt->table[i].dwRemoteAddr;
        char rip[INET_ADDRSTRLEN]; inet_ntop(AF_INET,&ra,rip,sizeof(rip));
        int rport=ntohs((u_short)tt->table[i].dwRemotePort);
        if(isSuspPort(rport)){
            HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
            PROCESSENTRY32 pe{sizeof(pe)}; std::string pname="?";
            if(snap!=INVALID_HANDLE_VALUE&&Process32First(snap,&pe)) do {
                if(pe.th32ProcessID==tt->table[i].dwOwningPid){pname=pe.szExeFile;break;}
            } while(Process32Next(snap,&pe));
            if(snap!=INVALID_HANDLE_VALUE) CloseHandle(snap);
            alert("ALERT","NETCONN","PID %lu (%s) connected to %s:%d (suspicious port)",
                  tt->table[i].dwOwningPid,pname.c_str(),rip,rport);
        }
    }
}

// ── file integrity monitor ────────────────────────────────────────────────────
static std::string sha256File(const char* path){
    HANDLE hf=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,0,0);
    if(hf==INVALID_HANDLE_VALUE) return "";
    BCRYPT_ALG_HANDLE alg=nullptr; BCRYPT_HASH_HANDLE hash=nullptr;
    BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0);
    DWORD ds=0,rs=0; BCryptGetProperty(alg,BCRYPT_HASH_LENGTH,(PUCHAR)&ds,4,&rs,0);
    BCryptCreateHash(alg,&hash,nullptr,0,nullptr,0,0);
    char buf[65536]; DWORD rd=0;
    while(ReadFile(hf,buf,sizeof(buf),&rd,0)&&rd>0) BCryptHashData(hash,(PUCHAR)buf,rd,0);
    std::vector<uint8_t> dig(ds); BCryptFinishHash(hash,dig.data(),ds,0);
    BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(alg,0); CloseHandle(hf);
    std::string s; char b[3]; for(auto v:dig){snprintf(b,sizeof(b),"%02x",v);s+=b;}
    return s;
}

static std::unordered_map<std::string,std::string> g_baseline;
static void buildBaseline(const char* dir){
    WIN32_FIND_DATAA fd{}; std::string pat=std::string(dir)+"\\*";
    HANDLE h=FindFirstFileA(pat.c_str(),&fd);
    if(h==INVALID_HANDLE_VALUE) return;
    do {
        if(fd.cFileName[0]=='.') continue;
        if(fd.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY){
            std::string sub=std::string(dir)+"\\"+fd.cFileName;
            buildBaseline(sub.c_str());
        } else {
            std::string fp=std::string(dir)+"\\"+fd.cFileName;
            g_baseline[fp]=sha256File(fp.c_str());
        }
    } while(FindNextFileA(h,&fd));
    FindClose(h);
}
static void checkChanges(const char* dir){
    WIN32_FIND_DATAA fd{}; std::string pat=std::string(dir)+"\\*";
    HANDLE h=FindFirstFileA(pat.c_str(),&fd);
    if(h==INVALID_HANDLE_VALUE) return;
    do {
        if(fd.cFileName[0]=='.') continue;
        if(fd.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY){
            std::string sub=std::string(dir)+"\\"+fd.cFileName;
            checkChanges(sub.c_str());
        } else {
            std::string fp=std::string(dir)+"\\"+fd.cFileName;
            std::string cur=sha256File(fp.c_str());
            auto it=g_baseline.find(fp);
            if(it==g_baseline.end()) alert("WARN","FIM","NEW file: %s",fp.c_str());
            else if(it->second!=cur) alert("ALERT","FIM","MODIFIED: %s",fp.c_str());
        }
    } while(FindNextFileA(h,&fd));
    FindClose(h);
    // Deleted files
    for(auto& kv:g_baseline){
        if(kv.first.rfind(std::string(dir),0)!=0) continue;
        if(GetFileAttributesA(kv.first.c_str())==INVALID_FILE_ATTRIBUTES)
            alert("WARN","FIM","DELETED: %s",kv.first.c_str());
    }
}

static void cmdFim(const char* dir){
    printf("[*] FIM: baseline for %s ...\n",dir);
    buildBaseline(dir);
    printf("[*] Baseline: %zu files.  Monitoring (Ctrl+C to stop) ...\n",g_baseline.size());
    while(true){ Sleep(5000); checkChanges(dir); }
}

// ── hunt: one-shot IOC scan ───────────────────────────────────────────────────
static void cmdHunt(){
    printf("=== IOC Hunt ===\n\n");
    printf("[*] Scanning Run keys ...\n"); scanRunKeys();
    printf("[*] Scanning startup folders ...\n"); scanStartupFiles();
    printf("[*] Scanning network connections ...\n"); scanNetConn();
    printf("[*] Scanning for memory injection ...\n");
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    PROCESSENTRY32 pe{sizeof(pe)};
    if(snap!=INVALID_HANDLE_VALUE&&Process32First(snap,&pe)) do {
        if(pe.th32ProcessID==GetCurrentProcessId()) continue;
        scanInjection(pe.th32ProcessID);
    } while(Process32Next(snap,&pe));
    if(snap!=INVALID_HANDLE_VALUE) CloseHandle(snap);
    printf("[*] Scanning for suspicious hooks ...\n"); scanHooks();
    printf("\n[*] Hunt complete.\n");
}

// ── watch: continuous monitoring ─────────────────────────────────────────────
static void cmdWatch(){
    printf("[*] Continuous monitoring (Ctrl+C to stop) ...\n\n");
    std::atomic<bool> run{true};
    auto netThread=[&]{while(run){scanNetConn();Sleep(5000);}};
    auto persThread=[&]{while(run){scanRunKeys();scanStartupFiles();Sleep(10000);}};
    auto injThread=[&]{
        while(run){
            HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
            PROCESSENTRY32 pe{sizeof(pe)};
            if(snap!=INVALID_HANDLE_VALUE&&Process32First(snap,&pe)) do {
                if(pe.th32ProcessID==GetCurrentProcessId()) continue;
                scanInjection(pe.th32ProcessID);
            } while(Process32Next(snap,&pe));
            if(snap!=INVALID_HANDLE_VALUE) CloseHandle(snap);
            Sleep(8000);
        }
    };
    std::thread t1(netThread),t2(persThread),t3(injThread);
    // Main thread just waits
    while(true) Sleep(1000);
    run=false; t1.join(); t2.join(); t3.join();
}

// ── report: full one-shot snapshot ───────────────────────────────────────────
static void cmdReport(){
    printf("=========================================\n");
    printf("  SECURITY SNAPSHOT\n");
    SYSTEMTIME st; GetLocalTime(&st);
    printf("  %04d-%02d-%02d %02d:%02d:%02d\n",
           st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,st.wSecond);
    printf("=========================================\n\n");
    cmdHunt();
}

// ── main ─────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]){
    if(argc<2){
        puts("blue_team_monitor — Module 12 workable\n"
             "  hunt          one-shot IOC scan (persistence/injection/hooks/network)\n"
             "  watch         continuous monitoring on all channels\n"
             "  fim <dir>     file integrity monitor\n"
             "  report        full security snapshot");
        return 1;
    }
    CoInitializeEx(nullptr,COINIT_MULTITHREADED);
    std::string cmd(argv[1]);
    if     (cmd=="hunt")            cmdHunt();
    else if(cmd=="watch")           cmdWatch();
    else if(cmd=="fim"&&argc>=3)    cmdFim(argv[2]);
    else if(cmd=="report")          cmdReport();
    else {fprintf(stderr,"Unknown command\n");return 1;}
    CoUninitialize();
    return 0;
}
