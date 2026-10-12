#pragma once
#ifndef MODULESTOMP_H
#define MODULESTOMP_H
#include "common.h"

// ModuleStomp — overwrite a legitimate DLL's .text section with custom code.
//
// Unlike process hollowing (which creates a new process), module stomping
// runs code *inside the current process* but attributes it to a signed,
// legitimate DLL. In memory, the code appears to belong to (e.g.) version.dll.
//
// Technique:
//   1. Load a sacrificial legitimate DLL via LoadLibraryExA(DONT_RESOLVE_DLL_REFERENCES)
//   2. Locate its .text section
//   3. VirtualProtect to RWX
//   4. Overwrite .text with our shellcode
//   5. Execute from there — EDR sees execution originating from version.dll
//
// The DLL is loaded a second time (doesn't affect the system copy already in use)
// so its in-memory image is private to this process and writable.
//
// What a strong detector still catches:
//   - The DLL's on-disk hash will not match its in-memory content (MDE checks this)
//   - A VirtualProtect on a loaded module's .text = Sysmon EID 10 / memory integrity check
//   - The PEB still shows version.dll as loaded, but with a modified checksum
//   - ETW image-load events fired before we overwrote the section
//
// MITRE T1055.001 (DLL Injection via module stomping variant)

namespace ModuleStomp {
    // Load `dllName` as a stomping target, copy `code` into its .text section.
    // `dllName` should be a system DLL that is not currently loaded (e.g. "version.dll").
    // After this call, executing the returned pointer runs `code` attributed to `dllName`.
    // Returns NULL on failure.
    PVOID Stomp(const char* dllName, const BYTE* code, SIZE_T codeSize);

    // Execute previously stomped code (call the PVOID returned by Stomp).
    // Casts and calls as a void(*)() — shellcode must not take args.
    std::string Execute(PVOID stompedAddr);

    // Free the stomped module (FreeLibrary).
    void Unstamp(HMODULE hMod);

    // List candidate system DLLs suitable for stomping (not already loaded).
    std::string ListCandidates();
}

#endif
