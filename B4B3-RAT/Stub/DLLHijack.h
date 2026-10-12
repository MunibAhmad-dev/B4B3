#pragma once
#ifndef DLLHIJACK_H
#define DLLHIJACK_H
#include "common.h"

// DLLHijack — DLL search order hijacking (T1574.001).
//
// Windows DLL resolution order for most processes:
//   1. Application directory (where the .exe lives)
//   2. System directory (C:\Windows\System32)
//   3. Windows directory (C:\Windows)
//   4. Current working directory
//   5. Directories in %PATH%
//
// If a privileged application loads a DLL by name (no full path) and the DLL
// is missing from the application directory, we can drop a fake DLL there.
// When the app loads, our DLL runs under its security context.
//
// Common hijackable scenarios:
//   - System tools that load DLLs from their own directory
//   - Applications that load "optional" plugins absent in their dir
//   - Services that run from writable directories
//
// This module:
//   1. Scans a target EXE's imports for DLLs not found in the EXE directory
//   2. Optionally generates a proxy DLL stub (exports all functions from the
//      real DLL, with our code in DllMain) at the hijack location
//
// MITRE T1574.001 — Hijack Execution Flow: DLL Search Order Hijacking

namespace DLLHijack {
    // Scan `exePath` for DLLs it imports that are missing from the EXE's directory.
    // Returns a list of hijackable DLL names.
    std::string FindHijackable(const char* exePath);

    // Drop a proxy DLL stub at `dropPath` that:
    //   1. Runs our payload (exePath) on DllMain attach
    //   2. Forwards all exports to the real `realDllName` in System32
    // Returns the generated proxy DLL source hint (for compilation).
    std::string GenerateProxyStub(const char* realDllName, const char* payloadExe,
                                   const char* dropPath);

    // Copy our own EXE as a DLL-named file to hijack a search-order gap.
    // (Only works if the target doesn't validate exports — rare but exists.)
    std::string PlantSimple(const char* dllDropPath, const char* ourExePath);

    // List all hijack-candidate applications in common program directories.
    std::string ScanCommonPaths();
}

#endif
