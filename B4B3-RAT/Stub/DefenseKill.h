#pragma once
#ifndef DEFENSEKILL_H
#define DEFENSEKILL_H
#include "common.h"

namespace DefenseKill {
    // Disable Windows Defender real-time protection via:
    //   1. Registry policy key (HKLM\SOFTWARE\Policies\Microsoft\Windows Defender)
    //   2. Set-MpPreference -Disable* via hidden PowerShell
    //   3. Stop + disable WinDefend and WdNisSvc services
    // Detection: registry policy write + service stop on WinDefend = T1562.001.
    std::string DisableDefender();

    // Disable Windows Firewall on all profiles via netsh + registry.
    // Detection: NetshCommand / registry write to HKLM\...\FirewallPolicy = T1562.004.
    std::string DisableFirewall();

    // Re-enable both (for cleanup / after test).
    std::string EnableDefender();
    std::string EnableFirewall();

    // Block Task Manager via registry (HKCU\...\DisableTaskMgr=1).
    // Detection: DisableTaskMgr registry write = T1562.001 policy tamper.
    std::string BlockTaskManager(bool block);

    // Exclude a path from Windows Defender scans (Add-MpPreference -ExclusionPath).
    // Detection: MpPreference ExclusionPath write from non-admin tool = T1562.001.
    std::string AddDefenderExclusion(const std::string& path);
}

#endif
