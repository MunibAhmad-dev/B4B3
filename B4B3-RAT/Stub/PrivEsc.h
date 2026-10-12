#pragma once
#ifndef PRIVESC_H
#define PRIVESC_H
#include "common.h"

namespace PrivEsc {
    // UAC bypass via fodhelper.exe registry hijack (ms-settings COM handler).
    // Writes HKCU\Software\Classes\ms-settings\shell\open\command and DelegateExecute,
    // executes fodhelper.exe (auto-elevates), then cleans up the registry key.
    // cmd = command to run with elevated token.
    // Detection: HKCU COM handler write + auto-elevation without UAC consent prompt.
    std::string FodhelperBypass(const std::string& cmd);

    // UAC bypass via eventvwr.exe (mscfile COM handler).
    // Same detection class, different target binary — tests two distinct detection rules.
    std::string EventvwrBypass(const std::string& cmd);

    // Extract local password hashes by saving SAM, SYSTEM, and SECURITY registry hives.
    // Requires SYSTEM privileges (run tokensteal first).
    // outDir = directory to write SAM / SYSTEM / SECURITY files.
    // Combine with Impacket secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL
    // Detection: RegSaveKeyExA on HKLM\SAM from a non-SYSTEM process is a high-confidence alert.
    std::string SamDump(const std::string& outDir);

    // Extract plaintext Wi-Fi passwords for all saved WLAN profiles.
    // Uses WlanGetProfile with WLAN_PROFILE_GET_PLAINTEXT_KEY — requires admin.
    // Detection: WlanGetProfile with plaintext key flag from a non-service process.
    std::string WiFiDump();
}

#endif
