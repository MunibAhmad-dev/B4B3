/*
 * sol04_com_hijack_sim.cpp — COM Hijacking Simulation (Authorized Testing)
 *
 * SECURITY EDUCATION: COM Hijacking for persistence without admin privileges.
 *
 * How it works:
 *   Windows COM resolves class loading in this order:
 *     1. HKCU\SOFTWARE\Classes\CLSID\{...}   (user-writable, no UAC needed)
 *     2. HKLM\SOFTWARE\Classes\CLSID\{...}   (requires admin to write)
 *
 *   Malware abuses this by writing a HKCU key pointing to its own DLL for
 *   a CLSID that exists in HKLM. The next time any process (including
 *   privileged ones) loads that COM class, the malicious DLL is loaded instead.
 *   This is a privilege-escalation-free persistence mechanism.
 *
 * Detection:
 *   Monitor HKCU\SOFTWARE\Classes\CLSID writes via:
 *     - Sysmon Event ID 13 (RegistryEvent: SetValue)
 *       Filter: TargetObject contains "HKCU\SOFTWARE\Classes\CLSID"
 *     - This program's blue-team scan logic (step 4 below) shows how to
 *       enumerate and flag discrepancies.
 *
 * Compile:
 *   g++ -std=c++17 -Wall -o sol04.exe sol04_com_hijack_sim.cpp -ladvapi32
 *
 * Run as standard user (no admin required — that is the point):
 *   sol04.exe
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

// ---------------------------------------------------------------------------
// Test CLSID — {DEADBEEF-CAFE-BABE-DEAD-BEEFCAFEBABE}
// Using a CLSID that does NOT exist in real HKLM so we control its setup
// entirely and clean it up completely.
// ---------------------------------------------------------------------------
static const char TEST_CLSID[] = "{DEADBEEF-CAFE-BABE-DEAD-BEEFCAFEBABE}";

// Safe existing DLL to use as the "real" HKLM entry (legitimate server)
static const char HKLM_DLL[]  = "C:\\Windows\\System32\\shell32.dll";
// Hijack target — doesn't need to exist; demonstrates the key write only
static const char HKCU_DLL[]  = "C:\\Temp\\hijacked.dll";

// ---------------------------------------------------------------------------
// Helper: build registry key path string
// ---------------------------------------------------------------------------
static void BuildCLSIDKey(char* buf, int cch, const char* root, const char* clsid)
{
    // root is e.g. "SOFTWARE\\Classes\\CLSID"
    snprintf(buf, cch, "%s\\%s\\InprocServer32", root, clsid);
}

// ---------------------------------------------------------------------------
// Step 1 — Setup: write test CLSID into HKLM (requires elevation on real
//           machines; here we use HKLM only to simulate the existing entry).
//           If this fails (no admin), we skip and note it.
// ---------------------------------------------------------------------------
static bool SetupHKLMEntry()
{
    char keyPath[512];
    BuildCLSIDKey(keyPath, sizeof(keyPath),
                  "SOFTWARE\\Classes\\CLSID", TEST_CLSID);

    HKEY hKey = NULL;
    LONG lRes = RegCreateKeyExA(HKEY_LOCAL_MACHINE, keyPath,
                                0, nullptr, REG_OPTION_NON_VOLATILE,
                                KEY_WRITE, nullptr, &hKey, nullptr);
    if (lRes != ERROR_SUCCESS) {
        printf("[STEP 1] HKLM write failed (error %ld) — admin required.\n"
               "         This is expected on a standard-user account.\n"
               "         Continuing with HKCU-only demonstration.\n\n",
               lRes);
        return false;
    }

    RegSetValueExA(hKey, nullptr, 0, REG_SZ,
                   (const BYTE*)HKLM_DLL,
                   (DWORD)(strlen(HKLM_DLL) + 1));
    RegCloseKey(hKey);

    printf("[STEP 1] HKLM setup: HKLM\\%s\n"
           "         -> \"%s\"\n\n", keyPath, HKLM_DLL);
    return true;
}

// ---------------------------------------------------------------------------
// Step 2 — Hijack: write HKCU override (no admin needed)
// ---------------------------------------------------------------------------
static void WriteHijackEntry()
{
    char keyPath[512];
    BuildCLSIDKey(keyPath, sizeof(keyPath),
                  "SOFTWARE\\Classes\\CLSID", TEST_CLSID);

    HKEY hKey = NULL;
    LONG lRes = RegCreateKeyExA(HKEY_CURRENT_USER, keyPath,
                                0, nullptr, REG_OPTION_NON_VOLATILE,
                                KEY_WRITE, nullptr, &hKey, nullptr);
    if (lRes != ERROR_SUCCESS) {
        printf("[STEP 2] HKCU write failed: error %ld\n\n", lRes);
        return;
    }

    RegSetValueExA(hKey, nullptr, 0, REG_SZ,
                   (const BYTE*)HKCU_DLL,
                   (DWORD)(strlen(HKCU_DLL) + 1));
    RegCloseKey(hKey);

    printf("[STEP 2] HIJACK WRITTEN (no admin needed):\n"
           "         HKCU\\%s\n"
           "         -> \"%s\"\n\n", keyPath, HKCU_DLL);
}

// ---------------------------------------------------------------------------
// Step 3 — Verify: read back both keys, show COM resolution order
// ---------------------------------------------------------------------------
static void VerifyPrecedence(bool hklmWritten)
{
    printf("[STEP 3] COM Resolution Order Verification\n");
    printf("         COM checks HKCU before HKLM — HKCU wins:\n\n");

    // Read HKCU
    char hkcuKey[512];
    BuildCLSIDKey(hkcuKey, sizeof(hkcuKey),
                  "SOFTWARE\\Classes\\CLSID", TEST_CLSID);

    HKEY hKey = NULL;
    char valBuf[512] = {};
    DWORD valLen = sizeof(valBuf);
    LONG lRes = RegOpenKeyExA(HKEY_CURRENT_USER, hkcuKey, 0, KEY_READ, &hKey);
    if (lRes == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, nullptr, nullptr, nullptr,
                         (BYTE*)valBuf, &valLen);
        RegCloseKey(hKey);
        printf("         HKCU: \"%s\"  <-- LOADED (hijack active)\n", valBuf);
    } else {
        printf("         HKCU: (not found)\n");
    }

    // Read HKLM
    if (hklmWritten) {
        char hklmKey[512];
        BuildCLSIDKey(hklmKey, sizeof(hklmKey),
                      "SOFTWARE\\Classes\\CLSID", TEST_CLSID);
        lRes = RegOpenKeyExA(HKEY_LOCAL_MACHINE, hklmKey, 0, KEY_READ, &hKey);
        if (lRes == ERROR_SUCCESS) {
            memset(valBuf, 0, sizeof(valBuf));
            valLen = sizeof(valBuf);
            RegQueryValueExA(hKey, nullptr, nullptr, nullptr,
                             (BYTE*)valBuf, &valLen);
            RegCloseKey(hKey);
            printf("         HKLM: \"%s\"  <-- ignored (HKCU wins)\n", valBuf);
        }
    }
    printf("\n");
}

// ---------------------------------------------------------------------------
// Step 4 — Detection: enumerate HKCU CLSID keys, check for HKLM shadow
//           This is blue-team logic: flag every HKCU CLSID that also has
//           an HKLM entry (potential hijack or at minimum suspicious).
// ---------------------------------------------------------------------------
static void DetectionScan()
{
    printf("[STEP 4] Blue Team Detection Scan\n");
    printf("         Enumerating HKCU\\SOFTWARE\\Classes\\CLSID...\n\n");
    printf("         %-44s  %-25s  %s\n", "CLSID", "HKCU Path", "HKLM Exists?");
    printf("         %-44s  %-25s  %s\n",
           "--------------------------------------------",
           "-------------------------",
           "------------");

    HKEY hHKCU = NULL;
    LONG lRes = RegOpenKeyExA(HKEY_CURRENT_USER,
                              "SOFTWARE\\Classes\\CLSID",
                              0, KEY_READ, &hHKCU);
    if (lRes != ERROR_SUCCESS) {
        printf("         (HKCU\\SOFTWARE\\Classes\\CLSID not found — nothing to scan)\n\n");
        return;
    }

    char clsidName[256];
    DWORD idx = 0;
    DWORD nameLen = sizeof(clsidName);
    int   hitCount = 0;

    while (RegEnumKeyExA(hHKCU, idx, clsidName, &nameLen,
                         nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS)
    {
        // Read HKCU InprocServer32 default value
        char hkcuSub[512];
        snprintf(hkcuSub, sizeof(hkcuSub),
                 "%s\\InprocServer32", clsidName);

        HKEY hSub = NULL;
        char hkcuVal[MAX_PATH] = "(no InprocServer32)";
        DWORD vLen = sizeof(hkcuVal);

        if (RegOpenKeyExA(hHKCU, hkcuSub, 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
            RegQueryValueExA(hSub, nullptr, nullptr, nullptr,
                             (BYTE*)hkcuVal, &vLen);
            RegCloseKey(hSub);
        }

        // Truncate path for display
        char shortPath[26] = {};
        strncpy(shortPath, hkcuVal, 25);
        if (strlen(hkcuVal) > 25) {
            shortPath[22] = '.';
            shortPath[23] = '.';
            shortPath[24] = '.';
            shortPath[25] = '\0';
        }

        // Check if HKLM shadow exists
        char hklmSub[512];
        snprintf(hklmSub, sizeof(hklmSub),
                 "SOFTWARE\\Classes\\CLSID\\%s", clsidName);
        HKEY hHKLM = NULL;
        bool hklmExists = (RegOpenKeyExA(HKEY_LOCAL_MACHINE, hklmSub,
                                         0, KEY_READ, &hHKLM) == ERROR_SUCCESS);
        if (hklmExists) RegCloseKey(hHKLM);

        printf("         %-44s  %-25s  %s\n",
               clsidName, shortPath,
               hklmExists ? "YES  <-- POTENTIAL HIJACK" : "no");
        hitCount++;

        // Reset for next iteration
        nameLen = sizeof(clsidName);
        idx++;
    }

    RegCloseKey(hHKCU);

    if (hitCount == 0)
        printf("         (no CLSID entries found in HKCU)\n");

    printf("\n         [Detection] %d HKCU CLSID entr%s found.\n"
               "         Entries with 'YES' shadow HKLM — investigate each DLL path.\n\n",
           hitCount, hitCount == 1 ? "y" : "ies");
}

// ---------------------------------------------------------------------------
// Step 5 — Cleanup: remove both registry entries
// ---------------------------------------------------------------------------
static void Cleanup(bool hklmWritten)
{
    printf("[STEP 5] Cleanup\n");

    // Remove HKCU hijack
    char hkcuBase[512];
    snprintf(hkcuBase, sizeof(hkcuBase),
             "SOFTWARE\\Classes\\CLSID\\%s", TEST_CLSID);
    LONG lRes = RegDeleteTreeA(HKEY_CURRENT_USER, hkcuBase);
    if (lRes == ERROR_SUCCESS || lRes == ERROR_FILE_NOT_FOUND)
        printf("         HKCU entry removed.\n");
    else
        printf("         HKCU removal failed: error %ld\n", lRes);

    // Remove HKLM test entry (only if we wrote it)
    if (hklmWritten) {
        char hklmBase[512];
        snprintf(hklmBase, sizeof(hklmBase),
                 "SOFTWARE\\Classes\\CLSID\\%s", TEST_CLSID);
        lRes = RegDeleteTreeA(HKEY_LOCAL_MACHINE, hklmBase);
        if (lRes == ERROR_SUCCESS || lRes == ERROR_FILE_NOT_FOUND)
            printf("         HKLM entry removed.\n");
        else
            printf("         HKLM removal failed: error %ld\n", lRes);
    }

    printf("\n");
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main()
{
    printf("=========================================================\n");
    printf(" COM Hijack Simulation — Authorized Security Testing\n");
    printf("=========================================================\n");
    printf(" Test CLSID: %s\n\n", TEST_CLSID);

    printf(" THEORY:\n"
           "   Malware writes HKCU\\SOFTWARE\\Classes\\CLSID\\{X}\\InprocServer32\n"
           "   pointing to its own DLL. COM loader checks HKCU before HKLM,\n"
           "   so any process loading class X will load the malicious DLL.\n"
           "   No admin rights required — HKCU is always user-writable.\n\n"
           " DETECTION: Sysmon Event ID 13 (RegistryEvent: SetValue)\n"
           "   Filter: TargetObject contains HKCU\\SOFTWARE\\Classes\\CLSID\n\n");
    printf("---------------------------------------------------------\n\n");

    // Step 1: setup HKLM (admin only — may fail gracefully)
    bool hklmWritten = SetupHKLMEntry();

    // Step 2: write HKCU hijack (no admin needed)
    WriteHijackEntry();

    // Step 3: verify COM resolution order
    VerifyPrecedence(hklmWritten);

    // Step 4: blue-team detection scan
    DetectionScan();

    // Step 5: cleanup
    Cleanup(hklmWritten);

    printf("=========================================================\n");
    printf(" Simulation complete. All test registry keys removed.\n");
    printf("=========================================================\n");

    return 0;
}
