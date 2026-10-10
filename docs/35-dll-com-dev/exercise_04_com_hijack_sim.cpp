/*
 * Module 35 — Exercise 04: COM Hijack Persistence Simulation (Skeleton)
 * =======================================================================
 * FOR EDUCATIONAL / AUTHORIZED-LAB USE ONLY.
 * Simulate a COM hijack against a test CLSID you control.
 * Never run against production systems or CLSIDs you do not own.
 *
 * Learning objectives:
 *   - Read HKLM CLSID InprocServer32 registry values
 *   - Write a per-user HKCU override that takes priority over HKLM
 *   - Understand the HKCU → HKCR lookup order used by CoCreateInstance
 *   - Enumerate hijack entries to confirm the override is in place
 *   - Clean up and verify cleanup
 *   - Understand blue team detection (Sysmon Event 13)
 *
 * This exercise uses a "test" CLSID that you register yourself.
 * The test CLSID is: {DEADBEEF-DEAD-BEEF-DEAD-BEEFDEADBEEF}
 * It is not registered anywhere by default — this exercise creates it.
 *
 * Compile (MinGW / g++):
 *   g++ -std=c++17 -Wall -o ex04.exe exercise_04_com_hijack_sim.cpp -ladvapi32
 *
 * Run from an elevated prompt (to write HKLM) or adjust to HKCU for unprivileged demo.
 *   .\ex04.exe
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <string>

// ---------------------------------------------------------------------------
// Test CLSID — you own this; it is not used by any real Windows component
// ---------------------------------------------------------------------------
// {DEADBEEF-DEAD-BEEF-DEAD-BEEFDEADBEEF}
static const char TARGET_CLSID[] = "{DEADBEEF-DEAD-BEEF-DEAD-BEEFDEADBEEF}";

// Registry paths
static const char HKLM_CLSID_BASE[]  = "SOFTWARE\\Classes\\CLSID\\";
static const char HKCU_CLSID_BASE[]  = "SOFTWARE\\Classes\\CLSID\\";
static const char INPROC_SUBKEY[]    = "\\InprocServer32";

// Simulated DLL paths
static const char LEGITIMATE_DLL[]   = "C:\\Program Files\\TestApp\\legitimate.dll";
static const char HIJACK_DLL[]       = "C:\\Users\\Public\\hijack.dll";

// ---------------------------------------------------------------------------
// Helper: build a full registry path for a CLSID subkey
// ---------------------------------------------------------------------------
static std::string MakePath(const char* base, const char* clsid, const char* sub)
{
    return std::string(base) + clsid + sub;
}

// ---------------------------------------------------------------------------
// Step 1: Register the test CLSID in HKLM (simulates a legitimately installed component)
// ---------------------------------------------------------------------------
static bool RegisterLegitimateEntry()
{
    // TODO: Use RegCreateKeyExA to open/create:
    //   HKLM\SOFTWARE\Classes\CLSID\{DEADBEEF-...}\InprocServer32
    // Then use RegSetValueExA to set:
    //   (Default) = LEGITIMATE_DLL
    //   ThreadingModel = "Apartment"
    // Check return codes (ERROR_SUCCESS on success).
    // Hint:
    //   HKEY hKey = nullptr;
    //   std::string path = MakePath(HKLM_CLSID_BASE, TARGET_CLSID, INPROC_SUBKEY);
    //   LONG rc = RegCreateKeyExA(HKEY_LOCAL_MACHINE, path.c_str(), 0, nullptr,
    //                             REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr);
    //   if (rc != ERROR_SUCCESS) { printf("RegCreateKeyEx failed: %ld\n", rc); return false; }
    //   RegSetValueExA(hKey, nullptr, 0, REG_SZ,
    //                  (BYTE*)LEGITIMATE_DLL, (DWORD)strlen(LEGITIMATE_DLL)+1);
    //   RegSetValueExA(hKey, "ThreadingModel", 0, REG_SZ, (BYTE*)"Apartment", 10);
    //   RegCloseKey(hKey);
    //   return true;
    printf("[TODO] RegisterLegitimateEntry — implement me\n");
    return false;
}

// ---------------------------------------------------------------------------
// Step 2: Write the hijack entry in HKCU (no elevation needed)
// ---------------------------------------------------------------------------
static bool WriteHijackEntry()
{
    // TODO: Use RegCreateKeyExA on HKEY_CURRENT_USER to create:
    //   HKCU\SOFTWARE\Classes\CLSID\{DEADBEEF-...}\InprocServer32
    // Set (Default) = HIJACK_DLL, ThreadingModel = "Apartment"
    // Because HKCU is checked BEFORE HKCR (which merges HKLM), this overrides
    // the legitimate entry without any elevation.
    printf("[TODO] WriteHijackEntry — implement me\n");
    return false;
}

// ---------------------------------------------------------------------------
// Step 3: Verify the hijack by reading what CoCreateInstance would load
// ---------------------------------------------------------------------------
static void VerifyHijack()
{
    // TODO: Read HKCU\SOFTWARE\Classes\CLSID\{...}\InprocServer32 (Default).
    // Print: "HKCU override path: <value>"
    // Then read HKLM\SOFTWARE\Classes\CLSID\{...}\InprocServer32 (Default).
    // Print: "HKLM legitimate path: <value>"
    // Explain: when both exist, COM picks the HKCU one.
    // Hint:
    //   char val[MAX_PATH] = {};
    //   DWORD sz = sizeof(val);
    //   LONG rc = RegGetValueA(HKEY_CURRENT_USER, path.c_str(), nullptr,
    //                          RRF_RT_REG_SZ, nullptr, val, &sz);
    printf("[TODO] VerifyHijack — implement me\n");
}

// ---------------------------------------------------------------------------
// Step 4: Enumerate all HKCU CLSID entries to find overrides
// ---------------------------------------------------------------------------
static void DetectHijacks()
{
    // TODO: Open HKCU\SOFTWARE\Classes\CLSID and enumerate all subkeys.
    // For each subkey, check if the same CLSID exists in HKLM.
    // If it does in both HKCU and HKLM, flag it as a potential COM hijack.
    // Print:
    //   [HIJACK?] {CLSID}: HKCU=<hkcu_path>  HKLM=<hklm_path>
    // Hint: RegOpenKeyExA, RegEnumKeyExA, then RegQueryValueExA for each.
    printf("[TODO] DetectHijacks — implement me\n");
}

// ---------------------------------------------------------------------------
// Step 5: Clean up — remove both registry entries
// ---------------------------------------------------------------------------
static void Cleanup()
{
    // TODO: Use RegDeleteTreeA (or RegDeleteKeyA recursively) to remove:
    //   HKCU\SOFTWARE\Classes\CLSID\{DEADBEEF-...}
    //   HKLM\SOFTWARE\Classes\CLSID\{DEADBEEF-...}
    // Print success or error for each.
    // Note: RegDeleteTreeA requires Windows Vista+.
    printf("[TODO] Cleanup — implement me\n");
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main()
{
    printf("=== COM Hijack Simulation (Exercise 04) ===\n\n");
    printf("Target CLSID: %s\n\n", TARGET_CLSID);

    printf("[Step 1] Registering legitimate CLSID in HKLM...\n");
    if (!RegisterLegitimateEntry()) {
        printf("  Tip: Run as Administrator to write HKLM. Alternatively, change the\n");
        printf("  target key to HKCU in RegisterLegitimateEntry to avoid needing elevation.\n\n");
    }

    printf("[Step 2] Writing hijack entry in HKCU...\n");
    WriteHijackEntry();

    printf("\n[Step 3] Verifying hijack (which path would COM load?)...\n");
    VerifyHijack();

    printf("\n[Step 4] Enumerating all HKCU CLSID overrides (hijack detection)...\n");
    DetectHijacks();

    printf("\n[Step 5] Cleaning up...\n");
    Cleanup();

    printf("\nDone.\n");
    printf("\n--- Blue Team Notes ---\n");
    printf("Detection: Sysmon Event ID 13 (RegistryValueSet)\n");
    printf("  Filter: TargetObject contains '\\SOFTWARE\\Classes\\CLSID' AND\n");
    printf("          TargetObject contains 'InprocServer32'\n");
    printf("          EventType = SetValue\n");
    printf("  Alert when the hive is HKCU (no elevation needed by attacker).\n");
    printf("  Correlate the DLL path: unsigned, in user-writable directory = high severity.\n");
    return 0;
}
