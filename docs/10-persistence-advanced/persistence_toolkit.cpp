/*
  Persistence Toolkit — Module 10 Standalone Tool
  =================================================
  Authorized security testing / blue-team curriculum only.
  Run only on machines and accounts you own.

  Usage:
    persistence_toolkit.exe scan           -- audit all persistence locations
    persistence_toolkit.exe install run    -- add HKCU Run key entry
    persistence_toolkit.exe install com    -- COM hijack (ShellLink CLSID in HKCU)
    persistence_toolkit.exe install sched  -- create logon scheduled task
    persistence_toolkit.exe remove run     -- remove Run key entry
    persistence_toolkit.exe remove com     -- remove COM hijack key
    persistence_toolkit.exe remove sched   -- delete scheduled task

  Compile:
    g++ -std=c++17 -Wall -o persistence_toolkit.exe persistence_toolkit.cpp \
        -ladvapi32 -lole32 -loleaut32 -lwbemuuid -ltaskschd

  Output format for scan: [TYPE] location = value
*/

#define _WIN32_DCOM
#include <windows.h>
#include <wbemidl.h>
#include <taskschd.h>
#include <comdef.h>
#include <psapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

// ── constants ────────────────────────────────────────────────────────────────
// ShellLink CLSID — well-known, safe for demonstration
static const char*    COM_CLSID      = "{7C857801-7381-11CF-884D-00AA004B2E24}";
static const wchar_t* TASK_NAME      = L"SecurityTool_M10";
static const char*    RUN_VALUE_NAME = "SecurityTool_M10";

// ─────────────────────────────────────────────────────────────────────────────
// Utility
// ─────────────────────────────────────────────────────────────────────────────
static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

static bool startsWithCI(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && toLower(s.substr(0, p.size())) == toLower(p);
}

static void printHR(const char* label, HRESULT hr) {
    _com_error e(hr);
    std::cerr << "  [ERR:" << label << "] hr=0x" << std::hex << (unsigned long)hr
              << std::dec << "  " << e.ErrorMessage() << "\n";
}

static void printW32(const char* label, DWORD err = GetLastError()) {
    char msg[256] = {};
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, err, 0, msg, sizeof(msg), nullptr);
    for (int i = (int)strlen(msg)-1; i >= 0 && (msg[i]=='\r'||msg[i]=='\n'); --i) msg[i]='\0';
    std::cerr << "  [ERR:" << label << "] " << err << ": " << msg << "\n";
}

// Get current executable path
static std::string getCurrentExePath() {
    char buf[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, buf, MAX_PATH);
    return std::string(buf);
}

// ─────────────────────────────────────────────────────────────────────────────
// Registry helpers
// ─────────────────────────────────────────────────────────────────────────────
static std::string readRegSZ(HKEY root, const char* subkey, const char* val = "") {
    HKEY hk = nullptr;
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hk) != ERROR_SUCCESS) return "";
    char  buf[1024] = {};
    DWORD type = REG_SZ, size = sizeof(buf);
    LONG rc = RegQueryValueExA(hk, val, nullptr, &type, (LPBYTE)buf, &size);
    RegCloseKey(hk);
    return rc == ERROR_SUCCESS ? std::string(buf) : "";
}

static bool writeRegSZ(HKEY root, const char* subkey,
                       const char* valueName, const std::string& data) {
    HKEY hk = nullptr;
    LONG rc = RegCreateKeyExA(root, subkey, 0, nullptr,
                              REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
                              nullptr, &hk, nullptr);
    if (rc != ERROR_SUCCESS) { printW32("RegCreateKeyExA", rc); return false; }
    rc = RegSetValueExA(hk, valueName, 0, REG_SZ,
                        reinterpret_cast<const BYTE*>(data.c_str()),
                        static_cast<DWORD>(data.size() + 1));
    RegCloseKey(hk);
    if (rc != ERROR_SUCCESS) { printW32("RegSetValueExA", rc); return false; }
    return true;
}

static bool deleteRegTree(HKEY root, const char* subkey) {
    LONG rc = RegDeleteTreeA(root, subkey);
    if (rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND) return true;
    printW32("RegDeleteTreeA", rc);
    return false;
}

static bool deleteRegValue(HKEY root, const char* subkey, const char* valueName) {
    HKEY hk = nullptr;
    LONG rc = RegOpenKeyExA(root, subkey, 0, KEY_SET_VALUE, &hk);
    if (rc == ERROR_FILE_NOT_FOUND) return true; // already gone
    if (rc != ERROR_SUCCESS) { printW32("RegOpenKeyExA", rc); return false; }
    rc = RegDeleteValueA(hk, valueName);
    RegCloseKey(hk);
    if (rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND) return true;
    printW32("RegDeleteValueA", rc);
    return false;
}

static std::vector<std::pair<std::string,std::string>>
    enumValues(HKEY root, const char* subkey) {
    std::vector<std::pair<std::string,std::string>> result;
    HKEY hk = nullptr;
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hk) != ERROR_SUCCESS) return result;
    DWORD idx = 0;
    char  name[256]; DWORD nameLen;
    char  data[1024]; DWORD dataLen;
    DWORD type;
    while (true) {
        nameLen = sizeof(name); dataLen = sizeof(data);
        LONG rc = RegEnumValueA(hk, idx++, name, &nameLen, nullptr, &type,
                                (LPBYTE)data, &dataLen);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ))
            result.push_back({std::string(name,nameLen), std::string(data)});
    }
    RegCloseKey(hk);
    return result;
}

static std::vector<std::string> enumSubkeys(HKEY root, const char* subkey) {
    std::vector<std::string> result;
    HKEY hk = nullptr;
    if (RegOpenKeyExA(root, subkey, 0, KEY_ENUMERATE_SUB_KEYS, &hk) != ERROR_SUCCESS) return result;
    char  name[256]; DWORD idx = 0, nameLen;
    while (true) {
        nameLen = sizeof(name);
        LONG rc = RegEnumKeyExA(hk, idx++, name, &nameLen,
                                nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc == ERROR_SUCCESS) result.emplace_back(name, nameLen);
    }
    RegCloseKey(hk);
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// COM / WMI helper: connect to a namespace
// ─────────────────────────────────────────────────────────────────────────────
static IWbemServices* wmiConnect(const wchar_t* ns) {
    IWbemLocator* pLoc = nullptr;
    if (FAILED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                IID_IWbemLocator, (void**)&pLoc))) return nullptr;
    BSTR bNs = SysAllocString(ns);
    IWbemServices* pSvc = nullptr;
    HRESULT hr = pLoc->ConnectServer(bNs, nullptr, nullptr, nullptr,
                                     0, nullptr, nullptr, &pSvc);
    SysFreeString(bNs);
    pLoc->Release();
    if (FAILED(hr)) return nullptr;
    CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                      RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                      nullptr, EOAC_NONE);
    return pSvc;
}

// ─────────────────────────────────────────────────────────────────────────────
// SCAN — checks all persistence locations
// ─────────────────────────────────────────────────────────────────────────────
static void scan() {
    std::cout << "=== PERSISTENCE SCAN ===\n\n";

    // ── Run keys ─────────────────────────────────────────────────────────────
    struct RunKey { HKEY root; const char* rootStr; const char* sub; };
    RunKey runKeys[] = {
        { HKEY_CURRENT_USER,  "HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\Run"     },
        { HKEY_CURRENT_USER,  "HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
        { HKEY_LOCAL_MACHINE, "HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"     },
        { HKEY_LOCAL_MACHINE, "HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
    };
    for (const auto& rk : runKeys) {
        auto vals = enumValues(rk.root, rk.sub);
        for (const auto& kv : vals)
            std::cout << "[RUN_KEY] " << rk.rootStr << "\\" << rk.sub
                      << " | " << kv.first << " = " << kv.second << "\n";
    }

    // ── Startup folders ───────────────────────────────────────────────────────
    char appData[MAX_PATH] = {}, programData[MAX_PATH] = {};
    GetEnvironmentVariableA("APPDATA",     appData,     sizeof(appData));
    GetEnvironmentVariableA("PROGRAMDATA", programData, sizeof(programData));

    auto scanFolder = [](const std::string& dir, const char* label) {
        WIN32_FIND_DATAA fd = {};
        HANDLE h = FindFirstFileA((dir + "\\*").c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) return;
        do {
            if (fd.cFileName[0] == '.') continue;
            std::cout << "[STARTUP] " << label << " = " << fd.cFileName << "\n";
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    };
    scanFolder(std::string(appData) + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
               "User Startup");
    scanFolder(std::string(programData) + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
               "AllUsers Startup");

    // ── IFEO debugger keys ───────────────────────────────────────────────────
    const char* ifeoBase = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    for (const auto& exe : enumSubkeys(HKEY_LOCAL_MACHINE, ifeoBase)) {
        std::string dbg = readRegSZ(HKEY_LOCAL_MACHINE,
                                    (std::string(ifeoBase) + "\\" + exe).c_str(),
                                    "Debugger");
        if (!dbg.empty())
            std::cout << "[IFEO] " << exe << " = " << dbg << "\n";
    }

    // ── AppInit_DLLs ─────────────────────────────────────────────────────────
    std::string appInit = readRegSZ(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", "AppInit_DLLs");
    if (!appInit.empty())
        std::cout << "[APPINIT] AppInit_DLLs = " << appInit << "\n";

    // ── HKCU COM overrides ───────────────────────────────────────────────────
    for (const auto& clsid : enumSubkeys(HKEY_CURRENT_USER, "SOFTWARE\\Classes\\CLSID")) {
        std::string sub = "SOFTWARE\\Classes\\CLSID\\" + clsid + "\\InprocServer32";
        std::string val = readRegSZ(HKEY_CURRENT_USER, sub.c_str());
        if (!val.empty())
            std::cout << "[COM_HIJACK] HKCU CLSID " << clsid << " InprocServer32 = " << val << "\n";
    }

    // ── Services ─────────────────────────────────────────────────────────────
    SC_HANDLE hSCM = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (hSCM) {
        DWORD bytesNeeded = 0, returned = 0, resume = 0;
        EnumServicesStatusExA(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                              nullptr, 0, &bytesNeeded, &returned, &resume, nullptr);
        std::vector<BYTE> buf(bytesNeeded);
        resume = 0;
        if (EnumServicesStatusExA(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                                  buf.data(), bytesNeeded, &bytesNeeded, &returned, &resume, nullptr)) {
            auto* svcs = reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESS>(buf.data());
            for (DWORD i = 0; i < returned; ++i) {
                SC_HANDLE hSvc = OpenServiceA(hSCM, svcs[i].lpServiceName, SERVICE_QUERY_CONFIG);
                if (!hSvc) continue;
                DWORD cb = 0;
                QueryServiceConfigA(hSvc, nullptr, 0, &cb);
                if (cb) {
                    std::vector<BYTE> cfgBuf(cb);
                    auto* cfg = reinterpret_cast<LPQUERY_SERVICE_CONFIGA>(cfgBuf.data());
                    if (QueryServiceConfigA(hSvc, cfg, cb, &cb)) {
                        std::string bp = cfg->lpBinaryPathName ? cfg->lpBinaryPathName : "";
                        if (!bp.empty() && bp[0] == '"') bp = bp.substr(1);
                        bool inWin = startsWithCI(bp, "C:\\Windows\\") ||
                                     startsWithCI(bp, "%SystemRoot%") ||
                                     startsWithCI(bp, "%windir%");
                        if (!inWin)
                            std::cout << "[SERVICE] " << svcs[i].lpServiceName
                                      << " = " << cfg->lpBinaryPathName << "\n";
                    }
                }
                CloseServiceHandle(hSvc);
            }
        }
        CloseServiceHandle(hSCM);
    }

    // ── WMI CommandLineEventConsumer ─────────────────────────────────────────
    IWbemServices* pSvc = wmiConnect(L"ROOT\\SUBSCRIPTION");
    if (pSvc) {
        BSTR clsName = SysAllocString(L"CommandLineEventConsumer");
        IEnumWbemClassObject* pEnum = nullptr;
        if (SUCCEEDED(pSvc->CreateInstanceEnum(clsName,
                      WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                      nullptr, &pEnum))) {
            IWbemClassObject* pObj = nullptr;
            ULONG got = 0;
            while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &got) == WBEM_S_NO_ERROR && got > 0) {
                VARIANT vName, vCmd;
                VariantInit(&vName); VariantInit(&vCmd);
                pObj->Get(L"Name",                0, &vName, nullptr, nullptr);
                pObj->Get(L"CommandLineTemplate", 0, &vCmd,  nullptr, nullptr);
                if (vName.vt == VT_BSTR && vName.bstrVal) {
                    std::wstring wn(vName.bstrVal);
                    std::string  name(wn.begin(), wn.end());
                    std::string  cmd;
                    if (vCmd.vt == VT_BSTR && vCmd.bstrVal) {
                        std::wstring wc(vCmd.bstrVal);
                        cmd = std::string(wc.begin(), wc.end());
                    }
                    std::cout << "[WMI_SUB] CommandLineEventConsumer Name=" << name
                              << " Cmd=" << cmd << "\n";
                }
                VariantClear(&vName); VariantClear(&vCmd);
                pObj->Release();
            }
            pEnum->Release();
        }
        SysFreeString(clsName);
        pSvc->Release();
    }

    std::cout << "\n=== END SCAN ===\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// INSTALL RUN — HKCU Run key pointing to current exe
// ─────────────────────────────────────────────────────────────────────────────
static int installRun() {
    std::string exePath = getCurrentExePath();
    const char* subkey  = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    std::cout << "[install run] Writing HKCU Run key ...\n"
              << "  Name: " << RUN_VALUE_NAME << "\n"
              << "  Path: " << exePath << "\n";
    if (!writeRegSZ(HKEY_CURRENT_USER, subkey, RUN_VALUE_NAME, exePath)) return 1;
    std::cout << "[+] Run key written.\n";
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// INSTALL COM — HKCU CLSID InprocServer32 override
// ─────────────────────────────────────────────────────────────────────────────
static int installCOM() {
    std::string exePath  = getCurrentExePath();
    // For a real hijack, payload would be a DLL. We record current exe path as demo.
    std::string subkey   = std::string("SOFTWARE\\Classes\\CLSID\\") + COM_CLSID + "\\InprocServer32";
    std::cout << "[install com] Writing HKCU COM override ...\n"
              << "  CLSID  : " << COM_CLSID << "\n"
              << "  Payload: " << exePath << "\n";
    if (!writeRegSZ(HKEY_CURRENT_USER, subkey.c_str(), "", exePath)) return 1;
    std::cout << "[+] HKCU CLSID override written.\n"
              << "  Remove: persistence_toolkit.exe remove com\n";
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// INSTALL SCHED — logon scheduled task running current exe
// ─────────────────────────────────────────────────────────────────────────────
static int installSched() {
    std::string exePath = getCurrentExePath();
    std::wstring wExePath(exePath.begin(), exePath.end());

    std::cout << "[install sched] Creating scheduled task '" ;
    std::wcout << TASK_NAME;
    std::cout << "' ...\n  Exe: " << exePath << "\n";

    ITaskService* pSvc = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, nullptr,
                                  CLSCTX_INPROC_SERVER,
                                  IID_ITaskService, (void**)&pSvc);
    if (FAILED(hr)) { printHR("CoCreateInstance(TaskScheduler)", hr); return 1; }

    hr = pSvc->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) { printHR("ITaskService::Connect", hr); pSvc->Release(); return 1; }

    ITaskFolder* pRoot = nullptr;
    hr = pSvc->GetFolder(_bstr_t(L"\\"), &pRoot);
    if (FAILED(hr)) { printHR("GetFolder", hr); pSvc->Release(); return 1; }

    ITaskDefinition* pDef = nullptr;
    hr = pSvc->NewTask(0, &pDef);
    if (FAILED(hr)) { printHR("NewTask", hr); pRoot->Release(); pSvc->Release(); return 1; }

    // Registration info
    IRegistrationInfo* pRegInfo = nullptr;
    pDef->get_RegistrationInfo(&pRegInfo);
    if (pRegInfo) {
        pRegInfo->put_Description(_bstr_t(L"Module 10 persistence demo (remove when done)"));
        pRegInfo->Release();
    }

    // Logon trigger
    ITriggerCollection* pTrigColl = nullptr;
    pDef->get_Triggers(&pTrigColl);
    if (pTrigColl) {
        ITrigger* pTrig = nullptr;
        pTrigColl->Create(TASK_TRIGGER_LOGON, &pTrig);
        if (pTrig) {
            ILogonTrigger* pLogon = nullptr;
            pTrig->QueryInterface(IID_ILogonTrigger, (void**)&pLogon);
            if (pLogon) {
                pLogon->put_Id(_bstr_t(L"T1"));
                pLogon->Release();
            }
            pTrig->Release();
        }
        pTrigColl->Release();
    }

    // Exec action
    IActionCollection* pActColl = nullptr;
    pDef->get_Actions(&pActColl);
    if (pActColl) {
        IAction* pAct = nullptr;
        pActColl->Create(TASK_ACTION_EXEC, &pAct);
        if (pAct) {
            IExecAction* pExec = nullptr;
            pAct->QueryInterface(IID_IExecAction, (void**)&pExec);
            if (pExec) {
                pExec->put_Path(_bstr_t(wExePath.c_str()));
                pExec->put_Arguments(_bstr_t(L"scan"));
                pExec->Release();
            }
            pAct->Release();
        }
        pActColl->Release();
    }

    // Settings
    ITaskSettings* pSettings = nullptr;
    pDef->get_Settings(&pSettings);
    if (pSettings) {
        pSettings->put_Hidden(VARIANT_TRUE);
        pSettings->put_StartWhenAvailable(VARIANT_TRUE);
        pSettings->Release();
    }

    // Register
    IRegisteredTask* pRegTask = nullptr;
    hr = pRoot->RegisterTaskDefinition(
        _bstr_t(TASK_NAME),
        pDef,
        TASK_CREATE_OR_UPDATE,
        _variant_t(), _variant_t(),
        TASK_LOGON_INTERACTIVE_TOKEN,
        _variant_t(L""),
        &pRegTask);

    if (pRegTask) pRegTask->Release();
    pDef->Release();
    pRoot->Release();
    pSvc->Release();

    if (FAILED(hr)) { printHR("RegisterTaskDefinition", hr); return 1; }

    std::cout << "[+] Scheduled task created.\n"
              << "  Remove: persistence_toolkit.exe remove sched\n";
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// REMOVE RUN
// ─────────────────────────────────────────────────────────────────────────────
static int removeRun() {
    const char* subkey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    std::cout << "[remove run] Deleting '" << RUN_VALUE_NAME << "' from HKCU Run ...\n";
    if (!deleteRegValue(HKEY_CURRENT_USER, subkey, RUN_VALUE_NAME)) return 1;
    std::cout << "[+] Done.\n";
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// REMOVE COM
// ─────────────────────────────────────────────────────────────────────────────
static int removeCOM() {
    std::string keyPath = std::string("SOFTWARE\\Classes\\CLSID\\") + COM_CLSID;
    std::cout << "[remove com] Removing HKCU\\SOFTWARE\\Classes\\CLSID\\" << COM_CLSID << " ...\n";
    if (!deleteRegTree(HKEY_CURRENT_USER, keyPath.c_str())) return 1;
    std::cout << "[+] Done.\n";
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// REMOVE SCHED
// ─────────────────────────────────────────────────────────────────────────────
static int removeSched() {
    std::cout << "[remove sched] Deleting task '";
    std::wcout << TASK_NAME;
    std::cout << "' ...\n";

    ITaskService* pSvc = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, nullptr,
                                  CLSCTX_INPROC_SERVER,
                                  IID_ITaskService, (void**)&pSvc);
    if (FAILED(hr)) { printHR("CoCreateInstance(TaskScheduler)", hr); return 1; }

    hr = pSvc->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) { printHR("ITaskService::Connect", hr); pSvc->Release(); return 1; }

    ITaskFolder* pRoot = nullptr;
    hr = pSvc->GetFolder(_bstr_t(L"\\"), &pRoot);
    if (FAILED(hr)) { printHR("GetFolder", hr); pSvc->Release(); return 1; }

    hr = pRoot->DeleteTask(_bstr_t(TASK_NAME), 0);
    pRoot->Release();
    pSvc->Release();

    if (hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
        std::cout << "  Task not found — already removed.\n";
        return 0;
    }
    if (FAILED(hr)) { printHR("DeleteTask", hr); return 1; }
    std::cout << "[+] Task deleted.\n";
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
static void usage(const char* prog) {
    std::cerr << "Usage:\n"
              << "  " << prog << " scan\n"
              << "  " << prog << " install run|com|sched\n"
              << "  " << prog << " remove  run|com|sched\n";
}

// ─────────────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    std::cout << "=== Persistence Toolkit — Module 10 ===\n\n";

    if (argc < 2) { usage(argv[0]); return 1; }

    // Initialize COM for the whole process
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        std::cerr << "CoInitializeEx failed.\n"; return 1;
    }
    CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                         RPC_C_AUTHN_LEVEL_DEFAULT,
                         RPC_C_IMP_LEVEL_IMPERSONATE,
                         nullptr, EOAC_NONE, nullptr);

    std::string verb = argv[1];
    std::string noun = argc >= 3 ? argv[2] : "";

    int rc = 0;

    if (verb == "scan") {
        scan();
    } else if (verb == "install") {
        if      (noun == "run")   rc = installRun();
        else if (noun == "com")   rc = installCOM();
        else if (noun == "sched") rc = installSched();
        else { usage(argv[0]); rc = 1; }
    } else if (verb == "remove") {
        if      (noun == "run")   rc = removeRun();
        else if (noun == "com")   rc = removeCOM();
        else if (noun == "sched") rc = removeSched();
        else { usage(argv[0]); rc = 1; }
    } else {
        usage(argv[0]);
        rc = 1;
    }

    CoUninitialize();
    return rc;
}
