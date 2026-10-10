/*
  Solution 04 — Persistence Detection Tool
  ==========================================
  Scans the most common persistence locations and prints all findings.
  Equivalent to a minimal Autoruns.exe / persistcheck.

  Checks performed:
    1.  HKCU + HKLM Run / RunOnce keys
    2.  User + AllUsers Startup folders
    3.  Scheduled tasks via ITaskService (Task Scheduler API)
    4.  Services with binary paths outside C:\Windows\
    5.  IFEO Debugger keys
    6.  AppInit_DLLs
    7.  HKCU COM CLSID overrides (potential hijacks)
    8.  WMI CommandLineEventConsumer subscriptions

  Compile:
    g++ -std=c++17 -Wall -o sol04.exe solutions/sol04_detection.cpp \
        -ladvapi32 -lole32 -loleaut32 -lwbemuuid -ltaskschd
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
#include <iomanip>

// ─────────────────────────────────────────────────────────────────────────────
// Utility
// ─────────────────────────────────────────────────────────────────────────────
static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

static bool startsWithCI(const std::string& str, const std::string& prefix) {
    if (str.size() < prefix.size()) return false;
    return toLower(str.substr(0, prefix.size())) == toLower(prefix);
}

static void printHR(const char* label, HRESULT hr) {
    _com_error err(hr);
    std::cerr << "  [WARN:" << label << "] 0x" << std::hex << (unsigned long)hr
              << std::dec << " " << err.ErrorMessage() << "\n";
}

static void printSectionHeader(const char* title) {
    std::string bar(60, '=');
    std::cout << "\n" << bar << "\n"
              << "  " << title << "\n"
              << bar << "\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// Registry helpers
// ─────────────────────────────────────────────────────────────────────────────
static std::string readRegSZ(HKEY root, const char* subkey, const char* val) {
    HKEY hk = nullptr;
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hk) != ERROR_SUCCESS) return "";
    char  buf[1024] = {};
    DWORD type = REG_SZ, size = sizeof(buf);
    LONG rc = RegQueryValueExA(hk, val, nullptr, &type, (LPBYTE)buf, &size);
    RegCloseKey(hk);
    return rc == ERROR_SUCCESS ? std::string(buf) : "";
}

// Enumerate all REG_SZ + REG_EXPAND_SZ values under a key
static std::vector<std::pair<std::string,std::string>>
    enumValues(HKEY root, const char* subkey) {
    std::vector<std::pair<std::string,std::string>> result;
    HKEY hk = nullptr;
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hk) != ERROR_SUCCESS) return result;

    DWORD idx = 0;
    char  name[256];
    char  data[1024];
    DWORD nameLen, dataLen, type;
    while (true) {
        nameLen = sizeof(name);
        dataLen = sizeof(data);
        LONG rc = RegEnumValueA(hk, idx++, name, &nameLen, nullptr, &type,
                                (LPBYTE)data, &dataLen);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ))
            result.push_back({std::string(name, nameLen), std::string(data)});
    }
    RegCloseKey(hk);
    return result;
}

// Enumerate immediate sub-key names
static std::vector<std::string> enumSubkeys(HKEY root, const char* subkey) {
    std::vector<std::string> result;
    HKEY hk = nullptr;
    if (RegOpenKeyExA(root, subkey, 0, KEY_ENUMERATE_SUB_KEYS, &hk) != ERROR_SUCCESS) return result;

    char  name[256];
    DWORD idx = 0, nameLen;
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
// 1. Run / RunOnce keys
// ─────────────────────────────────────────────────────────────────────────────
static void scanRunKeys() {
    printSectionHeader("1. RUN / RUNONCE KEYS");

    struct KeyDef { HKEY root; const char* rootName; const char* subkey; };
    KeyDef defs[] = {
        { HKEY_CURRENT_USER,  "HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\Run"     },
        { HKEY_CURRENT_USER,  "HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
        { HKEY_LOCAL_MACHINE, "HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"     },
        { HKEY_LOCAL_MACHINE, "HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
    };

    int total = 0;
    for (const auto& d : defs) {
        auto vals = enumValues(d.root, d.subkey);
        if (vals.empty()) continue;
        std::cout << "\n  [" << d.rootName << "\\" << d.subkey << "]\n";
        for (const auto& kv : vals) {
            ++total;
            bool suspicious = !startsWithCI(kv.second, "C:\\Windows\\") &&
                              !startsWithCI(kv.second, "C:\\Program Files") &&
                              !startsWithCI(kv.second, "C:\\Program Files (x86)");
            std::cout << "    " << kv.first << " = " << kv.second;
            if (suspicious) std::cout << "  ** SUSPICIOUS PATH **";
            std::cout << "\n";
        }
    }
    if (total == 0) std::cout << "  (none found)\n";
    std::cout << "  Total entries: " << total << "\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Startup folders
// ─────────────────────────────────────────────────────────────────────────────
static void scanFolder(const std::string& path, const std::string& label) {
    std::string mask = path + "\\*";
    WIN32_FIND_DATAA fd = {};
    HANDLE h = FindFirstFileA(mask.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) {
        std::cout << "  [" << label << "] (folder not accessible or empty)\n";
        return;
    }
    std::cout << "  [" << label << "]\n";
    int count = 0;
    do {
        if (fd.cFileName[0] == '.') continue;
        std::cout << "    " << fd.cFileName << "\n";
        ++count;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    if (count == 0) std::cout << "    (empty)\n";
}

static void scanStartupFolders() {
    printSectionHeader("2. STARTUP FOLDERS");

    char appData[MAX_PATH]     = {};
    char programData[MAX_PATH] = {};
    GetEnvironmentVariableA("APPDATA",     appData,     sizeof(appData));
    GetEnvironmentVariableA("PROGRAMDATA", programData, sizeof(programData));

    std::string userStartup =
        std::string(appData) + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
    std::string allStartup  =
        std::string(programData) + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";

    scanFolder(userStartup, "Current User Startup");
    scanFolder(allStartup,  "All Users Startup");
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Scheduled tasks via ITaskService
// ─────────────────────────────────────────────────────────────────────────────
static void printTaskActions(ITaskDefinition* pDef) {
    IActionCollection* pActions = nullptr;
    if (FAILED(pDef->get_Actions(&pActions)) || !pActions) return;
    LONG count = 0;
    pActions->get_Count(&count);
    for (LONG i = 1; i <= count; ++i) {
        IAction* pAct = nullptr;
        VARIANT idx;
        VariantInit(&idx);
        idx.vt   = VT_I4;
        idx.lVal = i;
        if (SUCCEEDED(pActions->get_Item(idx, &pAct)) && pAct) {
            TASK_ACTION_TYPE atype;
            pAct->get_Type(&atype);
            if (atype == TASK_ACTION_EXEC) {
                IExecAction* pExec = nullptr;
                if (SUCCEEDED(pAct->QueryInterface(IID_IExecAction, (void**)&pExec)) && pExec) {
                    BSTR path = nullptr;
                    pExec->get_Path(&path);
                    BSTR args = nullptr;
                    pExec->get_Arguments(&args);
                    std::cout << "      Action[" << i << "]: " << (path ? path : L"(null)");
                    if (args && wcslen(args)) std::wcout << L" " << args;
                    std::cout << "\n";
                    if (path) SysFreeString(path);
                    if (args) SysFreeString(args);
                    pExec->Release();
                }
            }
            pAct->Release();
        }
    }
    pActions->Release();
}

static void scanScheduledTasks() {
    printSectionHeader("3. SCHEDULED TASKS");

    ITaskService* pSvc = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, nullptr,
                                  CLSCTX_INPROC_SERVER,
                                  IID_ITaskService,
                                  reinterpret_cast<void**>(&pSvc));
    if (FAILED(hr)) { printHR("CoCreateInstance(TaskScheduler)", hr); return; }

    hr = pSvc->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) { printHR("ITaskService::Connect", hr); pSvc->Release(); return; }

    ITaskFolder* pRoot = nullptr;
    hr = pSvc->GetFolder(_bstr_t(L"\\"), &pRoot);
    if (FAILED(hr)) { printHR("GetFolder", hr); pSvc->Release(); return; }

    IRegisteredTaskCollection* pTasks = nullptr;
    hr = pRoot->GetTasks(0, &pTasks);
    if (FAILED(hr)) { printHR("GetTasks", hr); pRoot->Release(); pSvc->Release(); return; }

    LONG count = 0;
    pTasks->get_Count(&count);

    int printed = 0;
    for (LONG i = 1; i <= count; ++i) {
        IRegisteredTask* pTask = nullptr;
        VARIANT idx;
        VariantInit(&idx);
        idx.vt   = VT_I4;
        idx.lVal = i;
        if (FAILED(pTasks->get_Item(idx, &pTask)) || !pTask) continue;

        BSTR name = nullptr;
        pTask->get_Name(&name);

        TASK_STATE state;
        pTask->get_State(&state);
        bool enabled = (state != TASK_STATE_DISABLED);

        ITaskDefinition* pDef = nullptr;
        bool suspicious = false;
        if (SUCCEEDED(pTask->get_Definition(&pDef)) && pDef) {
            IActionCollection* pActs = nullptr;
            if (SUCCEEDED(pDef->get_Actions(&pActs)) && pActs) {
                LONG acnt = 0;
                pActs->get_Count(&acnt);
                for (LONG j = 1; j <= acnt; ++j) {
                    IAction* pAct = nullptr;
                    VARIANT jidx; VariantInit(&jidx); jidx.vt = VT_I4; jidx.lVal = j;
                    if (SUCCEEDED(pActs->get_Item(jidx, &pAct)) && pAct) {
                        TASK_ACTION_TYPE at; pAct->get_Type(&at);
                        if (at == TASK_ACTION_EXEC) {
                            IExecAction* pExec = nullptr;
                            if (SUCCEEDED(pAct->QueryInterface(IID_IExecAction,(void**)&pExec)) && pExec) {
                                BSTR p = nullptr; pExec->get_Path(&p);
                                if (p) {
                                    std::wstring wp(p);
                                    std::string sp(wp.begin(), wp.end());
                                    if (!startsWithCI(sp, "C:\\Windows\\") &&
                                        !startsWithCI(sp, "C:\\Program Files") &&
                                        !startsWithCI(sp, "%SystemRoot%") &&
                                        !sp.empty())
                                        suspicious = true;
                                    SysFreeString(p);
                                }
                                pExec->Release();
                            }
                        }
                        pAct->Release();
                    }
                }
                pActs->Release();
            }
        }

        if (suspicious || !enabled == false) { // print all; flag suspicious
            ++printed;
            std::wcout << L"  Task: " << (name ? name : L"(null)")
                       << (enabled ? L"" : L" [DISABLED]")
                       << (suspicious ? L"  ** NON-SYSTEM PATH **" : L"")
                       << L"\n";
            if (pDef) printTaskActions(pDef);
        }

        if (pDef)  pDef->Release();
        if (name)  SysFreeString(name);
        pTask->Release();
    }

    pTasks->Release();
    pRoot->Release();
    pSvc->Release();

    std::cout << "  Total tasks scanned: " << count << "\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Services with non-Windows binary paths
// ─────────────────────────────────────────────────────────────────────────────
static void scanServices() {
    printSectionHeader("4. SERVICES (non-Windows binary paths)");

    SC_HANDLE hSCM = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) {
        std::cerr << "  OpenSCManager failed: " << GetLastError() << "\n";
        return;
    }

    DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;
    EnumServicesStatusExA(hSCM, SC_ENUM_PROCESS_INFO,
                          SERVICE_WIN32, SERVICE_STATE_ALL,
                          nullptr, 0,
                          &bytesNeeded, &servicesReturned, &resumeHandle, nullptr);

    std::vector<BYTE> buf(bytesNeeded);
    resumeHandle = 0;
    if (!EnumServicesStatusExA(hSCM, SC_ENUM_PROCESS_INFO,
                               SERVICE_WIN32, SERVICE_STATE_ALL,
                               buf.data(), bytesNeeded,
                               &bytesNeeded, &servicesReturned, &resumeHandle, nullptr)) {
        CloseServiceHandle(hSCM);
        std::cerr << "  EnumServicesStatusExA failed: " << GetLastError() << "\n";
        return;
    }

    auto* pServices = reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESS>(buf.data());
    int flagged = 0;

    for (DWORD i = 0; i < servicesReturned; ++i) {
        SC_HANDLE hSvc = OpenServiceA(hSCM, pServices[i].lpServiceName, SERVICE_QUERY_CONFIG);
        if (!hSvc) continue;

        DWORD cbNeeded = 0;
        QueryServiceConfigA(hSvc, nullptr, 0, &cbNeeded);
        if (cbNeeded == 0) { CloseServiceHandle(hSvc); continue; }

        std::vector<BYTE> cfgBuf(cbNeeded);
        auto* pCfg = reinterpret_cast<LPQUERY_SERVICE_CONFIGA>(cfgBuf.data());
        if (!QueryServiceConfigA(hSvc, pCfg, cbNeeded, &cbNeeded)) {
            CloseServiceHandle(hSvc);
            continue;
        }

        std::string binPath = pCfg->lpBinaryPathName ? pCfg->lpBinaryPathName : "";
        // Strip leading quotes and svchost pattern
        if (!binPath.empty() && binPath[0] == '"') binPath = binPath.substr(1);

        bool inWindows = startsWithCI(binPath, "C:\\Windows\\") ||
                         startsWithCI(binPath, "%SystemRoot%") ||
                         startsWithCI(binPath, "%windir%");
        if (!inWindows && !binPath.empty()) {
            ++flagged;
            std::cout << "  [SVC] " << pServices[i].lpServiceName
                      << "\n        Path: " << pCfg->lpBinaryPathName << "\n";
        }
        CloseServiceHandle(hSvc);
    }

    CloseServiceHandle(hSCM);
    if (flagged == 0) std::cout << "  (none found outside C:\\Windows\\)\n";
    std::cout << "  Flagged: " << flagged << " / " << servicesReturned << " services\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. IFEO Debugger keys
// ─────────────────────────────────────────────────────────────────────────────
static void scanIFEO() {
    printSectionHeader("5. IFEO DEBUGGER KEYS");

    const char* base = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    auto exeNames = enumSubkeys(HKEY_LOCAL_MACHINE, base);

    int found = 0;
    for (const auto& exe : exeNames) {
        std::string subkey = std::string(base) + "\\" + exe;
        std::string debugger = readRegSZ(HKEY_LOCAL_MACHINE, subkey.c_str(), "Debugger");
        if (!debugger.empty()) {
            ++found;
            std::cout << "  [IFEO] " << exe << "\n"
                      << "         Debugger = " << debugger << "\n";
        }
    }
    if (found == 0) std::cout << "  (none found)\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. AppInit_DLLs
// ─────────────────────────────────────────────────────────────────────────────
static void scanAppInit() {
    printSectionHeader("6. APPINIT_DLLS");

    std::string val = readRegSZ(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
        "AppInit_DLLs");
    if (val.empty())
        std::cout << "  AppInit_DLLs = (empty — good)\n";
    else
        std::cout << "  AppInit_DLLs = " << val << "  ** SET **\n";

    // Also check the LoadAppInit_DLLs enable flag
    std::string enabled = readRegSZ(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
        "LoadAppInit_DLLs");
    std::cout << "  LoadAppInit_DLLs = " << (enabled.empty() ? "0" : enabled) << "\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. HKCU COM CLSID overrides
// ─────────────────────────────────────────────────────────────────────────────
static void scanCOMHijacks() {
    printSectionHeader("7. HKCU COM CLSID OVERRIDES (potential hijacks)");

    auto clsids = enumSubkeys(HKEY_CURRENT_USER, "SOFTWARE\\Classes\\CLSID");
    int found = 0;
    for (const auto& clsid : clsids) {
        std::string sub = "SOFTWARE\\Classes\\CLSID\\" + clsid + "\\InprocServer32";
        std::string hkcu_val = readRegSZ(HKEY_CURRENT_USER, sub.c_str(), "");
        if (hkcu_val.empty()) continue;

        // Check what HKCR says
        std::string hkcr_sub = "CLSID\\" + clsid + "\\InprocServer32";
        std::string hkcr_val = readRegSZ(HKEY_CLASSES_ROOT, hkcr_sub.c_str(), "");

        ++found;
        std::cout << "  CLSID : " << clsid << "\n"
                  << "    HKCU: " << hkcu_val << "\n";
        if (!hkcr_val.empty() && hkcr_val != hkcu_val)
            std::cout << "    HKCR: " << hkcr_val << "  ** OVERRIDE **\n";
        else if (hkcr_val.empty())
            std::cout << "    HKCR: (not registered — ghost entry)\n";
    }
    if (found == 0) std::cout << "  (none found)\n";
    std::cout << "  Total HKCU CLSID InprocServer32 overrides: " << found << "\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. WMI CommandLineEventConsumer subscriptions
// ─────────────────────────────────────────────────────────────────────────────
static void scanWMISubscriptions() {
    printSectionHeader("8. WMI COMMANDLINEEVENTCONSUMER SUBSCRIPTIONS");

    IWbemLocator* pLoc = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr,
                                  CLSCTX_INPROC_SERVER,
                                  IID_IWbemLocator,
                                  reinterpret_cast<void**>(&pLoc));
    if (FAILED(hr)) { printHR("CoCreateInstance(WbemLocator)", hr); return; }

    BSTR bNs = SysAllocString(L"ROOT\\SUBSCRIPTION");
    IWbemServices* pSvc = nullptr;
    hr = pLoc->ConnectServer(bNs, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &pSvc);
    SysFreeString(bNs);
    pLoc->Release();
    if (FAILED(hr)) { printHR("ConnectServer(root\\subscription)", hr); return; }

    CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                      RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                      nullptr, EOAC_NONE);

    BSTR clsName = SysAllocString(L"CommandLineEventConsumer");
    IEnumWbemClassObject* pEnum = nullptr;
    hr = pSvc->CreateInstanceEnum(clsName,
                                  WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                  nullptr, &pEnum);
    SysFreeString(clsName);

    if (FAILED(hr)) {
        // Class may not exist on some systems
        std::cout << "  (CommandLineEventConsumer class not accessible)\n";
        pSvc->Release();
        return;
    }

    int found = 0;
    IWbemClassObject* pObj = nullptr;
    ULONG returned = 0;
    while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &returned) == WBEM_S_NO_ERROR && returned > 0) {
        ++found;
        auto getStr = [&](const wchar_t* prop) -> std::wstring {
            VARIANT v; VariantInit(&v);
            if (SUCCEEDED(pObj->Get(prop, 0, &v, nullptr, nullptr)) && v.vt == VT_BSTR && v.bstrVal) {
                std::wstring r = v.bstrVal;
                VariantClear(&v);
                return r;
            }
            VariantClear(&v);
            return L"";
        };
        std::wcout << L"  [WMI Consumer] Name: " << getStr(L"Name") << L"\n"
                   << L"    Command: " << getStr(L"CommandLineTemplate") << L"\n";
        pObj->Release();
    }
    pEnum->Release();
    pSvc->Release();

    if (found == 0) std::cout << "  (none found)\n";
    std::cout << "  Total CommandLineEventConsumer instances: " << found << "\n";
}

// ─────────────────────────────────────────────────────────────────────────────
int main() {
    std::cout << "============================================================\n"
              << "  PERSISTENCE SCAN REPORT\n"
              << "  sol04_detection  |  " __DATE__ " " __TIME__ "\n"
              << "============================================================\n";

    // Initialize COM once for the whole scan (needed for tasks + WMI)
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        std::cerr << "CoInitializeEx failed: " << hr << "\n";
        return 1;
    }
    CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                         RPC_C_AUTHN_LEVEL_DEFAULT,
                         RPC_C_IMP_LEVEL_IMPERSONATE,
                         nullptr, EOAC_NONE, nullptr);

    scanRunKeys();
    scanStartupFolders();
    scanScheduledTasks();
    scanServices();
    scanIFEO();
    scanAppInit();
    scanCOMHijacks();
    scanWMISubscriptions();

    std::cout << "\n============================================================\n"
              << "  END OF REPORT\n"
              << "============================================================\n";

    CoUninitialize();
    return 0;
}
