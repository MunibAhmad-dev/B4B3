/*
  Solution 03 — WMI Event Subscription Persistence
  ==================================================
  Creates a permanent WMI event subscription that fires when notepad.exe
  starts (or whatever process name the query specifies) and runs a
  caller-supplied command.

  Usage:
    sol03.exe install <cmd_to_run>   — create filter + consumer + binding
    sol03.exe remove                 — delete all three objects
    sol03.exe list                   — show existing subscriptions

  IMPORTANT: Requires Administrator privileges.

  Compile:
    g++ -std=c++17 -Wall -o sol03.exe sol03_wmi_subscription.cpp \
        -lwbemuuid -lole32 -loleaut32 -ladvapi32
*/

#define _WIN32_DCOM
#include <windows.h>
#include <wbemidl.h>
#include <comdef.h>
#include <iostream>
#include <string>
#include <vector>

// ── subscription object names ────────────────────────────────────────────────
static const wchar_t* FILTER_NAME   = L"MalFilter";
static const wchar_t* CONSUMER_NAME = L"MalConsumer";

// WQL query: fires within 30 s of notepad.exe starting
static const wchar_t* FILTER_QUERY  =
    L"SELECT * FROM __InstanceCreationEvent WITHIN 30 "
    L"WHERE TargetInstance ISA 'Win32_Process' "
    L"AND TargetInstance.Name='notepad.exe'";

// ─────────────────────────────────────────────────────────────────────────────
// Print HRESULT error
// ─────────────────────────────────────────────────────────────────────────────
static void printHR(const char* label, HRESULT hr) {
    _com_error err(hr);
    std::cerr << "  ERROR [" << label << "] 0x" << std::hex << (unsigned long)hr
              << std::dec << ": " << err.ErrorMessage() << "\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// Initialize COM and security
// ─────────────────────────────────────────────────────────────────────────────
static bool initCOM() {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) { printHR("CoInitializeEx", hr); return false; }

    hr = CoInitializeSecurity(
        nullptr, -1, nullptr, nullptr,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_NONE, nullptr);
    if (FAILED(hr) && hr != RPC_E_TOO_LATE) { printHR("CoInitializeSecurity", hr); return false; }
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Connect to root\subscription, return IWbemServices*
// ─────────────────────────────────────────────────────────────────────────────
static IWbemServices* connectWMI(const wchar_t* ns) {
    IWbemLocator* pLoc = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr,
                                  CLSCTX_INPROC_SERVER,
                                  IID_IWbemLocator,
                                  reinterpret_cast<void**>(&pLoc));
    if (FAILED(hr)) { printHR("CoCreateInstance(WbemLocator)", hr); return nullptr; }

    BSTR bNs = SysAllocString(ns);
    IWbemServices* pSvc = nullptr;
    hr = pLoc->ConnectServer(bNs, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &pSvc);
    SysFreeString(bNs);
    pLoc->Release();
    if (FAILED(hr)) { printHR("ConnectServer", hr); return nullptr; }

    hr = CoSetProxyBlanket(pSvc,
                           RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                           RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                           nullptr, EOAC_NONE);
    if (FAILED(hr)) { printHR("CoSetProxyBlanket", hr); pSvc->Release(); return nullptr; }
    return pSvc;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: set a BSTR property on an IWbemClassObject
// ─────────────────────────────────────────────────────────────────────────────
static bool putBSTR(IWbemClassObject* pObj, const wchar_t* prop, const wchar_t* value) {
    VARIANT v;
    VariantInit(&v);
    v.vt      = VT_BSTR;
    v.bstrVal = SysAllocString(value);
    HRESULT hr = pObj->Put(prop, 0, &v, 0);
    VariantClear(&v);
    if (FAILED(hr)) { printHR("IWbemClassObject::Put", hr); return false; }
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Retrieve __PATH of a newly put instance (for confirmation)
// ─────────────────────────────────────────────────────────────────────────────
static std::wstring getPath(IWbemCallResult* pResult) {
    if (!pResult) return L"";
    IWbemClassObject* pObj = nullptr;
    if (SUCCEEDED(pResult->GetResultObject(WBEM_INFINITE, &pObj)) && pObj) {
        VARIANT v;
        VariantInit(&v);
        if (SUCCEEDED(pObj->Get(L"__PATH", 0, &v, nullptr, nullptr)) && v.vt == VT_BSTR) {
            std::wstring path = v.bstrVal ? v.bstrVal : L"";
            VariantClear(&v);
            pObj->Release();
            return path;
        }
        VariantClear(&v);
        pObj->Release();
    }
    return L"";
}

// ─────────────────────────────────────────────────────────────────────────────
// MODE: install
// ─────────────────────────────────────────────────────────────────────────────
static int modeInstall(const std::wstring& cmdToRun) {
    std::wcout << L"[install] Command: " << cmdToRun << L"\n\n";

    IWbemServices* pSvc = connectWMI(L"ROOT\\SUBSCRIPTION");
    if (!pSvc) return 1;

    // ── create __EventFilter ─────────────────────────────────────────────────
    {
        BSTR clsName = SysAllocString(L"__EventFilter");
        IWbemClassObject* pClass = nullptr;
        HRESULT hr = pSvc->GetObject(clsName, 0, nullptr, &pClass, nullptr);
        SysFreeString(clsName);
        if (FAILED(hr)) { printHR("GetObject(__EventFilter)", hr); pSvc->Release(); return 1; }

        IWbemClassObject* pInst = nullptr;
        pClass->SpawnInstance(0, &pInst);
        pClass->Release();

        putBSTR(pInst, L"Name",           FILTER_NAME);
        putBSTR(pInst, L"EventNamespace", L"root\\cimv2");
        putBSTR(pInst, L"QueryLanguage",  L"WQL");
        putBSTR(pInst, L"Query",          FILTER_QUERY);

        IWbemCallResult* pResult = nullptr;
        hr = pSvc->PutInstance(pInst,
                               WBEM_FLAG_CREATE_OR_UPDATE | WBEM_FLAG_RETURN_IMMEDIATELY,
                               nullptr, &pResult);
        pInst->Release();
        if (FAILED(hr)) { printHR("PutInstance(__EventFilter)", hr); pSvc->Release(); return 1; }

        auto path = getPath(pResult);
        if (pResult) pResult->Release();
        std::wcout << L"[+] __EventFilter created\n"
                   << L"    Name  : " << FILTER_NAME << L"\n"
                   << L"    Query : " << FILTER_QUERY << L"\n\n";
    }

    // ── create CommandLineEventConsumer ──────────────────────────────────────
    {
        BSTR clsName = SysAllocString(L"CommandLineEventConsumer");
        IWbemClassObject* pClass = nullptr;
        HRESULT hr = pSvc->GetObject(clsName, 0, nullptr, &pClass, nullptr);
        SysFreeString(clsName);
        if (FAILED(hr)) { printHR("GetObject(CommandLineEventConsumer)", hr); pSvc->Release(); return 1; }

        IWbemClassObject* pInst = nullptr;
        pClass->SpawnInstance(0, &pInst);
        pClass->Release();

        putBSTR(pInst, L"Name",                CONSUMER_NAME);
        putBSTR(pInst, L"CommandLineTemplate", cmdToRun.c_str());

        IWbemCallResult* pResult = nullptr;
        hr = pSvc->PutInstance(pInst,
                               WBEM_FLAG_CREATE_OR_UPDATE | WBEM_FLAG_RETURN_IMMEDIATELY,
                               nullptr, &pResult);
        pInst->Release();
        if (FAILED(hr)) { printHR("PutInstance(CommandLineEventConsumer)", hr); pSvc->Release(); return 1; }

        if (pResult) pResult->Release();
        std::wcout << L"[+] CommandLineEventConsumer created\n"
                   << L"    Name : " << CONSUMER_NAME << L"\n"
                   << L"    Cmd  : " << cmdToRun << L"\n\n";
    }

    // ── create __FilterToConsumerBinding ─────────────────────────────────────
    {
        BSTR clsName = SysAllocString(L"__FilterToConsumerBinding");
        IWbemClassObject* pClass = nullptr;
        HRESULT hr = pSvc->GetObject(clsName, 0, nullptr, &pClass, nullptr);
        SysFreeString(clsName);
        if (FAILED(hr)) { printHR("GetObject(__FilterToConsumerBinding)", hr); pSvc->Release(); return 1; }

        IWbemClassObject* pInst = nullptr;
        pClass->SpawnInstance(0, &pInst);
        pClass->Release();

        // Build reference strings
        std::wstring filterRef   = std::wstring(L"__EventFilter.Name=\"") + FILTER_NAME + L"\"";
        std::wstring consumerRef = std::wstring(L"CommandLineEventConsumer.Name=\"") + CONSUMER_NAME + L"\"";
        putBSTR(pInst, L"Filter",   filterRef.c_str());
        putBSTR(pInst, L"Consumer", consumerRef.c_str());

        IWbemCallResult* pResult = nullptr;
        hr = pSvc->PutInstance(pInst,
                               WBEM_FLAG_CREATE_OR_UPDATE | WBEM_FLAG_RETURN_IMMEDIATELY,
                               nullptr, &pResult);
        pInst->Release();
        if (FAILED(hr)) { printHR("PutInstance(__FilterToConsumerBinding)", hr); pSvc->Release(); return 1; }

        if (pResult) pResult->Release();
        std::wcout << L"[+] __FilterToConsumerBinding created\n"
                   << L"    Filter   -> " << filterRef << L"\n"
                   << L"    Consumer -> " << consumerRef << L"\n\n";
    }

    pSvc->Release();
    std::cout << "Subscription installed. Open notepad.exe to trigger within ~30s.\n";
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: delete all instances matching a WQL query by __PATH
// ─────────────────────────────────────────────────────────────────────────────
static int deleteByQuery(IWbemServices* pSvc, const wchar_t* wql, const char* label) {
    BSTR bLang = SysAllocString(L"WQL");
    BSTR bQuery = SysAllocString(wql);
    IEnumWbemClassObject* pEnum = nullptr;
    HRESULT hr = pSvc->ExecQuery(bLang, bQuery,
                                 WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                 nullptr, &pEnum);
    SysFreeString(bLang);
    SysFreeString(bQuery);
    if (FAILED(hr)) { printHR(label, hr); return 0; }

    int deleted = 0;
    IWbemClassObject* pObj = nullptr;
    ULONG returned = 0;
    while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &returned) == WBEM_S_NO_ERROR && returned > 0) {
        VARIANT vPath;
        VariantInit(&vPath);
        if (SUCCEEDED(pObj->Get(L"__PATH", 0, &vPath, nullptr, nullptr)) &&
            vPath.vt == VT_BSTR && vPath.bstrVal) {
            HRESULT del = pSvc->DeleteInstance(vPath.bstrVal, 0, nullptr, nullptr);
            if (SUCCEEDED(del)) {
                std::wcout << L"  Deleted: " << vPath.bstrVal << L"\n";
                ++deleted;
            } else {
                printHR("DeleteInstance", del);
            }
        }
        VariantClear(&vPath);
        pObj->Release();
    }
    pEnum->Release();
    return deleted;
}

// ─────────────────────────────────────────────────────────────────────────────
// MODE: remove
// ─────────────────────────────────────────────────────────────────────────────
static int modeRemove() {
    std::cout << "[remove] Deleting MalFilter / MalConsumer subscription ...\n\n";

    IWbemServices* pSvc = connectWMI(L"ROOT\\SUBSCRIPTION");
    if (!pSvc) return 1;

    // Delete binding first (referential integrity)
    int n = deleteByQuery(pSvc,
        L"SELECT * FROM __FilterToConsumerBinding "
        L"WHERE Filter = \"__EventFilter.Name=\\\"MalFilter\\\"\"",
        "query __FilterToConsumerBinding");
    std::cout << "  Bindings deleted : " << n << "\n";

    n = deleteByQuery(pSvc,
        L"SELECT * FROM CommandLineEventConsumer WHERE Name='MalConsumer'",
        "query CommandLineEventConsumer");
    std::cout << "  Consumers deleted: " << n << "\n";

    n = deleteByQuery(pSvc,
        L"SELECT * FROM __EventFilter WHERE Name='MalFilter'",
        "query __EventFilter");
    std::cout << "  Filters deleted  : " << n << "\n";

    pSvc->Release();
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Print all instances of a class
// ─────────────────────────────────────────────────────────────────────────────
static void listClass(IWbemServices* pSvc, const wchar_t* className) {
    BSTR bCls = SysAllocString(className);
    IEnumWbemClassObject* pEnum = nullptr;
    HRESULT hr = pSvc->CreateInstanceEnum(bCls,
                                          WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                          nullptr, &pEnum);
    SysFreeString(bCls);
    if (FAILED(hr)) {
        // Class may not exist; skip silently
        return;
    }

    IWbemClassObject* pObj = nullptr;
    ULONG returned = 0;
    int count = 0;
    while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &returned) == WBEM_S_NO_ERROR && returned > 0) {
        if (count == 0)
            std::wcout << L"  [" << className << L"]\n";
        ++count;

        // Print all non-system properties
        pObj->BeginEnumeration(WBEM_FLAG_NONSYSTEM_ONLY);
        BSTR propName = nullptr;
        VARIANT val;
        while (pObj->Next(0, &propName, &val, nullptr, nullptr) == WBEM_S_NO_ERROR) {
            if (propName) {
                std::wcout << L"    " << propName << L" = ";
                if (val.vt == VT_BSTR && val.bstrVal)
                    std::wcout << val.bstrVal;
                else if (val.vt == VT_I4)
                    std::wcout << val.lVal;
                else if (val.vt == VT_NULL || val.vt == VT_EMPTY)
                    std::wcout << L"(null)";
                else
                    std::wcout << L"(type=" << val.vt << L")";
                std::wcout << L"\n";
                SysFreeString(propName);
                propName = nullptr;
            }
            VariantClear(&val);
        }
        pObj->EndEnumeration();
        pObj->Release();
        std::wcout << L"\n";
    }
    pEnum->Release();
    if (count == 0)
        std::wcout << L"  [" << className << L"] — no instances\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// MODE: list
// ─────────────────────────────────────────────────────────────────────────────
static int modeList() {
    std::cout << "[list] Enumerating WMI subscriptions in root\\subscription ...\n\n";

    IWbemServices* pSvc = connectWMI(L"ROOT\\SUBSCRIPTION");
    if (!pSvc) return 1;

    listClass(pSvc, L"CommandLineEventConsumer");
    listClass(pSvc, L"__EventFilter");
    listClass(pSvc, L"__FilterToConsumerBinding");

    pSvc->Release();
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    std::cout << "=== Solution 03: WMI Event Subscription Persistence ===\n\n";
    std::cout << "NOTE: Requires Administrator.\n\n";

    if (argc < 2) {
        std::cerr << "Usage:\n"
                  << "  sol03.exe install <cmd_to_run>\n"
                  << "  sol03.exe remove\n"
                  << "  sol03.exe list\n";
        return 1;
    }

    if (!initCOM()) return 1;

    std::string mode = argv[1];
    int rc = 0;
    if (mode == "install") {
        if (argc < 3) { std::cerr << "install requires <cmd_to_run>.\n"; CoUninitialize(); return 1; }
        // Convert argv[2] to wstring
        std::string cmd = argv[2];
        std::wstring wcmd(cmd.begin(), cmd.end());
        rc = modeInstall(wcmd);
    } else if (mode == "remove") {
        rc = modeRemove();
    } else if (mode == "list") {
        rc = modeList();
    } else {
        std::cerr << "Unknown mode '" << mode << "'. Use: install | remove | list\n";
        CoUninitialize();
        return 1;
    }

    CoUninitialize();
    return rc;
}
