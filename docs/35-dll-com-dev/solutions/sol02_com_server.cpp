/*
 * sol02_com_server.cpp — In-Process COM Server DLL (ICalculator)
 *
 * Implements a complete, self-contained COM server with no IDL dependency.
 * All GUIDs are defined inline as const GUID literals.
 *
 * Build:
 *   g++ -shared -std=c++17 -o sol02.dll sol02_com_server.cpp \
 *       -lole32 -loleaut32 -luuid -ladvapi32
 *
 * Register:
 *   regsvr32 sol02.dll
 *
 * Unregister:
 *   regsvr32 /u sol02.dll
 */

#define WIN32_LEAN_AND_MEAN
#define UNICODE
#include <windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <unknwn.h>
#include <wchar.h>
#include <stdio.h>

// ---------------------------------------------------------------------------
// GUID definitions
// IID_ICalculator = {A1B2C3D4-1234-5678-ABCD-EF0123456789}
// CLSID_Calculator = {B2C3D4E5-2345-6789-BCDE-F012345678 9A}
// ---------------------------------------------------------------------------
static const GUID IID_ICalculator =
    { 0xA1B2C3D4, 0x1234, 0x5678,
      { 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89 } };

static const GUID CLSID_Calculator =
    { 0xB2C3D4E5, 0x2345, 0x6789,
      { 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A } };

// ---------------------------------------------------------------------------
// ICalculator — pure virtual interface
// ---------------------------------------------------------------------------
struct ICalculator : public IUnknown
{
    virtual HRESULT __stdcall Add(double a, double b, double* result) = 0;
    virtual HRESULT __stdcall Sub(double a, double b, double* result) = 0;
    virtual HRESULT __stdcall Mul(double a, double b, double* result) = 0;
    virtual HRESULT __stdcall Div(double a, double b, double* result) = 0;
    virtual HRESULT __stdcall GetVersion(BSTR* ver) = 0;
};

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------
HINSTANCE g_hModule    = NULL;
LONG      g_ObjectCount = 0;
LONG      g_LockCount   = 0;

// ---------------------------------------------------------------------------
// CCalculator — ICalculator implementation
// ---------------------------------------------------------------------------
class CCalculator : public ICalculator
{
public:
    CCalculator() : m_refCount(0) {}

    // IUnknown
    ULONG __stdcall AddRef() override
    {
        return InterlockedIncrement(&m_refCount);
    }

    ULONG __stdcall Release() override
    {
        LONG ref = InterlockedDecrement(&m_refCount);
        if (ref == 0) {
            InterlockedDecrement(&g_ObjectCount);
            delete this;
        }
        return (ULONG)ref;
    }

    HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv) return E_POINTER;

        if (IsEqualIID(riid, IID_IUnknown)) {
            *ppv = static_cast<IUnknown*>(this);
        } else if (IsEqualIID(riid, IID_ICalculator)) {
            *ppv = static_cast<ICalculator*>(this);
        } else {
            *ppv = nullptr;
            return E_NOINTERFACE;
        }
        AddRef();
        return S_OK;
    }

    // ICalculator
    HRESULT __stdcall Add(double a, double b, double* result) override
    {
        if (!result) return E_POINTER;
        *result = a + b;
        return S_OK;
    }

    HRESULT __stdcall Sub(double a, double b, double* result) override
    {
        if (!result) return E_POINTER;
        *result = a - b;
        return S_OK;
    }

    HRESULT __stdcall Mul(double a, double b, double* result) override
    {
        if (!result) return E_POINTER;
        *result = a * b;
        return S_OK;
    }

    HRESULT __stdcall Div(double a, double b, double* result) override
    {
        if (!result) return E_POINTER;
        if (b == 0.0) return E_INVALIDARG;
        *result = a / b;
        return S_OK;
    }

    HRESULT __stdcall GetVersion(BSTR* ver) override
    {
        if (!ver) return E_POINTER;
        *ver = SysAllocString(L"Calculator 1.0");
        return *ver ? S_OK : E_OUTOFMEMORY;
    }

private:
    LONG m_refCount;
};

// ---------------------------------------------------------------------------
// CClassFactory — IClassFactory for CCalculator
// ---------------------------------------------------------------------------
class CClassFactory : public IClassFactory
{
public:
    CClassFactory() : m_refCount(0) {}

    // IUnknown
    ULONG __stdcall AddRef() override
    {
        return InterlockedIncrement(&m_refCount);
    }

    ULONG __stdcall Release() override
    {
        LONG ref = InterlockedDecrement(&m_refCount);
        if (ref == 0) delete this;
        return (ULONG)ref;
    }

    HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv) return E_POINTER;

        if (IsEqualIID(riid, IID_IUnknown)) {
            *ppv = static_cast<IUnknown*>(this);
        } else if (IsEqualIID(riid, IID_IClassFactory)) {
            *ppv = static_cast<IClassFactory*>(this);
        } else {
            *ppv = nullptr;
            return E_NOINTERFACE;
        }
        AddRef();
        return S_OK;
    }

    // IClassFactory
    HRESULT __stdcall CreateInstance(IUnknown* pOuter,
                                      REFIID    riid,
                                      void**    ppv) override
    {
        if (!ppv) return E_POINTER;
        *ppv = nullptr;

        // Aggregation not supported
        if (pOuter) return CLASS_E_NOAGGREGATION;

        CCalculator* pObj = new (std::nothrow) CCalculator();
        if (!pObj) return E_OUTOFMEMORY;

        InterlockedIncrement(&g_ObjectCount);

        HRESULT hr = pObj->QueryInterface(riid, ppv);
        if (FAILED(hr)) {
            InterlockedDecrement(&g_ObjectCount);
            delete pObj;
        }
        return hr;
    }

    HRESULT __stdcall LockServer(BOOL fLock) override
    {
        if (fLock)
            InterlockedIncrement(&g_LockCount);
        else
            InterlockedDecrement(&g_LockCount);
        return S_OK;
    }

private:
    LONG m_refCount;
};

// ---------------------------------------------------------------------------
// Helper: GUID → wide-string in registry format "{XXXXXXXX-...}"
// ---------------------------------------------------------------------------
static void GuidToStringW(REFGUID guid, wchar_t* buf, int cch)
{
    swprintf_s(buf, cch,
        L"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        guid.Data1, guid.Data2, guid.Data3,
        guid.Data4[0], guid.Data4[1],
        guid.Data4[2], guid.Data4[3], guid.Data4[4],
        guid.Data4[5], guid.Data4[6], guid.Data4[7]);
}

// ---------------------------------------------------------------------------
// DLL exports
// ---------------------------------------------------------------------------
extern "C"
{

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        g_hModule = hinstDLL;
        DisableThreadLibraryCalls(hinstDLL);
    }
    return TRUE;
}

HRESULT __stdcall DllGetClassObject(REFCLSID clsid, REFIID riid, void** ppv)
{
    if (!ppv) return E_POINTER;
    *ppv = nullptr;

    if (!IsEqualCLSID(clsid, CLSID_Calculator))
        return CLASS_E_CLASSNOTAVAILABLE;

    CClassFactory* pFactory = new (std::nothrow) CClassFactory();
    if (!pFactory) return E_OUTOFMEMORY;

    HRESULT hr = pFactory->QueryInterface(riid, ppv);
    if (FAILED(hr)) delete pFactory;
    return hr;
}

HRESULT __stdcall DllCanUnloadNow()
{
    return (g_ObjectCount == 0 && g_LockCount == 0) ? S_OK : S_FALSE;
}

HRESULT __stdcall DllRegisterServer()
{
    wchar_t szCLSID[64];
    GuidToStringW(CLSID_Calculator, szCLSID, 64);

    wchar_t szKey[256];
    swprintf_s(szKey, 256, L"CLSID\\%s", szCLSID);

    // Create HKCR\CLSID\{...}
    HKEY hKey = NULL;
    LONG lRes = RegCreateKeyExW(HKEY_CLASSES_ROOT, szKey,
                                0, nullptr, REG_OPTION_NON_VOLATILE,
                                KEY_WRITE, nullptr, &hKey, nullptr);
    if (lRes != ERROR_SUCCESS) return HRESULT_FROM_WIN32(lRes);

    // Set default value = friendly name
    const wchar_t* szName = L"Calculator COM Server";
    RegSetValueExW(hKey, nullptr, 0, REG_SZ,
                   (const BYTE*)szName,
                   (DWORD)((wcslen(szName) + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);

    // Create HKCR\CLSID\{...}\InprocServer32
    wchar_t szInproc[256];
    swprintf_s(szInproc, 256, L"CLSID\\%s\\InprocServer32", szCLSID);

    lRes = RegCreateKeyExW(HKEY_CLASSES_ROOT, szInproc,
                           0, nullptr, REG_OPTION_NON_VOLATILE,
                           KEY_WRITE, nullptr, &hKey, nullptr);
    if (lRes != ERROR_SUCCESS) return HRESULT_FROM_WIN32(lRes);

    // Set default value = path to this DLL
    wchar_t szModulePath[MAX_PATH] = {};
    GetModuleFileNameW(g_hModule, szModulePath, MAX_PATH);

    RegSetValueExW(hKey, nullptr, 0, REG_SZ,
                   (const BYTE*)szModulePath,
                   (DWORD)((wcslen(szModulePath) + 1) * sizeof(wchar_t)));

    // Set ThreadingModel = Apartment
    const wchar_t* szModel = L"Apartment";
    RegSetValueExW(hKey, L"ThreadingModel", 0, REG_SZ,
                   (const BYTE*)szModel,
                   (DWORD)((wcslen(szModel) + 1) * sizeof(wchar_t)));

    RegCloseKey(hKey);
    return S_OK;
}

HRESULT __stdcall DllUnregisterServer()
{
    wchar_t szCLSID[64];
    GuidToStringW(CLSID_Calculator, szCLSID, 64);

    wchar_t szKey[256];
    swprintf_s(szKey, 256, L"CLSID\\%s", szCLSID);

    LONG lRes = RegDeleteTreeW(HKEY_CLASSES_ROOT, szKey);
    if (lRes != ERROR_SUCCESS && lRes != ERROR_FILE_NOT_FOUND)
        return HRESULT_FROM_WIN32(lRes);

    return S_OK;
}

} // extern "C"
