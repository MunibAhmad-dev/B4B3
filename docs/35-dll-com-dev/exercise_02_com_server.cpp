/*
 * Module 35 — Exercise 02: In-Process COM Server Skeleton
 * =========================================================
 * Learning objectives:
 *   - Define a COM interface (ICalculator) with its own IID
 *   - Implement IUnknown methods: QueryInterface, AddRef, Release
 *   - Implement IClassFactory: CreateInstance, LockServer
 *   - Export DllGetClassObject and DllCanUnloadNow
 *
 * Compile (MinGW / g++):
 *   g++ -shared -std=c++17 -o ex02.dll exercise_02_com_server.cpp \
 *       -lole32 -loleaut32 -luuid -ladvapi32
 *
 * Register:
 *   regsvr32 ex02.dll
 *
 * Note: regsvr32 calls DllRegisterServer. You will implement that in Exercise 04 / Solution 02.
 *       For now, you can manually set the registry key shown in the TODO comments.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <unknwn.h>
#include <objbase.h>

// ---------------------------------------------------------------------------
// ICalculator interface definition
// IID: {A1B2C3D4-1111-2222-3344-556677889900}
// ---------------------------------------------------------------------------

// TODO: Define IID_ICalculator as a GUID literal matching the value above.
// static const GUID IID_ICalculator = { 0xa1b2c3d4, 0x1111, 0x2222,
//     { 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00 } };

// TODO: Define CLSID_Calculator.
// Use a freshly generated GUID (guidgen.exe or online UUID generator).
// CLSID: {B1B2B3B4-BBBB-CCCC-DDDD-EEEEFF001122}
// static const GUID CLSID_Calculator = { 0xb1b2b3b4, 0xbbbb, 0xcccc,
//     { 0xdd, 0xdd, 0xee, 0xee, 0xff, 0x00, 0x11, 0x22 } };

// Forward-declare the interface
struct ICalculator; // : IUnknown

// The interface struct / abstract class. In real code this would be in a header.
// TODO: Uncomment and complete the interface declaration.
/*
struct ICalculator : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE Add(double a, double b, double* result) = 0;
    virtual HRESULT STDMETHODCALLTYPE Sub(double a, double b, double* result) = 0;
    virtual HRESULT STDMETHODCALLTYPE Mul(double a, double b, double* result) = 0;
    virtual HRESULT STDMETHODCALLTYPE Div(double a, double b, double* result) = 0;
};
*/

// ---------------------------------------------------------------------------
// Global reference count — tracks total objects + locks
// ---------------------------------------------------------------------------
static volatile LONG g_objCount = 0;

// ---------------------------------------------------------------------------
// CCalculator — implements IUnknown and ICalculator
// ---------------------------------------------------------------------------
class CCalculator // TODO: inherit from ICalculator
{
    volatile LONG m_refCount;

public:
    CCalculator() : m_refCount(0) { InterlockedIncrement(&g_objCount); }
    ~CCalculator()                { InterlockedDecrement(&g_objCount); }

    // --- IUnknown ---

    // TODO: Implement QueryInterface.
    // If riid == IID_IUnknown OR riid == IID_ICalculator:
    //     *ppv = static_cast<ICalculator*>(this); AddRef(); return S_OK;
    // Otherwise: *ppv = nullptr; return E_NOINTERFACE;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv)
    {
        // TODO: implement
        (void)riid; *ppv = nullptr;
        return E_NOINTERFACE;
    }

    // TODO: Implement AddRef using InterlockedIncrement(&m_refCount). Return new count.
    ULONG STDMETHODCALLTYPE AddRef()
    {
        // TODO: implement
        return 0;
    }

    // TODO: Implement Release using InterlockedDecrement(&m_refCount).
    // If the new count == 0, call: delete this; return 0;
    // Otherwise return the new count.
    ULONG STDMETHODCALLTYPE Release()
    {
        // TODO: implement
        return 0;
    }

    // --- ICalculator ---

    // TODO: Implement each method. Check that result != nullptr. Return E_POINTER if null.
    HRESULT STDMETHODCALLTYPE Add(double a, double b, double* result)
    {
        // TODO: if (!result) return E_POINTER; *result = a + b; return S_OK;
        return E_NOTIMPL;
    }

    HRESULT STDMETHODCALLTYPE Sub(double a, double b, double* result)
    {
        // TODO: *result = a - b;
        return E_NOTIMPL;
    }

    HRESULT STDMETHODCALLTYPE Mul(double a, double b, double* result)
    {
        // TODO: *result = a * b;
        return E_NOTIMPL;
    }

    HRESULT STDMETHODCALLTYPE Div(double a, double b, double* result)
    {
        // TODO: check b != 0.0, then *result = a / b;
        // If b == 0.0, return E_INVALIDARG (or a custom HRESULT).
        return E_NOTIMPL;
    }
};

// ---------------------------------------------------------------------------
// CClassFactory — creates CCalculator objects
// ---------------------------------------------------------------------------
class CClassFactory : public IClassFactory
{
    volatile LONG m_refCount;

public:
    CClassFactory() : m_refCount(1) {}

    // IUnknown
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override
    {
        // TODO: handle IID_IUnknown and IID_IClassFactory
        (void)riid; *ppv = nullptr;
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef()  override
    {
        // TODO: InterlockedIncrement
        return 0;
    }

    ULONG STDMETHODCALLTYPE Release() override
    {
        // TODO: InterlockedDecrement; delete this if 0
        return 0;
    }

    // IClassFactory
    // TODO: Implement CreateInstance.
    // If pUnkOuter != nullptr: return CLASS_E_NOAGGREGATION.
    // Allocate a new CCalculator. Call obj->QueryInterface(riid, ppv).
    // Release the extra reference from construction. Return the QI result.
    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv) override
    {
        // TODO: implement
        (void)pUnkOuter; (void)riid; *ppv = nullptr;
        return E_NOTIMPL;
    }

    // TODO: Implement LockServer.
    // If fLock: InterlockedIncrement(&g_objCount)
    // Else:     InterlockedDecrement(&g_objCount)
    // Return S_OK.
    HRESULT STDMETHODCALLTYPE LockServer(BOOL fLock) override
    {
        // TODO: implement
        (void)fLock;
        return E_NOTIMPL;
    }
};

// ---------------------------------------------------------------------------
// Required DLL exports
// ---------------------------------------------------------------------------

// TODO: Implement DllGetClassObject.
// If rclsid == CLSID_Calculator: create a new CClassFactory, QI for riid, return.
// Otherwise return CLASS_E_CLASSNOTAVAILABLE.
extern "C" __declspec(dllexport)
HRESULT STDAPICALLTYPE DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv)
{
    // TODO: implement
    (void)rclsid; (void)riid; *ppv = nullptr;
    return CLASS_E_CLASSNOTAVAILABLE;
}

// TODO: Implement DllCanUnloadNow.
// Return S_OK if g_objCount == 0, S_FALSE otherwise.
extern "C" __declspec(dllexport)
HRESULT STDAPICALLTYPE DllCanUnloadNow()
{
    // TODO: implement
    return S_FALSE;
}

// DllMain (minimal — no logging needed for this exercise)
BOOL WINAPI DllMain(HINSTANCE, DWORD fdwReason, LPVOID)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Optionally call DisableThreadLibraryCalls
    }
    return TRUE;
}
