/*
 * Module 35 — Exercise 03: COM Client Skeleton
 * ==============================================
 * Learning objectives:
 *   - Initialize COM with CoInitialize / CoInitializeEx
 *   - Create a COM object with CoCreateInstance
 *   - Use QueryInterface to get a specific interface pointer
 *   - Call methods through the interface vtable
 *   - Check HRESULT return values correctly
 *   - Release interfaces and uninitialize COM
 *
 * Prerequisites:
 *   - ex02.dll (from Exercise 02) must be compiled and registered:
 *       regsvr32 ex02.dll
 *     (Exercise 02's DllRegisterServer stub is not yet complete, so
 *      manually add the registry key shown below, or complete Exercise 02 first.)
 *
 * Manual registry setup (replace GUIDs with those in your ex02 source):
 *   reg add "HKCR\CLSID\{B1B2B3B4-BBBB-CCCC-DDDD-EEEEFF001122}\InprocServer32" /ve /d "C:\path\to\ex02.dll"
 *   reg add "HKCR\CLSID\{B1B2B3B4-BBBB-CCCC-DDDD-EEEEFF001122}\InprocServer32" /v ThreadingModel /d Apartment
 *
 * Compile (MinGW / g++):
 *   g++ -std=c++17 -Wall -o ex03.exe exercise_03_com_client.cpp -lole32 -loleaut32 -luuid
 *
 * Run:
 *   .\ex03.exe
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <cstdio>

// ---------------------------------------------------------------------------
// ICalculator interface — must match the definition in ex02 exactly
// (In a real project this would be in a shared header.)
// ---------------------------------------------------------------------------
// IID: {A1B2C3D4-1111-2222-3344-556677889900}
static const GUID IID_ICalculator = { 0xa1b2c3d4, 0x1111, 0x2222,
    { 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00 } };

// CLSID: {B1B2B3B4-BBBB-CCCC-DDDD-EEEEFF001122}
static const GUID CLSID_Calculator = { 0xb1b2b3b4, 0xbbbb, 0xcccc,
    { 0xdd, 0xdd, 0xee, 0xee, 0xff, 0x00, 0x11, 0x22 } };

struct ICalculator : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE Add(double a, double b, double* result) = 0;
    virtual HRESULT STDMETHODCALLTYPE Sub(double a, double b, double* result) = 0;
    virtual HRESULT STDMETHODCALLTYPE Mul(double a, double b, double* result) = 0;
    virtual HRESULT STDMETHODCALLTYPE Div(double a, double b, double* result) = 0;
};

// ---------------------------------------------------------------------------
// Helper: print an HRESULT as hex and a brief description
// ---------------------------------------------------------------------------
static void PrintHR(const char* label, HRESULT hr)
{
    // TODO: Use FormatMessage to get a human-readable error string.
    // Hint:
    //   LPSTR msg = nullptr;
    //   FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
    //                  nullptr, hr, 0, (LPSTR)&msg, 0, nullptr);
    //   printf("%s: 0x%08X — %s\n", label, (unsigned)hr, msg ? msg : "unknown");
    //   if (msg) LocalFree(msg);
    printf("%s: 0x%08X\n", label, (unsigned)hr);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main()
{
    HRESULT hr;

    // TODO: Call CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED).
    // Check FAILED(hr) and print an error if COM initialization failed.
    // hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    // if (FAILED(hr)) { PrintHR("CoInitializeEx", hr); return 1; }

    ICalculator* pCalc = nullptr;

    // TODO: Call CoCreateInstance to create the Calculator object.
    // Parameters: CLSID_Calculator, nullptr (no aggregation),
    //             CLSCTX_INPROC_SERVER, IID_ICalculator, (void**)&pCalc
    // Check FAILED(hr). Common failure: REGDB_E_CLASSNOTREG (0x80040154) means
    // the DLL is not registered. See the manual registry setup at the top.
    // hr = CoCreateInstance(CLSID_Calculator, nullptr, CLSCTX_INPROC_SERVER,
    //                       IID_ICalculator, (void**)&pCalc);
    // if (FAILED(hr)) { PrintHR("CoCreateInstance", hr); CoUninitialize(); return 1; }

    // TODO: Call pCalc->Add(10.0, 5.0, &result) and print the result.
    // Expected: 15.0
    double result = 0.0;
    // hr = pCalc->Add(10.0, 5.0, &result);
    // if (SUCCEEDED(hr)) printf("Add(10, 5) = %.2f\n", result);
    // else PrintHR("Add", hr);

    // TODO: Call Sub, Mul, Div similarly.

    // TODO: Release the interface pointer: pCalc->Release(); pCalc = nullptr;

    // TODO: Call CoUninitialize().

    printf("Done. result placeholder = %.2f\n", result);
    return 0;
}
