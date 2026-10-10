/*
 * sol03_com_client.cpp — COM Client for sol02's ICalculator server
 *
 * NOTE: Run 'regsvr32 sol02.dll' before using this client.
 *
 * Build:
 *   g++ -std=c++17 -Wall -o sol03.exe sol03_com_client.cpp \
 *       -lole32 -loleaut32 -luuid
 *
 * Run:
 *   sol03.exe
 */

#define WIN32_LEAN_AND_MEAN
#define UNICODE
#include <windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <unknwn.h>
#include <stdio.h>

// ---------------------------------------------------------------------------
// GUIDs — must match sol02_com_server.cpp exactly
// IID_ICalculator = {A1B2C3D4-1234-5678-ABCD-EF0123456789}
// CLSID_Calculator = {B2C3D4E5-2345-6789-BCDE-F0123456789A}
// ---------------------------------------------------------------------------
static const GUID IID_ICalculator =
    { 0xA1B2C3D4, 0x1234, 0x5678,
      { 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89 } };

static const GUID CLSID_Calculator =
    { 0xB2C3D4E5, 0x2345, 0x6789,
      { 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A } };

// ---------------------------------------------------------------------------
// ICalculator — must match sol02_com_server.cpp exactly
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
// Helper: print HRESULT as hex on failure
// ---------------------------------------------------------------------------
static void CheckHR(HRESULT hr, const char* label)
{
    if (FAILED(hr)) {
        fprintf(stderr, "[ERROR] %s failed: 0x%08X\n", label, (unsigned)hr);
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main()
{
    printf("=== ICalculator COM Client ===\n");
    printf("NOTE: Run 'regsvr32 sol02.dll' before using this client\n\n");

    // Initialize COM (single-threaded apartment)
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        fprintf(stderr, "CoInitializeEx failed: 0x%08X\n", (unsigned)hr);
        return 1;
    }

    // Get ICalculator interface via CoCreateInstance
    ICalculator* pCalc = nullptr;
    hr = CoCreateInstance(CLSID_Calculator, nullptr, CLSCTX_INPROC_SERVER,
                          IID_ICalculator,
                          reinterpret_cast<void**>(&pCalc));
    if (FAILED(hr)) {
        fprintf(stderr, "CoCreateInstance failed: 0x%08X\n"
                        "  -> Is sol02.dll registered? Run: regsvr32 sol02.dll\n",
                (unsigned)hr);
        CoUninitialize();
        return 1;
    }

    double result = 0.0;

    // Add(100, 42) -> 142
    hr = pCalc->Add(100.0, 42.0, &result);
    if (SUCCEEDED(hr))
        printf("100 + 42 = %.0f\n", result);
    else
        CheckHR(hr, "Add");

    // Sub(100, 42) -> 58
    hr = pCalc->Sub(100.0, 42.0, &result);
    if (SUCCEEDED(hr))
        printf("100 - 42 = %.0f\n", result);
    else
        CheckHR(hr, "Sub");

    // Mul(6, 7) -> 42
    hr = pCalc->Mul(6.0, 7.0, &result);
    if (SUCCEEDED(hr))
        printf("6 * 7 = %.0f\n", result);
    else
        CheckHR(hr, "Mul");

    // Div(100, 4) -> 25
    hr = pCalc->Div(100.0, 4.0, &result);
    if (SUCCEEDED(hr))
        printf("100 / 4 = %.0f\n", result);
    else
        CheckHR(hr, "Div");

    // Div(10, 0) -> E_INVALIDARG (division by zero)
    hr = pCalc->Div(10.0, 0.0, &result);
    if (hr == E_INVALIDARG)
        printf("10 / 0 = E_INVALIDARG (division by zero)\n");
    else if (SUCCEEDED(hr))
        printf("10 / 0 = %.0f  [unexpected success!]\n", result);
    else
        fprintf(stderr, "10 / 0 failed with unexpected code: 0x%08X\n", (unsigned)hr);

    // GetVersion()
    BSTR bstr = nullptr;
    hr = pCalc->GetVersion(&bstr);
    if (SUCCEEDED(hr) && bstr) {
        // Convert BSTR to narrow for printf
        int needed = WideCharToMultiByte(CP_UTF8, 0, bstr, -1, nullptr, 0, nullptr, nullptr);
        if (needed > 0) {
            char* narrow = new char[needed];
            WideCharToMultiByte(CP_UTF8, 0, bstr, -1, narrow, needed, nullptr, nullptr);
            printf("Version: %s\n", narrow);
            delete[] narrow;
        }
        SysFreeString(bstr);
    } else {
        CheckHR(hr, "GetVersion");
    }

    // Clean up
    pCalc->Release();
    CoUninitialize();

    printf("\nDone.\n");
    return 0;
}
