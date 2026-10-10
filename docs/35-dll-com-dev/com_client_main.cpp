/*
 * com_client_main.cpp — CLI client for com_toolkit.dll (IFileInspector)
 *
 * Usage:
 *   com_client.exe scan   <filepath>   — scan file, print JSON report
 *   com_client.exe procs               — enumerate running processes
 *   com_client.exe hash   <filepath>   — compute SHA-256 of file
 *   com_client.exe version             — print server version
 *
 * Prerequisites:
 *   regsvr32 com_toolkit.dll   (run once, requires admin)
 *
 * Build:
 *   g++ -std=c++17 -o com_client.exe com_client_main.cpp \
 *       -lole32 -loleaut32 -luuid
 */

#define WIN32_LEAN_AND_MEAN
#define UNICODE
#include <windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <unknwn.h>
#include <stdio.h>
#include <string.h>

// ---------------------------------------------------------------------------
// IFileInspector — must match com_toolkit.cpp exactly
// IID  = {C3D4E5F6-3456-789A-CDEF-0123456789AB}
// CLSID = {D4E5F6A7-4567-89AB-DEF0-123456789ABC}
// ---------------------------------------------------------------------------
static const GUID IID_IFileInspector =
    { 0xC3D4E5F6, 0x3456, 0x789A,
      { 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB } };

static const GUID CLSID_FileInspector =
    { 0xD4E5F6A7, 0x4567, 0x89AB,
      { 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC } };

struct IFileInspector : public IUnknown
{
    virtual HRESULT __stdcall ScanFile(LPCWSTR path, BSTR* report) = 0;
    virtual HRESULT __stdcall GetVersion(BSTR* ver) = 0;
    virtual HRESULT __stdcall EnumProcesses(BSTR* jsonList) = 0;
    virtual HRESULT __stdcall HashFile(LPCWSTR path, BSTR* sha256hex) = 0;
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Print BSTR as UTF-8 to stdout
static void PrintBSTR(BSTR b)
{
    if (!b) { printf("(null)\n"); return; }
    int needed = WideCharToMultiByte(CP_UTF8, 0, b, -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 0) { printf("(empty)\n"); return; }
    char* buf = new char[needed];
    WideCharToMultiByte(CP_UTF8, 0, b, -1, buf, needed, nullptr, nullptr);
    printf("%s\n", buf);
    delete[] buf;
}

// Print HRESULT error details
static void PrintError(HRESULT hr, const char* context)
{
    char msgBuf[512] = {};
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, hr, 0, msgBuf, sizeof(msgBuf), nullptr);
    // Strip trailing newline
    int len = (int)strlen(msgBuf);
    while (len > 0 && (msgBuf[len-1] == '\n' || msgBuf[len-1] == '\r'))
        msgBuf[--len] = '\0';

    if (len > 0)
        fprintf(stderr, "[ERROR] %s: 0x%08X — %s\n", context, (unsigned)hr, msgBuf);
    else
        fprintf(stderr, "[ERROR] %s: 0x%08X\n", context, (unsigned)hr);
}

// Narrow string → wide (heap allocated, caller frees with delete[])
static wchar_t* NarrowToWide(const char* s)
{
    int needed = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
    if (needed <= 0) return nullptr;
    wchar_t* w = new wchar_t[needed];
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, needed);
    return w;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(int argc, char* argv[])
{
    if (argc < 2) {
        fprintf(stderr,
            "com_client.exe — IFileInspector COM client\n\n"
            "Usage:\n"
            "  com_client.exe scan   <filepath>   scan file, print JSON report\n"
            "  com_client.exe procs               list running processes (JSON)\n"
            "  com_client.exe hash   <filepath>   SHA-256 of file\n"
            "  com_client.exe version             server version string\n\n"
            "Prerequisite: regsvr32 com_toolkit.dll\n");
        return 1;
    }

    const char* subcmd = argv[1];

    // Initialize COM
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        PrintError(hr, "CoInitializeEx");
        return 1;
    }

    // Get IFileInspector
    IFileInspector* pInsp = nullptr;
    hr = CoCreateInstance(CLSID_FileInspector, nullptr, CLSCTX_INPROC_SERVER,
                          IID_IFileInspector,
                          reinterpret_cast<void**>(&pInsp));
    if (FAILED(hr)) {
        PrintError(hr, "CoCreateInstance(CLSID_FileInspector)");
        fprintf(stderr,
            "  -> Is com_toolkit.dll registered?\n"
            "     Run (as admin): regsvr32 com_toolkit.dll\n");
        CoUninitialize();
        return 1;
    }

    int exitCode = 0;

    if (_stricmp(subcmd, "scan") == 0)
    {
        if (argc < 3) {
            fprintf(stderr, "Usage: com_client.exe scan <filepath>\n");
            exitCode = 1;
        } else {
            wchar_t* wPath = NarrowToWide(argv[2]);
            BSTR report = nullptr;
            hr = pInsp->ScanFile(wPath, &report);
            delete[] wPath;
            if (SUCCEEDED(hr)) {
                PrintBSTR(report);
                SysFreeString(report);
            } else {
                PrintError(hr, "ScanFile");
                exitCode = 1;
            }
        }
    }
    else if (_stricmp(subcmd, "procs") == 0)
    {
        BSTR list = nullptr;
        hr = pInsp->EnumProcesses(&list);
        if (SUCCEEDED(hr)) {
            PrintBSTR(list);
            SysFreeString(list);
        } else {
            PrintError(hr, "EnumProcesses");
            exitCode = 1;
        }
    }
    else if (_stricmp(subcmd, "hash") == 0)
    {
        if (argc < 3) {
            fprintf(stderr, "Usage: com_client.exe hash <filepath>\n");
            exitCode = 1;
        } else {
            wchar_t* wPath = NarrowToWide(argv[2]);
            BSTR hex = nullptr;
            hr = pInsp->HashFile(wPath, &hex);
            delete[] wPath;
            if (SUCCEEDED(hr)) {
                PrintBSTR(hex);
                SysFreeString(hex);
            } else {
                PrintError(hr, "HashFile");
                exitCode = 1;
            }
        }
    }
    else if (_stricmp(subcmd, "version") == 0)
    {
        BSTR ver = nullptr;
        hr = pInsp->GetVersion(&ver);
        if (SUCCEEDED(hr)) {
            PrintBSTR(ver);
            SysFreeString(ver);
        } else {
            PrintError(hr, "GetVersion");
            exitCode = 1;
        }
    }
    else
    {
        fprintf(stderr, "Unknown subcommand: %s\n"
                        "Valid: scan, procs, hash, version\n", subcmd);
        exitCode = 1;
    }

    pInsp->Release();
    CoUninitialize();
    return exitCode;
}
