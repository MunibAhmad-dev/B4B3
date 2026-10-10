/*
 * com_toolkit.cpp — IFileInspector COM Server DLL
 *
 * A finished in-process COM server that provides file inspection,
 * process enumeration, and SHA-256 hashing as COM methods.
 *
 * Interface: IFileInspector
 *   IID  = {C3D4E5F6-3456-789A-CDEF-0123456789AB}
 *   CLSID = {D4E5F6A7-4567-89AB-DEF0-123456789ABC}
 *
 * Methods:
 *   ScanFile(path, &report)    — PE check, entropy, imports → JSON BSTR
 *   GetVersion(&ver)           — version string BSTR
 *   EnumProcesses(&jsonList)   — running processes → JSON array BSTR
 *   HashFile(path, &sha256hex) — SHA-256 of file → hex BSTR
 *
 * Build:
 *   g++ -shared -std=c++17 -o com_toolkit.dll com_toolkit.cpp \
 *       -lole32 -loleaut32 -luuid -ladvapi32 -lbcrypt
 *
 * Register:
 *   regsvr32 com_toolkit.dll
 *
 * Unregister:
 *   regsvr32 /u com_toolkit.dll
 */

#define WIN32_LEAN_AND_MEAN
#define UNICODE
#include <windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <unknwn.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdint.h>
#include <new>

#pragma comment(lib, "bcrypt.lib")

// ---------------------------------------------------------------------------
// GUIDs
// IID_IFileInspector  = {C3D4E5F6-3456-789A-CDEF-0123456789AB}
// CLSID_FileInspector = {D4E5F6A7-4567-89AB-DEF0-123456789ABC}
// ---------------------------------------------------------------------------
static const GUID IID_IFileInspector =
    { 0xC3D4E5F6, 0x3456, 0x789A,
      { 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB } };

static const GUID CLSID_FileInspector =
    { 0xD4E5F6A7, 0x4567, 0x89AB,
      { 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC } };

// ---------------------------------------------------------------------------
// IFileInspector — pure virtual interface
// ---------------------------------------------------------------------------
struct IFileInspector : public IUnknown
{
    virtual HRESULT __stdcall ScanFile(LPCWSTR path, BSTR* report) = 0;
    virtual HRESULT __stdcall GetVersion(BSTR* ver) = 0;
    virtual HRESULT __stdcall EnumProcesses(BSTR* jsonList) = 0;
    virtual HRESULT __stdcall HashFile(LPCWSTR path, BSTR* sha256hex) = 0;
};

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------
HINSTANCE g_hModule    = NULL;
LONG      g_ObjectCount = 0;
LONG      g_LockCount   = 0;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Narrow string → BSTR
static BSTR MakeBSTR(const char* s)
{
    int needed = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
    if (needed <= 0) return SysAllocString(L"");
    wchar_t* buf = new wchar_t[needed];
    MultiByteToWideChar(CP_UTF8, 0, s, -1, buf, needed);
    BSTR b = SysAllocString(buf);
    delete[] buf;
    return b;
}

// Escape a string for JSON (replaces backslash and double-quote only)
static void JsonEscape(const char* in, char* out, int outCch)
{
    int j = 0;
    for (int i = 0; in[i] && j < outCch - 2; i++) {
        if (in[i] == '\\' || in[i] == '"') {
            if (j < outCch - 3) { out[j++] = '\\'; }
        }
        out[j++] = in[i];
    }
    out[j] = '\0';
}

// Wide path → narrow UTF-8
static void WideToNarrow(LPCWSTR w, char* buf, int cch)
{
    WideCharToMultiByte(CP_UTF8, 0, w, -1, buf, cch, nullptr, nullptr);
}

// ---------------------------------------------------------------------------
// Shannon entropy of a byte buffer
// ---------------------------------------------------------------------------
static double ShannonEntropy(const uint8_t* data, size_t len)
{
    if (len == 0) return 0.0;
    unsigned long long freq[256] = {};
    for (size_t i = 0; i < len; i++) freq[data[i]]++;
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / (double)len;
        entropy -= p * log2(p);
    }
    return entropy;
}

// ---------------------------------------------------------------------------
// Walk PE import table — returns up to maxImports names in importList[]
// Returns count of imports found (0 if not a PE or no imports)
// ---------------------------------------------------------------------------
static int GetPEImports(const uint8_t* base, size_t fileSize,
                        char importList[][64], int maxImports)
{
    if (fileSize < sizeof(IMAGE_DOS_HEADER)) return 0;

    const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    DWORD peOffset = dos->e_lfanew;
    if (peOffset + sizeof(IMAGE_NT_HEADERS) > fileSize) return 0;

    const IMAGE_NT_HEADERS* nt =
        reinterpret_cast<const IMAGE_NT_HEADERS*>(base + peOffset);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    // Get import directory RVA
    DWORD importRVA = 0;
    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        const IMAGE_NT_HEADERS32* nt32 =
            reinterpret_cast<const IMAGE_NT_HEADERS32*>(base + peOffset);
        importRVA = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    } else if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        const IMAGE_NT_HEADERS64* nt64 =
            reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + peOffset);
        importRVA = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    } else {
        return 0;
    }

    if (importRVA == 0) return 0;

    // Resolve RVA to file offset using section headers
    WORD numSections = nt->FileHeader.NumberOfSections;
    DWORD sectionOffset = peOffset + sizeof(DWORD) +
                          sizeof(IMAGE_FILE_HEADER) +
                          nt->FileHeader.SizeOfOptionalHeader;

    auto RVAtoOffset = [&](DWORD rva) -> DWORD {
        const IMAGE_SECTION_HEADER* sec =
            reinterpret_cast<const IMAGE_SECTION_HEADER*>(base + sectionOffset);
        for (WORD i = 0; i < numSections; i++) {
            DWORD va  = sec[i].VirtualAddress;
            DWORD raw = sec[i].PointerToRawData;
            DWORD sz  = sec[i].SizeOfRawData;
            if (rva >= va && rva < va + sz) return raw + (rva - va);
        }
        return 0;
    };

    DWORD importOff = RVAtoOffset(importRVA);
    if (importOff == 0 || importOff >= fileSize) return 0;

    int count = 0;
    const IMAGE_IMPORT_DESCRIPTOR* desc =
        reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(base + importOff);

    while (count < maxImports) {
        if (desc->OriginalFirstThunk == 0 && desc->FirstThunk == 0) break;
        DWORD nameOff = RVAtoOffset(desc->Name);
        if (nameOff == 0 || nameOff >= fileSize) { desc++; continue; }
        const char* dllName = reinterpret_cast<const char*>(base + nameOff);
        strncpy(importList[count], dllName, 63);
        importList[count][63] = '\0';
        count++;
        desc++;
    }
    return count;
}

// ---------------------------------------------------------------------------
// SHA-256 via Windows CNG
// Returns hex string in hexOut (65 bytes: 64 hex chars + null)
// ---------------------------------------------------------------------------
static HRESULT SHA256File(const uint8_t* data, DWORD dataLen, char* hexOut)
{
    BCRYPT_ALG_HANDLE  hAlg  = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg,
                                         BCRYPT_SHA256_ALGORITHM,
                                         nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) return E_FAIL;

    DWORD hashLen = 0, cbData = 0;
    status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
                               (PUCHAR)&hashLen, sizeof(hashLen),
                               &cbData, 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return E_FAIL; }

    DWORD objLen = 0;
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                               (PUCHAR)&objLen, sizeof(objLen),
                               &cbData, 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return E_FAIL; }

    uint8_t* hashObj = new uint8_t[objLen];

    status = BCryptCreateHash(hAlg, &hHash, hashObj, objLen,
                              nullptr, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        delete[] hashObj;
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return E_FAIL;
    }

    status = BCryptHashData(hHash, (PUCHAR)data, dataLen, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        delete[] hashObj;
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return E_FAIL;
    }

    uint8_t hashBuf[32] = {};
    status = BCryptFinishHash(hHash, hashBuf, hashLen, 0);
    BCryptDestroyHash(hHash);
    delete[] hashObj;
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(status)) return E_FAIL;

    for (DWORD i = 0; i < hashLen; i++)
        sprintf(hexOut + i * 2, "%02x", hashBuf[i]);
    hexOut[hashLen * 2] = '\0';
    return S_OK;
}

// ---------------------------------------------------------------------------
// CFileInspector — IFileInspector implementation
// ---------------------------------------------------------------------------
class CFileInspector : public IFileInspector
{
public:
    CFileInspector() : m_refCount(0) {}

    // IUnknown
    ULONG __stdcall AddRef() override { return InterlockedIncrement(&m_refCount); }

    ULONG __stdcall Release() override {
        LONG ref = InterlockedDecrement(&m_refCount);
        if (ref == 0) { InterlockedDecrement(&g_ObjectCount); delete this; }
        return (ULONG)ref;
    }

    HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (IsEqualIID(riid, IID_IUnknown))
            *ppv = static_cast<IUnknown*>(this);
        else if (IsEqualIID(riid, IID_IFileInspector))
            *ppv = static_cast<IFileInspector*>(this);
        else { *ppv = nullptr; return E_NOINTERFACE; }
        AddRef();
        return S_OK;
    }

    // -----------------------------------------------------------------
    // ScanFile: open file, check MZ, compute entropy, walk import table
    // Returns JSON BSTR:
    //   {"path":"...","isPE":true,"entropy":6.42,
    //    "imports":["KERNEL32.dll","USER32.dll"],"verdict":"CLEAN"}
    // -----------------------------------------------------------------
    HRESULT __stdcall ScanFile(LPCWSTR path, BSTR* report) override
    {
        if (!path || !report) return E_POINTER;
        *report = nullptr;

        // Narrow path for JSON embedding
        char narrowPath[MAX_PATH] = {};
        WideToNarrow(path, narrowPath, MAX_PATH);
        char escapedPath[MAX_PATH * 2] = {};
        JsonEscape(narrowPath, escapedPath, sizeof(escapedPath));

        // Open file
        HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            char buf[MAX_PATH + 64];
            snprintf(buf, sizeof(buf),
                     "{\"error\":\"Cannot open file\",\"path\":\"%s\"}", escapedPath);
            *report = MakeBSTR(buf);
            return *report ? S_OK : E_OUTOFMEMORY;
        }

        LARGE_INTEGER liSize = {};
        GetFileSizeEx(hFile, &liSize);
        LONGLONG fileSize = liSize.QuadPart;

        // Read up to 1 MB for analysis
        DWORD readSize = (DWORD)min(fileSize, (LONGLONG)1024 * 1024);
        uint8_t* fileData = new uint8_t[readSize > 0 ? readSize : 1];
        DWORD bytesRead = 0;
        ReadFile(hFile, fileData, readSize, &bytesRead, nullptr);
        CloseHandle(hFile);

        // Check MZ signature
        bool isPE = (bytesRead >= 2 &&
                     fileData[0] == 'M' && fileData[1] == 'Z');

        // Entropy on first 4 KB
        DWORD entropyLen = min(bytesRead, (DWORD)4096);
        double entropy = ShannonEntropy(fileData, entropyLen);

        // High entropy threshold (packed/encrypted indicator)
        bool highEntropy = (entropy > 7.0);

        // Import table (PE only, up to 5)
        char importList[5][64] = {};
        int  importCount = 0;
        if (isPE && bytesRead > 0) {
            importCount = GetPEImports(fileData, bytesRead, importList, 5);
        }

        delete[] fileData;

        // Build imports JSON array
        char importsJson[512] = "[";
        for (int i = 0; i < importCount; i++) {
            char escaped[128] = {};
            JsonEscape(importList[i], escaped, sizeof(escaped));
            if (i > 0) strcat_s(importsJson, sizeof(importsJson), ",");
            strcat_s(importsJson, sizeof(importsJson), "\"");
            strcat_s(importsJson, sizeof(importsJson), escaped);
            strcat_s(importsJson, sizeof(importsJson), "\"");
        }
        strcat_s(importsJson, sizeof(importsJson), "]");

        // Verdict
        const char* verdict = "CLEAN";
        if (highEntropy && isPE) verdict = "SUSPICIOUS_HIGH_ENTROPY";
        else if (highEntropy)    verdict = "HIGH_ENTROPY";

        // Build final JSON
        char jsonBuf[2048];
        snprintf(jsonBuf, sizeof(jsonBuf),
                 "{\"path\":\"%s\",\"isPE\":%s,\"fileSize\":%lld,"
                 "\"entropy\":%.2f,\"highEntropy\":%s,"
                 "\"imports\":%s,\"verdict\":\"%s\"}",
                 escapedPath,
                 isPE ? "true" : "false",
                 fileSize,
                 entropy,
                 highEntropy ? "true" : "false",
                 importsJson,
                 verdict);

        *report = MakeBSTR(jsonBuf);
        return *report ? S_OK : E_OUTOFMEMORY;
    }

    // -----------------------------------------------------------------
    // GetVersion
    // -----------------------------------------------------------------
    HRESULT __stdcall GetVersion(BSTR* ver) override
    {
        if (!ver) return E_POINTER;
        *ver = SysAllocString(L"FileInspector COM Server 1.0");
        return *ver ? S_OK : E_OUTOFMEMORY;
    }

    // -----------------------------------------------------------------
    // EnumProcesses: Toolhelp32 snapshot → JSON array
    // Returns: [{"pid":4,"name":"System"},{"pid":1234,"name":"chrome.exe"}]
    // -----------------------------------------------------------------
    HRESULT __stdcall EnumProcesses(BSTR* jsonList) override
    {
        if (!jsonList) return E_POINTER;
        *jsonList = nullptr;

        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) return E_FAIL;

        // Collect into a growing buffer
        const int MAXBUF = 65536;
        char* buf = new char[MAXBUF];
        int   pos = 0;

        auto Append = [&](const char* s) {
            int len = (int)strlen(s);
            if (pos + len < MAXBUF - 1) {
                memcpy(buf + pos, s, len);
                pos += len;
            }
        };

        Append("[");

        PROCESSENTRY32W pe = {};
        pe.dwSize = sizeof(pe);
        bool first = true;

        if (Process32FirstW(hSnap, &pe)) {
            do {
                char nameNarrow[MAX_PATH] = {};
                WideToNarrow(pe.szExeFile, nameNarrow, MAX_PATH);
                char nameEsc[MAX_PATH * 2] = {};
                JsonEscape(nameNarrow, nameEsc, sizeof(nameEsc));

                char entry[256];
                snprintf(entry, sizeof(entry),
                         "%s{\"pid\":%lu,\"name\":\"%s\"}",
                         first ? "" : ",",
                         (unsigned long)pe.th32ProcessID,
                         nameEsc);
                Append(entry);
                first = false;
            } while (Process32NextW(hSnap, &pe));
        }

        CloseHandle(hSnap);
        Append("]");
        buf[pos] = '\0';

        *jsonList = MakeBSTR(buf);
        delete[] buf;
        return *jsonList ? S_OK : E_OUTOFMEMORY;
    }

    // -----------------------------------------------------------------
    // HashFile: compute SHA-256 of file contents via CNG, return hex BSTR
    // -----------------------------------------------------------------
    HRESULT __stdcall HashFile(LPCWSTR path, BSTR* sha256hex) override
    {
        if (!path || !sha256hex) return E_POINTER;
        *sha256hex = nullptr;

        HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return HRESULT_FROM_WIN32(GetLastError());

        LARGE_INTEGER liSize = {};
        GetFileSizeEx(hFile, &liSize);
        DWORD fileSize = (DWORD)min(liSize.QuadPart, (LONGLONG)64 * 1024 * 1024);

        uint8_t* data = new uint8_t[fileSize > 0 ? fileSize : 1];
        DWORD    bytesRead = 0;
        ReadFile(hFile, data, fileSize, &bytesRead, nullptr);
        CloseHandle(hFile);

        char hexBuf[65] = {};
        HRESULT hr = SHA256File(data, bytesRead, hexBuf);
        delete[] data;

        if (FAILED(hr)) return hr;

        *sha256hex = MakeBSTR(hexBuf);
        return *sha256hex ? S_OK : E_OUTOFMEMORY;
    }

private:
    LONG m_refCount;
};

// ---------------------------------------------------------------------------
// CClassFactory
// ---------------------------------------------------------------------------
class CClassFactory : public IClassFactory
{
public:
    CClassFactory() : m_refCount(0) {}

    ULONG __stdcall AddRef() override { return InterlockedIncrement(&m_refCount); }

    ULONG __stdcall Release() override {
        LONG ref = InterlockedDecrement(&m_refCount);
        if (ref == 0) delete this;
        return (ULONG)ref;
    }

    HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (IsEqualIID(riid, IID_IUnknown))
            *ppv = static_cast<IUnknown*>(this);
        else if (IsEqualIID(riid, IID_IClassFactory))
            *ppv = static_cast<IClassFactory*>(this);
        else { *ppv = nullptr; return E_NOINTERFACE; }
        AddRef();
        return S_OK;
    }

    HRESULT __stdcall CreateInstance(IUnknown* pOuter, REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        *ppv = nullptr;
        if (pOuter) return CLASS_E_NOAGGREGATION;

        CFileInspector* p = new (std::nothrow) CFileInspector();
        if (!p) return E_OUTOFMEMORY;
        InterlockedIncrement(&g_ObjectCount);

        HRESULT hr = p->QueryInterface(riid, ppv);
        if (FAILED(hr)) { InterlockedDecrement(&g_ObjectCount); delete p; }
        return hr;
    }

    HRESULT __stdcall LockServer(BOOL fLock) override {
        fLock ? InterlockedIncrement(&g_LockCount)
              : InterlockedDecrement(&g_LockCount);
        return S_OK;
    }

private:
    LONG m_refCount;
};

// ---------------------------------------------------------------------------
// Registry helpers
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

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID)
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
    if (!IsEqualCLSID(clsid, CLSID_FileInspector))
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
    GuidToStringW(CLSID_FileInspector, szCLSID, 64);

    // HKCR\CLSID\{...}
    wchar_t szKey[256];
    swprintf_s(szKey, 256, L"CLSID\\%s", szCLSID);

    HKEY hKey = NULL;
    LONG lRes = RegCreateKeyExW(HKEY_CLASSES_ROOT, szKey,
                                0, nullptr, REG_OPTION_NON_VOLATILE,
                                KEY_WRITE, nullptr, &hKey, nullptr);
    if (lRes != ERROR_SUCCESS) return HRESULT_FROM_WIN32(lRes);

    const wchar_t* szName = L"FileInspector COM Server";
    RegSetValueExW(hKey, nullptr, 0, REG_SZ,
                   (const BYTE*)szName,
                   (DWORD)((wcslen(szName) + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);

    // HKCR\CLSID\{...}\InprocServer32
    wchar_t szInproc[256];
    swprintf_s(szInproc, 256, L"CLSID\\%s\\InprocServer32", szCLSID);

    lRes = RegCreateKeyExW(HKEY_CLASSES_ROOT, szInproc,
                           0, nullptr, REG_OPTION_NON_VOLATILE,
                           KEY_WRITE, nullptr, &hKey, nullptr);
    if (lRes != ERROR_SUCCESS) return HRESULT_FROM_WIN32(lRes);

    wchar_t szPath[MAX_PATH] = {};
    GetModuleFileNameW(g_hModule, szPath, MAX_PATH);
    RegSetValueExW(hKey, nullptr, 0, REG_SZ,
                   (const BYTE*)szPath,
                   (DWORD)((wcslen(szPath) + 1) * sizeof(wchar_t)));

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
    GuidToStringW(CLSID_FileInspector, szCLSID, 64);

    wchar_t szKey[256];
    swprintf_s(szKey, 256, L"CLSID\\%s", szCLSID);

    LONG lRes = RegDeleteTreeW(HKEY_CLASSES_ROOT, szKey);
    if (lRes != ERROR_SUCCESS && lRes != ERROR_FILE_NOT_FOUND)
        return HRESULT_FROM_WIN32(lRes);
    return S_OK;
}

} // extern "C"
