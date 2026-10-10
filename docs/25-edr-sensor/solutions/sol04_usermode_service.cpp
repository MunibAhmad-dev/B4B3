/*
  Solution 04 — User-Mode EDR Service (ETW Consumer with Detection Rules)
  -------------------------------------------------------------------------
  Complete ETW-based process telemetry consumer with five detection rules:
    1. Office macro execution: Office app (Word/Excel/Outlook) spawns a shell.
    2. LOLBAS: mshta.exe / regsvr32.exe / rundll32.exe / certutil.exe / wscript.exe launched.
    3. Suspicious path: process launched from \AppData\ or \Temp\.
    4. Rapid spawn: >5 processes spawned in 1 second (loader/dropper behavior).
    5. Unusual parent: svchost.exe spawns cmd.exe.

  Uses Microsoft-Windows-Kernel-Process provider so no custom kernel driver is needed.
  Alerts are written to C:\Windows\Temp\edr_alerts.log and stdout.

  Compile:
    g++ -std=c++17 -Wall -o sol04_edr_service.exe sol04_usermode_service.cpp
        -ladvapi32 -ltdh
  Run as Administrator (ETW kernel provider requires elevation).
  Press Ctrl+C to stop.
*/

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <evntcons.h>

#include <string>
#include <map>
#include <vector>
#include <deque>
#include <fstream>
#include <cstdio>
#include <atomic>
#include <thread>
#include <mutex>
#include <chrono>
#include <algorithm>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

using Clock = std::chrono::steady_clock;
using TP    = std::chrono::time_point<Clock>;

// Microsoft-Windows-Kernel-Process provider GUID
static const GUID KERNEL_PROCESS_GUID = {
    0x22FB2CD6, 0x0E7B, 0x422B,
    {0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}
};

static const wchar_t* SESSION_NAME = L"EDRServiceSession";

// Process info table
struct ProcessInfo {
    std::string imageName;   // base name, e.g. "cmd.exe"
    std::string imagePath;   // full path
    DWORD       parentPid;
};

static std::map<DWORD, ProcessInfo> g_processes;
static std::mutex                   g_procMutex;

// Rapid-spawn window
static std::deque<TP> g_recentCreates;

// ETW handles
static TRACEHANDLE g_sessionHandle = 0;
static TRACEHANDLE g_traceHandle   = INVALID_PROCESSTRACE_HANDLE;
static std::atomic<bool> g_running{true};

// Alert log
static std::ofstream g_alertLog;

// ---- Helper: timestamp string ----
static std::string timestamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[32];
    sprintf_s(buf, "%04d-%02d-%02dT%02d:%02d:%02d",
              st.wYear, st.wMonth, st.wDay,
              st.wHour, st.wMinute, st.wSecond);
    return buf;
}

// ---- Alert emitter ----
static void alert(const std::string& rule, const std::string& detail) {
    std::string msg = timestamp() + "  [ALERT:" + rule + "]  " + detail;
    printf("%s\n", msg.c_str());
    if (g_alertLog.is_open())
        g_alertLog << msg << "\n" << std::flush;
}

// ---- String helpers ----
static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return (char)tolower(c); });
    return s;
}

static bool containsI(const std::string& haystack, const char* needle) {
    return toLower(haystack).find(needle) != std::string::npos;
}

static bool matchesAny(const std::string& s, const std::vector<const char*>& list) {
    std::string lower = toLower(s);
    for (auto* item : list)
        if (lower.find(item) != std::string::npos)
            return true;
    return false;
}

// ---- Extract a WCHAR property from an ETW event record ----
static std::string GetWCharProp(PEVENT_RECORD pEvent,
                                 PTRACE_EVENT_INFO pInfo,
                                 const wchar_t* propName) {
    // Find property index
    for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; i++) {
        LPWSTR name = (LPWSTR)((BYTE*)pInfo + pInfo->EventPropertyInfoArray[i].NameOffset);
        if (wcscmp(name, propName) == 0) {
            PROPERTY_DATA_DESCRIPTOR desc = {};
            desc.PropertyName = (ULONGLONG)propName;
            desc.ArrayIndex   = ULONG_MAX;

            ULONG propSize = 0;
            if (TdhGetPropertySize(pEvent, 0, nullptr, 1, &desc, &propSize) != ERROR_SUCCESS
                || propSize == 0)
                return "";

            std::vector<BYTE> buf(propSize + 2, 0);
            if (TdhGetProperty(pEvent, 0, nullptr, 1, &desc, propSize, buf.data()) != ERROR_SUCCESS)
                return "";

            // Convert wide string to narrow
            LPWSTR ws = (LPWSTR)buf.data();
            int len = WideCharToMultiByte(CP_UTF8, 0, ws, -1, nullptr, 0, nullptr, nullptr);
            if (len <= 0) return "";
            std::string result(len - 1, '\0');
            WideCharToMultiByte(CP_UTF8, 0, ws, -1, &result[0], len, nullptr, nullptr);
            return result;
        }
    }
    return "";
}

// ---- Base name from path ----
static std::string baseName(const std::string& path) {
    size_t pos = path.rfind('\\');
    return (pos == std::string::npos) ? path : path.substr(pos + 1);
}

// ---- Detection rules ----
static void applyRules(DWORD pid, DWORD parentPid,
                        const std::string& imagePath,
                        const std::string& imageNameRaw) {
    std::string imgName  = toLower(imageNameRaw.empty() ? baseName(imagePath) : imageNameRaw);
    std::string imgPath  = toLower(imagePath);
    std::string parentName;

    {
        std::lock_guard<std::mutex> lk(g_procMutex);
        auto it = g_processes.find(parentPid);
        if (it != g_processes.end())
            parentName = toLower(it->second.imageName);
    }

    // --- Rule 1: Office -> Shell (macro execution) ---
    static const std::vector<const char*> officeProcs = {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"
    };
    static const std::vector<const char*> shellProcs = {
        "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"
    };
    if (matchesAny(parentName, officeProcs) && matchesAny(imgName, shellProcs)) {
        alert("MACRO_EXEC",
              "Office process spawned shell: parent=" + parentName
              + " child=" + imgName
              + " PID=" + std::to_string(pid));
    }

    // --- Rule 2: LOLBAS detection ---
    static const std::vector<const char*> lolbas = {
        "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe", "wscript.exe"
    };
    if (matchesAny(imgName, lolbas)) {
        alert("LOLBAS",
              "Living-off-the-land binary: " + imgName
              + " PID=" + std::to_string(pid));
    }

    // --- Rule 3: Suspicious path ---
    if (containsI(imgPath, "\\appdata\\") || containsI(imgPath, "\\temp\\")) {
        alert("SUSPICIOUS_PATH",
              "Process from writable path: " + imagePath
              + " PID=" + std::to_string(pid));
    }

    // --- Rule 4: Rapid process spawn (>5 in 1 second) ---
    {
        auto now = Clock::now();
        g_recentCreates.push_back(now);
        while (!g_recentCreates.empty() &&
               std::chrono::duration_cast<std::chrono::milliseconds>(
                   now - g_recentCreates.front()).count() > 1000)
            g_recentCreates.pop_front();

        if (g_recentCreates.size() > 5) {
            alert("RAPID_SPAWN",
                  std::to_string(g_recentCreates.size())
                  + " processes spawned in <1s (loader behavior?)");
        }
    }

    // --- Rule 5: svchost spawns cmd.exe ---
    if (parentName.find("svchost.exe") != std::string::npos &&
        imgName.find("cmd.exe") != std::string::npos) {
        alert("UNUSUAL_PARENT",
              "cmd.exe spawned by svchost.exe"
              + std::string(" parentPID=") + std::to_string(parentPid)
              + " childPID=" + std::to_string(pid));
    }
}

// ---- ETW Event Record Callback ----
static VOID WINAPI EventRecordCallback(PEVENT_RECORD pEvent) {
    if (!IsEqualGUID(pEvent->EventHeader.ProviderId, KERNEL_PROCESS_GUID)) return;

    ULONG bufSz = 0;
    if (TdhGetEventInformation(pEvent, 0, nullptr, nullptr, &bufSz) != ERROR_INSUFFICIENT_BUFFER
        || bufSz == 0)
        return;

    std::vector<BYTE> infoBuf(bufSz);
    auto* pInfo = reinterpret_cast<TRACE_EVENT_INFO*>(infoBuf.data());
    if (TdhGetEventInformation(pEvent, 0, nullptr, pInfo, &bufSz) != ERROR_SUCCESS)
        return;

    USHORT eventId = pEvent->EventHeader.EventDescriptor.Id;

    if (eventId == 1) {
        // ProcessStart / process creation
        std::string pid_s      = GetWCharProp(pEvent, pInfo, L"ProcessID");
        std::string ppid_s     = GetWCharProp(pEvent, pInfo, L"ParentProcessID");
        std::string imageName  = GetWCharProp(pEvent, pInfo, L"ImageName");

        DWORD pid  = pid_s.empty()  ? 0 : (DWORD)atoi(pid_s.c_str());
        DWORD ppid = ppid_s.empty() ? 0 : (DWORD)atoi(ppid_s.c_str());

        std::string base = baseName(imageName);

        {
            std::lock_guard<std::mutex> lk(g_procMutex);
            g_processes[pid] = { base, imageName, ppid };
        }

        applyRules(pid, ppid, imageName, base);
    } else if (eventId == 2) {
        // ProcessStop / process exit — clean up our table
        std::string pid_s = GetWCharProp(pEvent, pInfo, L"ProcessID");
        if (!pid_s.empty()) {
            DWORD pid = (DWORD)atoi(pid_s.c_str());
            std::lock_guard<std::mutex> lk(g_procMutex);
            g_processes.erase(pid);
        }
    }
}

// ---- Stop ETW session ----
static void stopEtw() {
    if (g_traceHandle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(g_traceHandle);
        g_traceHandle = INVALID_PROCESSTRACE_HANDLE;
    }
    if (g_sessionHandle != 0) {
        ULONG bufSize = sizeof(EVENT_TRACE_PROPERTIES)
                      + (ULONG)(wcslen(SESSION_NAME) + 1) * sizeof(wchar_t);
        std::vector<BYTE> propBuf(bufSize, 0);
        auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propBuf.data());
        props->Wnode.BufferSize   = bufSize;
        props->LoggerNameOffset   = sizeof(EVENT_TRACE_PROPERTIES);
        StopTraceW(g_sessionHandle, SESSION_NAME, props);
        g_sessionHandle = 0;
    }
}

// ---- Start ETW session and blocking trace ----
static void runEtw() {
    ULONG bufSize = sizeof(EVENT_TRACE_PROPERTIES)
                  + (ULONG)(wcslen(SESSION_NAME) + 1) * sizeof(wchar_t);
    std::vector<BYTE> propBuf(bufSize, 0);
    auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propBuf.data());
    props->Wnode.BufferSize    = bufSize;
    props->Wnode.ClientContext  = 1;   // QPC clock
    props->Wnode.Flags          = WNODE_FLAG_TRACED_GUID;
    props->LogFileMode          = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset     = sizeof(EVENT_TRACE_PROPERTIES);
    memcpy((BYTE*)props + props->LoggerNameOffset,
           SESSION_NAME, wcslen(SESSION_NAME) * sizeof(wchar_t));

    // Stop any previous session with the same name
    StopTraceW(0, SESSION_NAME, props);
    RtlZeroMemory((BYTE*)props + sizeof(EVENT_TRACE_PROPERTIES),
                  bufSize - sizeof(EVENT_TRACE_PROPERTIES));
    memcpy((BYTE*)props + props->LoggerNameOffset,
           SESSION_NAME, wcslen(SESSION_NAME) * sizeof(wchar_t));
    props->Wnode.BufferSize   = bufSize;
    props->Wnode.Flags        = WNODE_FLAG_TRACED_GUID;
    props->LogFileMode        = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset   = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG rc = StartTraceW(&g_sessionHandle, SESSION_NAME, props);
    if (rc != ERROR_SUCCESS) {
        printf("[-] StartTraceW: %lu\n", rc);
        return;
    }

    // Enable Microsoft-Windows-Kernel-Process provider
    rc = EnableTraceEx2(g_sessionHandle, &KERNEL_PROCESS_GUID,
                         EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                         TRACE_LEVEL_INFORMATION,
                         0x10,  // keyword: process events
                         0, 0, nullptr);
    if (rc != ERROR_SUCCESS)
        printf("[!] EnableTraceEx2: %lu (may need elevation)\n", rc);

    // Open trace for real-time consumption
    EVENT_TRACE_LOGFILEW logfile = {};
    logfile.LoggerName       = (LPWSTR)SESSION_NAME;
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME
                             | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = EventRecordCallback;

    g_traceHandle = OpenTraceW(&logfile);
    if (g_traceHandle == INVALID_PROCESSTRACE_HANDLE) {
        printf("[-] OpenTraceW: %lu\n", GetLastError());
        stopEtw();
        return;
    }

    printf("[EDR] Trace started. Watching for process events...\n");
    // ProcessTrace blocks until CloseTrace() is called from another thread
    ProcessTrace(&g_traceHandle, 1, nullptr, nullptr);
}

// ---- Ctrl+C handler ----
static BOOL WINAPI CtrlHandler(DWORD ctrlType) {
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT) {
        printf("\n[EDR] Stopping...\n");
        g_running = false;
        stopEtw();
        return TRUE;
    }
    return FALSE;
}

int main() {
    // Open alert log
    g_alertLog.open("C:\\Windows\\Temp\\edr_alerts.log", std::ios::app);
    if (!g_alertLog.is_open())
        printf("[!] Could not open alert log (check permissions)\n");

    printf("[EDR] User-mode EDR service starting\n");
    printf("[EDR] Alert log: C:\\Windows\\Temp\\edr_alerts.log\n");
    printf("[EDR] Press Ctrl+C to stop\n\n");
    printf("[EDR] Detection rules active:\n");
    printf("  1. Office macro execution (Word/Excel/Outlook -> shell)\n");
    printf("  2. LOLBAS (mshta, regsvr32, rundll32, certutil, wscript)\n");
    printf("  3. Process from %%APPDATA%% or %%TEMP%%\n");
    printf("  4. Rapid process spawn (>5 in 1 second)\n");
    printf("  5. svchost.exe spawns cmd.exe\n\n");

    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    // Run ETW consumer in a separate thread so main can handle signals
    std::thread etwThread(runEtw);

    // Main loop — wait for stop signal
    while (g_running) {
        Sleep(500);
    }

    stopEtw();
    if (etwThread.joinable()) etwThread.join();

    printf("[EDR] Stopped.\n");
    return 0;
}
