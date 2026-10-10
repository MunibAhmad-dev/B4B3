/*
  Exercise 04 — User-Mode EDR Service (Event Consumer)
  ------------------------------------------------------
  The kernel driver (ex01-ex03) collects telemetry — but you need a
  user-mode service to:
    - Receive events from the kernel (via ETW or IOCTL/pipe)
    - Store them in a log
    - Apply detection rules
    - Alert (write to Windows Event Log, send HTTP, write a file)

  This exercise builds the user-mode half using ETW as the transport:
    - The kernel driver calls EventWrite with your custom provider GUID.
    - This service subscribes as an ETW consumer using the same GUID.
    - For each event, apply detection logic and log/alert.

  For simplicity this exercise re-uses the ETW Process Monitor from
  Module 19 (Microsoft-Windows-Kernel-Process) so it works without a
  custom kernel driver.

  Detection rules to implement:
    1. Office macro execution: WINWORD.EXE or EXCEL.EXE spawns cmd.exe/powershell
    2. Living-off-the-land: certutil.exe / mshta.exe / regsvr32.exe appears
    3. Process from suspicious path: any process from %TEMP% or %APPDATA%
    4. Rapid process creation: >5 unique processes in 1 second (loader behavior)
    5. Unusual parent-child: cmd.exe spawned by svchost.exe

  Tasks:
  1. Extend the ETW consumer from Module 19 (ex01_process_monitor) to:
     - Build a parent→child process map as you receive events.
     - Apply the 5 rules above.
     - Write alerts to C:\Windows\Temp\edr_alerts.log.
  2. Run as a Windows Service (use the skeleton from Module 27).
  3. Test: open a command prompt from Word (manually), observe the alert.

  BONUS:
  - Report to a remote C2-like server (HTTP POST to your team server).
  - Add a blocklist: read blocked process names from a JSON config file
    and set a flag in shared memory that the kernel driver can read to
    block process creation.

  Compile:
    g++ -std=c++17 -Wall -o edr_service.exe ex04_usermode_service.cpp
    -ladvapi32 -ltdh
*/

#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <evntcons.h>
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

#include <string>
#include <map>
#include <deque>
#include <fstream>
#include <cstdio>
#include <atomic>
#include <chrono>

using Clock = std::chrono::steady_clock;
using TP    = std::chrono::time_point<Clock>;

// --- ETW provider: Microsoft-Windows-Kernel-Process ---
static const GUID KERNEL_PROCESS_GUID = {
    0x22FB2CD6, 0x0E7B, 0x422B,
    {0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}
};

// Process table: PID → {image, parentPid}
struct ProcessInfo { std::string image; DWORD parentPid; };
static std::map<DWORD, ProcessInfo> g_processes;

// For rapid process detection
static std::deque<TP> g_recentCreates;

static TRACEHANDLE g_sessionHandle = 0;
static TRACEHANDLE g_traceHandle   = INVALID_PROCESSTRACE_HANDLE;
static std::atomic<bool> g_running{true};

static std::ofstream g_alertLog;

void alert(const std::string& rule, const std::string& detail) {
    char ts[32];
    SYSTEMTIME st; GetLocalTime(&st);
    sprintf_s(ts, "%04d-%02d-%02dT%02d:%02d:%02d",
              st.wYear, st.wMonth, st.wDay,
              st.wHour, st.wMinute, st.wSecond);

    std::string msg = std::string(ts) + "  [ALERT:" + rule + "]  " + detail;
    printf("%s\n", msg.c_str());
    if (g_alertLog.is_open()) g_alertLog << msg << "\n" << std::flush;
}

std::string toLower(std::string s) {
    for (auto& c : s) c = (char)tolower((unsigned char)c);
    return s;
}

// ---------- TODO: detection rules ----------
void applyRules(DWORD pid, DWORD parentPid, const std::string& image) {
    std::string imgLower = toLower(image);
    std::string parentImg;
    if (g_processes.count(parentPid)) parentImg = toLower(g_processes[parentPid].image);

    // Rule 1: Office macro execution
    static const char* officeProcs[] = {"winword.exe", "excel.exe", "powerpnt.exe"};
    static const char* shellProcs[]  = {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"};
    for (auto* o : officeProcs) {
        if (parentImg.find(o) != std::string::npos) {
            for (auto* s : shellProcs) {
                if (imgLower.find(s) != std::string::npos) {
                    alert("MACRO_EXEC", "Office spawned shell: " + image + " (parent=" + parentImg + ")");
                }
            }
        }
    }

    // Rule 2: Living-off-the-land binaries
    static const char* lotl[] = {"certutil.exe","mshta.exe","regsvr32.exe","rundll32.exe","wmic.exe"};
    for (auto* l : lotl) {
        if (imgLower.find(l) != std::string::npos) {
            alert("LOLBAS", "LOL binary launched: " + image);
        }
    }

    // Rule 3: Process from Temp/AppData
    // YOUR CODE HERE: check image path for \\Temp\\ or \\AppData\\
    // if (imgLower.find("\\temp\\") != std::string::npos || ...)
    //     alert("SUSPICIOUS_PATH", "Process from writable path: " + image);

    // Rule 4: Rapid process creation
    auto now = Clock::now();
    g_recentCreates.push_back(now);
    while (!g_recentCreates.empty() &&
           std::chrono::duration_cast<std::chrono::milliseconds>(
               now - g_recentCreates.front()).count() > 1000)
        g_recentCreates.pop_front();
    if (g_recentCreates.size() > 5)
        alert("RAPID_SPAWN", "5+ processes created in 1s (" +
              std::to_string(g_recentCreates.size()) + ")");

    // Rule 5: Unusual parent-child (cmd from svchost)
    if (parentImg.find("svchost.exe") != std::string::npos &&
        imgLower.find("cmd.exe") != std::string::npos)
        alert("UNUSUAL_PARENT", "cmd.exe spawned by svchost");
}

// ETW event callback
VOID WINAPI EventRecordCallback(PEVENT_RECORD pEvent) {
    if (!IsEqualGUID(pEvent->EventHeader.ProviderId, KERNEL_PROCESS_GUID)) return;

    DWORD eventId = pEvent->EventHeader.EventDescriptor.Id;
    ULONG bufSz = 0;
    TdhGetEventInformation(pEvent, 0, nullptr, nullptr, &bufSz);
    if (!bufSz) return;
    std::vector<BYTE> buf(bufSz);
    auto* info = (TRACE_EVENT_INFO*)buf.data();
    TdhGetEventInformation(pEvent, 0, nullptr, info, &bufSz);

    if (eventId == 1) { // ProcessStart
        // Extract pid, parentPid, imageName from event properties
        // (simplified — in production use TdhFormatProperty)
        DWORD pid = 0, ppid = 0;
        if (pEvent->UserDataLength >= 8) {
            pid  = *(DWORD*)pEvent->UserData;
            ppid = *(DWORD*)((BYTE*)pEvent->UserData + 4);
        }
        g_processes[pid] = { "unknown", ppid };
        applyRules(pid, ppid, "unknown");
    }
}

void startEtw() {
    const wchar_t* SESSION_NAME = L"EDRServiceSession";
    ULONG bufSize = sizeof(EVENT_TRACE_PROPERTIES) + (ULONG)(wcslen(SESSION_NAME) + 1) * 2;
    std::vector<BYTE> propBuf(bufSize, 0);
    auto* props = (EVENT_TRACE_PROPERTIES*)propBuf.data();
    props->Wnode.BufferSize    = bufSize;
    props->Wnode.ClientContext = 1;
    props->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
    props->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);
    memcpy((BYTE*)props + props->LoggerNameOffset, SESSION_NAME, wcslen(SESSION_NAME) * 2);

    StopTraceW(0, SESSION_NAME, props);
    StartTraceW(&g_sessionHandle, SESSION_NAME, props);
    EnableTraceEx2(g_sessionHandle, &KERNEL_PROCESS_GUID,
                   EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                   TRACE_LEVEL_INFORMATION, 0x10, 0, 0, nullptr);

    EVENT_TRACE_LOGFILEW logfile = {};
    logfile.LoggerName      = (LPWSTR)SESSION_NAME;
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = EventRecordCallback;
    g_traceHandle = OpenTraceW(&logfile);
    ProcessTrace(&g_traceHandle, 1, nullptr, nullptr);
}

int main() {
    g_alertLog.open("C:\\Windows\\Temp\\edr_alerts.log", std::ios::app);
    printf("[EDR] User-mode service starting...\n");
    printf("[EDR] Alert log: C:\\Windows\\Temp\\edr_alerts.log\n");
    startEtw();
    return 0;
}
