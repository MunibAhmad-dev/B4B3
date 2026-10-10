/*
  Module 19 — ETW Consumer
  Exercise 01 Solution — Real-Time Process Monitor
  =================================================
  Uses the Windows Event Tracing (ETW) API to receive a real-time callback
  for every process start and stop on the system — no polling, no snapshots.

  Provider:  Microsoft-Windows-Kernel-Process
  GUID:      {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
  EventIDs:  1 = ProcessStart, 2 = ProcessStop

  Key ETW APIs used:
    StartTrace      — create a real-time trace session
    EnableTraceEx2  — subscribe a provider to that session
    OpenTrace       — attach a consumer with a callback
    ProcessTrace    — blocking pump that delivers events to the callback
    CloseTrace      — shut down the consumer
    ControlTrace    — stop/query/flush a session

  TDH APIs for property decoding:
    TdhGetEventInformation — retrieve event schema (TRACE_EVENT_INFO)
    TdhFormatProperty      — decode a single property value to a string

  Expected output (while opening/closing programs):
    [PROCESS START] PID=12345  PPID=4321  Image=notepad.exe
    [PROCESS STOP]  PID=12345

  IMPORTANT: Requires Administrator privileges to start ETW sessions.

  Compile:
    g++ -std=c++17 -Wall -o sol01.exe sol01_process_monitor.cpp \
        -lkernel32 -ltdh -lAdvAPI32
*/

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <iostream>
#include <string>
#include <vector>
#include <signal.h>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

// ---------------------------------------------------------------------------
// Provider and session constants
// ---------------------------------------------------------------------------

// Microsoft-Windows-Kernel-Process GUID
// {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
static const GUID KERNEL_PROCESS_GUID = {
    0x22FB2CD6, 0x0E7B, 0x422B,
    {0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}
};

static const wchar_t* SESSION_NAME    = L"MyProcessMonitor";
static TRACEHANDLE    g_SessionHandle = 0;
static TRACEHANDLE    g_TraceHandle   = INVALID_PROCESSTRACE_HANDLE;
static volatile bool  g_Running       = true;

// ETW event IDs for Microsoft-Windows-Kernel-Process
#define EVENT_PROCESS_START  1
#define EVENT_PROCESS_STOP   2
#define EVENT_THREAD_START   3
#define EVENT_THREAD_STOP    4
#define EVENT_IMAGE_LOAD     5

// ---------------------------------------------------------------------------
// getProperty
// ---------------------------------------------------------------------------
// Decodes a named property from an EVENT_RECORD using the TDH (Trace Data
// Helper) API and returns it as a wide string. Returns L"?" on failure.
//
// Steps:
//  1. TdhGetEventInformation — fetch the full TRACE_EVENT_INFO for this event.
//     This describes every property (name, type, offsets).
//  2. Find the property index by scanning PropertyNameOffset entries.
//  3. TdhFormatProperty — decode the raw bytes into a human-readable wstring.
// ---------------------------------------------------------------------------
std::wstring getProperty(PEVENT_RECORD rec, const wchar_t* propName) {
    // -----------------------------------------------------------------------
    // Step 1: Allocate TRACE_EVENT_INFO.
    //
    // Call once with size 0 to get the required buffer size, then allocate
    // and call again.
    // -----------------------------------------------------------------------
    ULONG bufSize = 0;
    ULONG status  = TdhGetEventInformation(rec, 0, nullptr, nullptr, &bufSize);
    if (status != ERROR_INSUFFICIENT_BUFFER) {
        return L"?";
    }

    std::vector<BYTE> teiBuffer(bufSize);
    PTRACE_EVENT_INFO tei = reinterpret_cast<PTRACE_EVENT_INFO>(teiBuffer.data());

    status = TdhGetEventInformation(rec, 0, nullptr, tei, &bufSize);
    if (status != ERROR_SUCCESS) {
        return L"?";
    }

    // -----------------------------------------------------------------------
    // Step 2: Find the property index whose name matches propName.
    //
    // Property names are stored as offsets from the start of the TEI buffer.
    // -----------------------------------------------------------------------
    USHORT propIndex = 0;
    bool   found     = false;
    for (ULONG i = 0; i < tei->PropertyCount; i++) {
        const wchar_t* name = (const wchar_t*)((PBYTE)tei
            + tei->EventPropertyInfoArray[i].NameOffset);
        if (_wcsicmp(name, propName) == 0) {
            propIndex = (USHORT)i;
            found     = true;
            break;
        }
    }
    if (!found) {
        return L"?";
    }

    // -----------------------------------------------------------------------
    // Step 3: Decode the property value using TdhFormatProperty.
    //
    // We need the pointer and size of the property's raw bytes within the
    // event's UserData block. For simple fixed/variable-length properties
    // the standard approach is to walk the UserData accumulating offsets,
    // but for educational clarity we use TdhFormatProperty with the whole
    // UserData block and let TDH do the offset arithmetic.
    //
    // UserDataConsumed out-parameter tracks how many bytes TDH consumed,
    // which we don't need here since we ask for one property at a time.
    // -----------------------------------------------------------------------
    USHORT userDataConsumed = 0;
    ULONG  formattedSize    = 0;

    // First call: get required buffer size.
    status = TdhFormatProperty(
        tei,
        nullptr,                          // no map info
        sizeof(ULONG_PTR),                // pointer size (8 on 64-bit)
        tei->EventPropertyInfoArray[propIndex].nonStructType.InType,
        tei->EventPropertyInfoArray[propIndex].nonStructType.OutType,
        tei->EventPropertyInfoArray[propIndex].length,
        (USHORT)rec->UserDataLength,
        (PBYTE)rec->UserData,
        &formattedSize,
        nullptr,
        &userDataConsumed);

    if (status != ERROR_INSUFFICIENT_BUFFER && status != ERROR_SUCCESS) {
        return L"?";
    }

    // Second call: fill the buffer.
    std::vector<wchar_t> formatted(formattedSize / sizeof(wchar_t) + 1, L'\0');
    status = TdhFormatProperty(
        tei,
        nullptr,
        sizeof(ULONG_PTR),
        tei->EventPropertyInfoArray[propIndex].nonStructType.InType,
        tei->EventPropertyInfoArray[propIndex].nonStructType.OutType,
        tei->EventPropertyInfoArray[propIndex].length,
        (USHORT)rec->UserDataLength,
        (PBYTE)rec->UserData,
        &formattedSize,
        formatted.data(),
        &userDataConsumed);

    if (status != ERROR_SUCCESS) {
        return L"?";
    }

    return std::wstring(formatted.data());
}

// ---------------------------------------------------------------------------
// EventRecordCallback
// ---------------------------------------------------------------------------
// Called by ProcessTrace() for each event the provider emits.
// We filter on EventDescriptor.Id to handle process start/stop only.
// ---------------------------------------------------------------------------
VOID WINAPI EventRecordCallback(PEVENT_RECORD EventRecord) {
    // Ignore events from providers other than the one we subscribed to.
    // (ProcessTrace may deliver bookkeeping events with ProviderId == 0.)
    if (IsEqualGUID(EventRecord->EventHeader.ProviderId, GUID_NULL)) {
        return;
    }

    USHORT eventId = EventRecord->EventHeader.EventDescriptor.Id;

    if (eventId == EVENT_PROCESS_START) {
        // ------------------------------------------------------------------
        // Process started — extract PID, PPID, and image name.
        //
        // The Microsoft-Windows-Kernel-Process ProcessStart event schema:
        //   ProcessID         UINT32  (PID of the new process)
        //   ParentProcessID   UINT32  (PID of the creating process)
        //   ImageName         UNICODE_STRING / UnicodeString (path)
        //   SessionID         UINT32
        //   Flags             UINT32
        // ------------------------------------------------------------------
        std::wstring pid    = getProperty(EventRecord, L"ProcessID");
        std::wstring ppid   = getProperty(EventRecord, L"ParentProcessID");
        std::wstring image  = getProperty(EventRecord, L"ImageName");

        // Strip path, keep base name for readability.
        size_t slash = image.rfind(L'\\');
        std::wstring baseName = (slash != std::wstring::npos)
                                ? image.substr(slash + 1)
                                : image;

        wprintf(L"[PROCESS START] PID=%-6s  PPID=%-6s  Image=%s\n",
                pid.c_str(), ppid.c_str(), baseName.c_str());

    } else if (eventId == EVENT_PROCESS_STOP) {
        // ------------------------------------------------------------------
        // Process stopped — extract PID.
        //
        // ProcessStop schema also has ExitCode; grab it for completeness.
        // ------------------------------------------------------------------
        std::wstring pid      = getProperty(EventRecord, L"ProcessID");
        std::wstring exitCode = getProperty(EventRecord, L"ExitCode");

        wprintf(L"[PROCESS STOP]  PID=%-6s  ExitCode=%s\n",
                pid.c_str(), exitCode.c_str());

    }
    // Silently ignore thread start/stop, image load, and other events.
}

// ---------------------------------------------------------------------------
// BufferCallback
// ---------------------------------------------------------------------------
// Called by ProcessTrace() after each buffer of events is delivered.
// Returning FALSE tells ProcessTrace to stop; we use it to implement Ctrl+C.
// ---------------------------------------------------------------------------
ULONG WINAPI BufferCallback(PEVENT_TRACE_LOGFILEW logfile) {
    UNREFERENCED_PARAMETER(logfile);
    return g_Running ? TRUE : FALSE;
}

// ---------------------------------------------------------------------------
// cleanupSession
// ---------------------------------------------------------------------------
void cleanupSession() {
    // Close the consumer handle (stops ProcessTrace from blocking).
    if (g_TraceHandle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(g_TraceHandle);
        g_TraceHandle = INVALID_PROCESSTRACE_HANDLE;
    }

    // Stop the trace session (frees the kernel-side session).
    if (g_SessionHandle) {
        // EVENT_TRACE_PROPERTIES must be large enough to hold the session name
        // string that follows it in memory.
        ULONG nameLen  = (ULONG)((wcslen(SESSION_NAME) + 1) * sizeof(wchar_t));
        ULONG propSize = sizeof(EVENT_TRACE_PROPERTIES) + nameLen;
        auto* props    = (EVENT_TRACE_PROPERTIES*)calloc(1, propSize);
        if (props) {
            props->Wnode.BufferSize = propSize;
            ControlTrace(g_SessionHandle, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
            free(props);
        }
        g_SessionHandle = 0;
    }
}

// ---------------------------------------------------------------------------
// Signal handler — Ctrl+C
// ---------------------------------------------------------------------------
void ctrlCHandler(int) {
    g_Running = false;
    cleanupSession();  // unblock ProcessTrace
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    signal(SIGINT, ctrlCHandler);

    wprintf(L"[*] ETW Process Monitor — Module 19 Exercise 01 Solution\n");
    wprintf(L"[*] Requires Administrator privileges.\n");
    wprintf(L"[*] Press Ctrl+C to stop.\n\n");

    // -----------------------------------------------------------------------
    // Step 1: Build and start the trace session.
    //
    // EVENT_TRACE_PROPERTIES is a variable-length structure; the session
    // name string must be appended immediately after the fixed part.
    // -----------------------------------------------------------------------
    ULONG nameLen  = (ULONG)((wcslen(SESSION_NAME) + 1) * sizeof(wchar_t));
    ULONG propSize = sizeof(EVENT_TRACE_PROPERTIES) + nameLen;
    auto* props    = (EVENT_TRACE_PROPERTIES*)calloc(1, propSize);
    if (!props) {
        wprintf(L"[-] Out of memory\n");
        return 1;
    }

    props->Wnode.BufferSize    = propSize;
    props->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;  // QPC clock (high-resolution timestamps)
    props->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
    props->MaximumFileSize     = 0;
    // LoggerNameOffset: the name string lives right after the fixed struct.
    props->LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);
    // Copy the session name into the appended buffer.
    wcscpy_s((wchar_t*)((PBYTE)props + props->LoggerNameOffset),
             wcslen(SESSION_NAME) + 1, SESSION_NAME);

    ULONG startStatus = StartTrace(&g_SessionHandle, SESSION_NAME, props);

    if (startStatus == ERROR_ALREADY_EXISTS) {
        // A previous run crashed and left the session open — stop it and retry.
        wprintf(L"[!] Session already exists; stopping old session...\n");
        ControlTrace(0, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
        ZeroMemory(props, propSize);
        props->Wnode.BufferSize    = propSize;
        props->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
        props->Wnode.ClientContext = 1;
        props->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
        props->LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);
        wcscpy_s((wchar_t*)((PBYTE)props + props->LoggerNameOffset),
                 wcslen(SESSION_NAME) + 1, SESSION_NAME);
        startStatus = StartTrace(&g_SessionHandle, SESSION_NAME, props);
    }
    free(props);

    if (startStatus != ERROR_SUCCESS) {
        wprintf(L"[-] StartTrace failed: %lu\n", startStatus);
        if (startStatus == ERROR_ACCESS_DENIED)
            wprintf(L"    Run as Administrator.\n");
        return 1;
    }
    wprintf(L"[+] Trace session started (handle=0x%llX)\n",
            (ULONG64)g_SessionHandle);

    // -----------------------------------------------------------------------
    // Step 2: Enable the Microsoft-Windows-Kernel-Process provider.
    //
    // EnableTraceEx2 attaches the provider to our session and sets the
    // event level and keyword filter.
    //   Level   = TRACE_LEVEL_INFORMATION (4) — process events are informational.
    //   Keywords = 0x10  (PROCESS keyword for this provider — filters to
    //             process start/stop events; 0 = all keywords / no filter).
    // -----------------------------------------------------------------------
    ENABLE_TRACE_PARAMETERS etp = {};
    etp.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;

    ULONG enableStatus = EnableTraceEx2(
        g_SessionHandle,
        &KERNEL_PROCESS_GUID,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,  // 4
        0x10,                     // keyword: PROCESS (process start/stop events)
        0,                        // match any keyword
        0,                        // timeout (0 = asynchronous)
        &etp);

    if (enableStatus != ERROR_SUCCESS) {
        wprintf(L"[-] EnableTraceEx2 failed: %lu\n", enableStatus);
        cleanupSession();
        return 1;
    }
    wprintf(L"[+] Enabled Microsoft-Windows-Kernel-Process provider\n");
    wprintf(L"[*] Waiting for events...\n\n");

    // -----------------------------------------------------------------------
    // Step 3: Open the trace consumer and start the blocking event pump.
    //
    // EVENT_TRACE_LOGFILEW describes both the source (our real-time session)
    // and the callbacks (EventRecordCallback, BufferCallback).
    // ProcessTrace() blocks until the session ends or BufferCallback returns FALSE.
    // -----------------------------------------------------------------------
    EVENT_TRACE_LOGFILEW logFile = {};
    logFile.LoggerName           = (LPWSTR)SESSION_NAME;
    logFile.ProcessTraceMode     = PROCESS_TRACE_MODE_REAL_TIME
                                 | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback  = EventRecordCallback;
    logFile.BufferCallback       = BufferCallback;

    g_TraceHandle = OpenTrace(&logFile);
    if (g_TraceHandle == INVALID_PROCESSTRACE_HANDLE) {
        wprintf(L"[-] OpenTrace failed: %lu\n", GetLastError());
        cleanupSession();
        return 1;
    }
    wprintf(L"[+] Consumer opened. Blocking on ProcessTrace...\n");

    // ProcessTrace blocks here, calling EventRecordCallback for each event.
    // Returns when the session is stopped (Ctrl+C → cleanupSession).
    ULONG processStatus = ProcessTrace(&g_TraceHandle, 1, nullptr, nullptr);
    if (processStatus != ERROR_SUCCESS && processStatus != ERROR_CANCELLED) {
        wprintf(L"[-] ProcessTrace returned: %lu\n", processStatus);
    }

    // -----------------------------------------------------------------------
    // Cleanup (also called by ctrlCHandler, but safe to call twice).
    // -----------------------------------------------------------------------
    cleanupSession();
    wprintf(L"\n[*] Session stopped. Exiting.\n");
    return 0;
}
