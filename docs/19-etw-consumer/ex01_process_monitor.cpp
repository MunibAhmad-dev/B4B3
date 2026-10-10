/*
  Exercise 01 — ETW Real-Time Process Monitor
  ---------------------------------------------
  Use ETW to receive a callback for EVERY process that starts or exits
  on the system, in real time. No polling, no snapshots — pure event-driven.

  This is the core of how Windows Defender, Sysmon, and EDRs track process creation.

  Tasks:
  1. Implement startEtwSession() — call StartTrace with REAL_TIME mode.
  2. Implement enableProvider() — EnableTraceEx2 for Microsoft-Windows-Kernel-Process.
  3. Implement EventRecordCallback() — print ProcessStart (ID=1) and ProcessStop (ID=2).
     For ProcessStart, try to parse the ImageName from UserData using TDH (BONUS).
  4. Implement the main loop — OpenTrace + ProcessTrace (blocking).
  5. Handle Ctrl+C to cleanly stop the session.

  Expected output (as you open/close programs):
    [PROCESS START] PID=12345  PPID=4321  Image=notepad.exe
    [PROCESS STOP]  PID=12345  ExitCode=0

  IMPORTANT: Requires admin rights to start ETW sessions.

  Compile:
    g++ -std=c++17 -Wall -o ex01.exe ex01_process_monitor.cpp -lkernel32 -ltdh -lAdvAPI32
*/

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <iostream>
#include <string>
#include <signal.h>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

// Microsoft-Windows-Kernel-Process provider GUID
// {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
static const GUID KERNEL_PROCESS_GUID = {
    0x22FB2CD6, 0x0E7B, 0x422B,
    {0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}
};

static const wchar_t* SESSION_NAME = L"MyProcessMonitor";
static TRACEHANDLE    g_SessionHandle = 0;
static TRACEHANDLE    g_TraceHandle   = INVALID_PROCESSTRACE_HANDLE;
static bool           g_Running       = true;

// ETW event IDs for Microsoft-Windows-Kernel-Process
#define EVENT_PROCESS_START  1
#define EVENT_PROCESS_STOP   2
#define EVENT_THREAD_START   3
#define EVENT_THREAD_STOP    4
#define EVENT_IMAGE_LOAD     5

// TODO: Decode a specific property from an event using TDH.
// Returns the property value as a wide string, or L"?" on failure.
// Hint: TdhGetEventInformation → find property by name → TdhFormatProperty
std::wstring getProperty(PEVENT_RECORD rec, const wchar_t* propName) {
    // YOUR CODE HERE
    return L"?";
}

// TODO: Implement the event record callback.
// For each event:
//   1. Check EventRecord->EventHeader.EventDescriptor.Id
//   2. If EVENT_PROCESS_START (1): print PID and try to get ImageName property
//   3. If EVENT_PROCESS_STOP  (2): print PID
//   4. Ignore other events (thread, image load noise)
VOID WINAPI EventRecordCallback(PEVENT_RECORD EventRecord) {
    // YOUR CODE HERE
}

ULONG WINAPI BufferCallback(PEVENT_TRACE_LOGFILEW logfile) {
    UNREFERENCED_PARAMETER(logfile);
    return g_Running ? TRUE : FALSE;
}

void cleanupSession() {
    if (g_TraceHandle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(g_TraceHandle);
        g_TraceHandle = INVALID_PROCESSTRACE_HANDLE;
    }
    if (g_SessionHandle) {
        ULONG propSize = sizeof(EVENT_TRACE_PROPERTIES) + (wcslen(SESSION_NAME) + 1) * 2;
        EVENT_TRACE_PROPERTIES* props = (EVENT_TRACE_PROPERTIES*)calloc(1, propSize);
        props->Wnode.BufferSize = propSize;
        ControlTrace(g_SessionHandle, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
        free(props);
        g_SessionHandle = 0;
    }
}

void ctrlCHandler(int) {
    g_Running = false;
    cleanupSession();
}

int main() {
    signal(SIGINT, ctrlCHandler);

    printf("[*] Starting ETW Process Monitor (requires admin)\n");
    printf("[*] Press Ctrl+C to stop\n\n");

    // TODO: Allocate and fill EVENT_TRACE_PROPERTIES, call StartTrace
    // (handle ERROR_ALREADY_EXISTS by stopping and restarting)
    // YOUR CODE HERE

    // TODO: EnableTraceEx2 for KERNEL_PROCESS_GUID
    // YOUR CODE HERE

    // TODO: Set up EVENT_TRACE_LOGFILEW and call OpenTrace + ProcessTrace
    // YOUR CODE HERE

    cleanupSession();
    return 0;
}
