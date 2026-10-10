// etw_monitor.cpp — ETW process start/stop monitor
// Compile: g++ -std=c++17 -o etw_monitor.exe etw_monitor.cpp -ltdh -ladvapi32
// Usage: etw_monitor.exe [--filter <name_substring>]

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

// Microsoft-Windows-Kernel-Process GUID
static const GUID GUID_KernelProcess = {
    0x22FB2CD6, 0x0E7B, 0x422B,
    {0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}
};

static std::string g_filter;
static TRACEHANDLE g_hTrace = INVALID_PROCESSTRACE_HANDLE;
static std::atomic<bool> g_running{true};

// ─── Property extraction helpers ─────────────────────────────────────────────

static std::wstring get_wstring_prop(PEVENT_RECORD ev, const wchar_t* prop_name) {
    TDHSTATUS st;
    ULONG buf_size = 0;
    PROPERTY_DATA_DESCRIPTOR dd{};
    dd.PropertyName = (ULONGLONG)prop_name;
    dd.ArrayIndex   = ULONG_MAX;
    st = TdhGetPropertySize(ev, 0, nullptr, 1, &dd, &buf_size);
    if (st != ERROR_SUCCESS || buf_size < 2) return L"";
    std::vector<BYTE> buf(buf_size);
    st = TdhGetProperty(ev, 0, nullptr, 1, &dd, buf_size, buf.data());
    if (st != ERROR_SUCCESS) return L"";
    return std::wstring((wchar_t*)buf.data());
}

static DWORD get_dword_prop(PEVENT_RECORD ev, const wchar_t* prop_name) {
    TDHSTATUS st;
    ULONG buf_size = sizeof(DWORD);
    PROPERTY_DATA_DESCRIPTOR dd{};
    dd.PropertyName = (ULONGLONG)prop_name;
    dd.ArrayIndex   = ULONG_MAX;
    DWORD val = 0;
    st = TdhGetProperty(ev, 0, nullptr, 1, &dd, buf_size, (BYTE*)&val);
    return (st == ERROR_SUCCESS) ? val : 0;
}

// ─── ETW event callback ───────────────────────────────────────────────────────

static VOID WINAPI event_callback(PEVENT_RECORD ev) {
    if (!ev) return;
    // Keyword 0x10 = process; EventId 1=start 2=stop
    USHORT eid = ev->EventHeader.EventDescriptor.Id;
    if (eid != 1 && eid != 2) return;

    std::wstring image   = get_wstring_prop(ev, L"ImageName");
    DWORD pid            = get_dword_prop(ev, L"ProcessID");
    DWORD ppid           = get_dword_prop(ev, L"ParentProcessID");

    // Apply filter
    if (!g_filter.empty()) {
        std::string narrow(image.begin(), image.end());
        if (narrow.find(g_filter) == std::string::npos) return;
    }

    char ts[32]{};
    SYSTEMTIME st{};
    FileTimeToSystemTime((FILETIME*)&ev->EventHeader.TimeStamp, &st);
    snprintf(ts, sizeof(ts), "%02d:%02d:%02d.%03d",
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    printf("[%s] %-5s  PID=%-6lu PPID=%-6lu  %ls\n",
           ts, eid == 1 ? "START" : "STOP",
           pid, ppid, image.c_str());
}

// ─── ProcessTrace thread ──────────────────────────────────────────────────────

static void trace_thread_fn(TRACEHANDLE h) {
    ProcessTrace(&h, 1, nullptr, nullptr);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--filter") && i+1 < argc)
            g_filter = argv[++i];
    }

    const wchar_t* SESSION_NAME = L"EtwMonitorSession";

    // Allocate EVENT_TRACE_PROPERTIES
    DWORD props_size = sizeof(EVENT_TRACE_PROPERTIES) +
                       (DWORD)((wcslen(SESSION_NAME)+1) * sizeof(wchar_t));
    std::vector<BYTE> buf(props_size, 0);
    auto* props = (EVENT_TRACE_PROPERTIES*)buf.data();
    props->Wnode.BufferSize    = props_size;
    props->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1; // QPC clock
    props->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);

    TRACEHANDLE hSession = 0;
    ULONG status = StartTraceW(&hSession, SESSION_NAME, props);
    if (status == ERROR_ALREADY_EXISTS) {
        printf("[*] Session exists; stopping old one...\n");
        ControlTraceW(0, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
        status = StartTraceW(&hSession, SESSION_NAME, props);
    }
    if (status != ERROR_SUCCESS) {
        fprintf(stderr, "[!] StartTraceW failed: %lu\n", status);
        fprintf(stderr, "    (Run as Administrator)\n");
        return 1;
    }
    printf("[+] Trace session started\n");

    // Enable Microsoft-Windows-Kernel-Process, keyword 0x10
    ENABLE_TRACE_PARAMETERS etp{};
    etp.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    status = EnableTraceEx2(hSession, &GUID_KernelProcess,
                            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_INFORMATION,
                            0x10,   // process events keyword
                            0, 0, &etp);
    if (status != ERROR_SUCCESS)
        fprintf(stderr, "[!] EnableTraceEx2 warning: %lu\n", status);

    // Open trace for real-time consumption
    EVENT_TRACE_LOGFILEW logfile{};
    logfile.LoggerName         = (LPWSTR)SESSION_NAME;
    logfile.ProcessTraceMode   = PROCESS_TRACE_MODE_REAL_TIME |
                                 PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = event_callback;

    g_hTrace = OpenTraceW(&logfile);
    if (g_hTrace == INVALID_PROCESSTRACE_HANDLE) {
        fprintf(stderr, "[!] OpenTraceW failed: %lu\n", GetLastError());
        ControlTraceW(hSession, nullptr, props, EVENT_TRACE_CONTROL_STOP);
        return 1;
    }

    printf("[+] Monitoring process events%s%s%s\n",
           g_filter.empty() ? "" : " (filter: \"",
           g_filter.c_str(),
           g_filter.empty() ? "" : "\")");
    printf("    Press Ctrl+C to stop\n\n");
    printf("%-13s  %-5s  %-6s  %-6s  %s\n", "Time", "Event", "PID", "PPID", "Image");
    printf("%s\n", std::string(70, '-').c_str());

    std::thread t(trace_thread_fn, g_hTrace);

    // Wait for Ctrl+C
    SetConsoleCtrlHandler([](DWORD) -> BOOL {
        g_running = false;
        CloseTrace(g_hTrace);
        return TRUE;
    }, TRUE);

    t.join();

    ControlTraceW(hSession, nullptr, props, EVENT_TRACE_CONTROL_STOP);
    printf("\n[*] Trace stopped\n");
    return 0;
}
