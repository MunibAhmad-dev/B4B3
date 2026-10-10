# Module 19 — ETW: Event Tracing for Windows

## What ETW is and why it matters

ETW is the telemetry backbone of Windows. Almost everything that happens
on the system generates ETW events:
- Every process/thread create/exit
- Every image (DLL/EXE) load
- Network connections
- Registry access
- File system operations
- System calls (via NT Kernel Logger or Microsoft-Windows-Threat-Intelligence provider)

**Why you must understand ETW:**

As a **red teamer**: ETW is what modern EDRs use for behavioral detection.
If you don't understand what events your actions produce, you can't avoid them.
Some ETW providers run in the kernel and can't be disabled from user-mode.

As a **blue teamer**: ETW is how you build real-time monitoring tools,
behavioral detections, and incident response dashboards — for free, using
built-in Windows infrastructure.

---

## 2. ETW Architecture

```
Providers:
  → Any code that calls EventWrite() or EtwWrite() to emit events
  → Examples: ntoskrnl (kernel), Microsoft-Windows-Security-Auditing,
               Microsoft-Antimalware-AMFilter, your own app

Controller:
  → Starts/stops trace sessions, enables/disables providers
  → logman.exe, WPR, or your own code using StartTrace/EnableTraceEx2

Consumer:
  → Reads events from a session buffer in real-time or from a .etl log file
  → ProcessTrace() + event callback

Session:
  → A named buffer that routes events from providers to consumers
  → Max 64 simultaneous sessions on Windows
  → Special sessions: "NT Kernel Logger" (kernel events), "Circular Kernel Context Logger"
```

```
Provider → Event → Session buffer → Consumer (real-time callback)
                                  → .etl file (offline analysis)
```

---

## 3. Consuming ETW Events in Real Time (C++)

The key functions:
- `StartTrace` — create or open a trace session
- `EnableTraceEx2` — tell a provider to send events to your session
- `OpenTrace` — open the session for reading
- `ProcessTrace` — blocking call that feeds events to your callback
- `EventRecordCallback` — your function called for each event

```cpp
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <stdio.h>

// Provider GUID — Microsoft-Windows-Kernel-Process
// {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
static const GUID KERNEL_PROCESS_GUID = {
    0x22FB2CD6, 0x0E7B, 0x422B,
    {0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}
};

// Called for every event in the session
VOID WINAPI EventRecordCallback(PEVENT_RECORD EventRecord) {
    // EventRecord->EventHeader.ProviderId — which provider
    // EventRecord->EventHeader.EventDescriptor.Id — event type ID
    // EventRecord->UserData, EventRecord->UserDataLength — payload

    USHORT eventId = EventRecord->EventHeader.EventDescriptor.Id;

    // Event IDs for Microsoft-Windows-Kernel-Process:
    // 1 = ProcessStart, 2 = ProcessStop, 3 = ThreadStart, 4 = ThreadStop
    // 5 = ImageLoad, 6 = ImageUnload

    if (eventId == 1) {  // ProcessStart
        // Parse UserData as the ProcessStart event structure
        // (use TDH — Trace Data Helper — to decode generically)
        printf("[PROCESS START] Event received\n");
    }
}

// Buffer callback — called when a buffer is full or flush occurs
ULONG WINAPI BufferCallback(PEVENT_TRACE_LOGFILEW logfile) {
    UNREFERENCED_PARAMETER(logfile);
    return TRUE;  // keep processing
}

int main() {
    // Step 1: Configure the trace session
    TRACEHANDLE sessionHandle = 0;
    const wchar_t* SESSION_NAME = L"MyETWSession";

    // EVENT_TRACE_PROPERTIES must be followed by the session name in memory
    ULONG propSize = sizeof(EVENT_TRACE_PROPERTIES) + (wcslen(SESSION_NAME) + 1) * sizeof(wchar_t);
    EVENT_TRACE_PROPERTIES* props = (EVENT_TRACE_PROPERTIES*)malloc(propSize);
    ZeroMemory(props, propSize);

    props->Wnode.BufferSize    = propSize;
    props->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;  // QPC clock
    props->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
    props->BufferSize          = 64;   // KB per buffer
    props->MinimumBuffers      = 4;
    props->MaximumBuffers      = 8;
    props->FlushTimer          = 1;    // flush every 1 second

    wcscpy_s((wchar_t*)((PBYTE)props + sizeof(EVENT_TRACE_PROPERTIES)),
             wcslen(SESSION_NAME) + 1, SESSION_NAME);

    ULONG status = StartTrace(&sessionHandle, SESSION_NAME, props);
    if (status == ERROR_ALREADY_EXISTS) {
        // Session already running — open existing
        status = ControlTrace(sessionHandle, SESSION_NAME, props, EVENT_TRACE_CONTROL_QUERY);
    }
    if (status != ERROR_SUCCESS && status != ERROR_ALREADY_EXISTS) {
        printf("StartTrace failed: %lu\n", status); free(props); return 1;
    }
    printf("[+] Trace session started\n");

    // Step 2: Enable the provider to send events to our session
    ENABLE_TRACE_PARAMETERS params = { ENABLE_TRACE_PARAMETERS_VERSION_2 };
    EnableTraceEx2(sessionHandle, &KERNEL_PROCESS_GUID,
                   EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                   TRACE_LEVEL_VERBOSE,
                   0xFFFFFFFFFFFFFFFF,  // all keywords
                   0, 0, &params);
    printf("[+] Provider enabled\n");

    // Step 3: Open the trace for reading
    EVENT_TRACE_LOGFILEW logFile = {};
    logFile.LoggerName      = (LPWSTR)SESSION_NAME;
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = EventRecordCallback;
    logFile.BufferCallback      = BufferCallback;

    TRACEHANDLE traceHandle = OpenTrace(&logFile);
    printf("[+] Processing events — press Ctrl+C to stop\n");

    // Step 4: Block and process events (runs until CloseTrace called or Ctrl+C)
    ProcessTrace(&traceHandle, 1, nullptr, nullptr);

    CloseTrace(traceHandle);

    // Cleanup
    ControlTrace(sessionHandle, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
    free(props);
    return 0;
}
```

---

## 4. Decoding Event Payload with TDH

Raw `EventRecord->UserData` is binary. The Trace Data Helper (TDH) API
decodes it into named fields.

```cpp
#include <tdh.h>
#pragma comment(lib, "tdh.lib")

void decodeEvent(PEVENT_RECORD rec) {
    // Get schema for this event
    DWORD bufSize = 0;
    TdhGetEventInformation(rec, 0, nullptr, nullptr, &bufSize);
    PTRACE_EVENT_INFO info = (PTRACE_EVENT_INFO)malloc(bufSize);
    TdhGetEventInformation(rec, 0, nullptr, info, &bufSize);

    // Print all properties
    PBYTE userData = (PBYTE)rec->UserData;
    for (DWORD i = 0; i < info->TopLevelPropertyCount; i++) {
        EVENT_PROPERTY_INFO& prop = info->EventPropertyInfoArray[i];
        wchar_t* name = (wchar_t*)((PBYTE)info + prop.NameOffset);

        // TdhFormatProperty converts the binary field to a string
        BYTE valueBuf[512] = {};
        USHORT valueSize = sizeof(valueBuf);
        ULONG consumed = 0;
        TdhFormatProperty(info, nullptr, sizeof(PVOID),
                          prop.nonStructType.InType,
                          prop.nonStructType.OutType,
                          0, (USHORT)(rec->UserDataLength - (userData - (PBYTE)rec->UserData)),
                          userData, &valueSize, (LPWSTR)valueBuf, &consumed);
        userData += consumed;

        wprintf(L"  %s = %s\n", name, (LPWSTR)valueBuf);
    }
    free(info);
}
```

---

## 5. Important ETW Providers for Security

| Provider | GUID | Events |
|----------|------|--------|
| Microsoft-Windows-Kernel-Process | 22FB2CD6-... | Process/thread/image |
| Microsoft-Windows-Kernel-Network | 7DD42A49-... | TCP/UDP events |
| Microsoft-Windows-Kernel-File | EDD08927-... | File create/read/write |
| Microsoft-Windows-Kernel-Registry | 70EB4F03-... | Registry CRUD |
| Microsoft-Windows-Threat-Intelligence | F4E1897C-... | Suspicious behaviors (EDR-tier) |
| Microsoft-Antimalware-AMFilter | 80085345-... | Defender detections |

**Threat-Intelligence provider** is special: it can only be consumed by
PPL (Protected Process Light) processes, which means only EDR vendors can
subscribe to it from user-mode. From kernel mode, you can access it directly.

---

## 6. Attacker Perspective: Blinding ETW

From user-mode, you can patch `EtwEventWrite` in ntdll to make it return
immediately without emitting any events. This blinds any consumer that
relies on ETW events generated by your process.

```cpp
// Patch EtwEventWrite in ntdll to just "ret"
// (This only affects your own process's ETW emissions)
void blindEtw() {
    PVOID addr = GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
    DWORD old;
    VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &old);
    *(BYTE*)addr = 0xC3;  // ret
    VirtualProtect(addr, 1, old, &old);
}
```

**Detection:** EDRs watch for patches to `EtwEventWrite` — it's a known
evasion technique and itself generates a detection event in better EDRs.

---

## Exercises

- `ex01_process_monitor.cpp` — real-time process create/exit using ETW
- `ex02_network_monitor.cpp` — real-time TCP connection events using ETW
- `ex03_image_load_monitor.cpp` — log every DLL loaded into every process
- `ex04_blind_etw.cpp` — patch EtwEventWrite and observe the effect (blue team lab)
