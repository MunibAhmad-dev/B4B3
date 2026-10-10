# Module 25 — Building an EDR Sensor

## What an EDR sensor does

An EDR (Endpoint Detection and Response) sensor collects telemetry from
the endpoint and makes it available for detection. The main collection points:

```
User-mode hooks (ntdll)     → catch API calls in each process
Kernel minifilter driver    → file system events (create, read, write, delete)
WFP callout driver          → network events (all TCP/UDP connections)
ETW consumers               → process, thread, image load events
AMSI integration            → script/macro content scanning
Registry callbacks          → CmRegisterCallback in kernel
Process/image load callbacks→ PsSetCreateProcessNotifyRoutine in kernel
```

A full commercial EDR uses all of these. This module focuses on the
kernel-callback approach — the most powerful and most reliable.

---

## 2. Kernel Process Notification Callbacks

Register a callback that fires for EVERY process creation/exit system-wide.
No polling. No ETW session needed. Runs in the kernel.

```c
// In your kernel driver:
#include <ntddk.h>

// This callback fires for every process create/exit
VOID ProcessNotifyCallback(
    PEPROCESS Process,
    HANDLE    ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo  // NULL on exit
) {
    if (CreateInfo) {
        // Process is being CREATED
        if (CreateInfo->ImageFileName) {
            DbgPrint("[EDR] Process create: PID=%llu  Image=%wZ\n",
                     (ULONG64)(ULONG_PTR)ProcessId,
                     CreateInfo->ImageFileName);
        }

        // Can BLOCK the process from starting!
        // CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
    } else {
        // Process is EXITING
        DbgPrint("[EDR] Process exit: PID=%llu\n", (ULONG64)(ULONG_PTR)ProcessId);
    }
}

// Register in DriverEntry:
PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, FALSE);

// Unregister in DriverUnload:
PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);
```

**Other notification callbacks:**
```c
// Image (DLL/EXE) load notification
PsSetLoadImageNotifyRoutine(ImageLoadCallback);

// Thread creation/exit
PsSetCreateThreadNotifyRoutine(ThreadNotifyCallback);

// Registry events
CmRegisterCallback(RegistryCallback, nullptr, &g_RegCallbackCookie);
```

---

## 3. Kernel Minifilter Driver (File System Events)

A minifilter intercepts file system I/O operations. This is how EDRs:
- Detect ransomware (many rapid file writes + renames)
- Block malicious files at the moment of creation
- Log every file opened by a suspicious process

```c
#include <fltKernel.h>

PFLT_FILTER g_FilterHandle = nullptr;

// Pre-create callback: called BEFORE a file is opened/created
FLT_PREOP_CALLBACK_STATUS PreCreateCallback(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
) {
    PFLT_FILE_NAME_INFORMATION nameInfo = nullptr;
    FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED |
                                     FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (nameInfo) {
        FltParseFileNameInformation(nameInfo);
        DbgPrint("[EDR] File open: %wZ by PID=%llu\n",
                 &nameInfo->Name,
                 (ULONG64)(ULONG_PTR)PsGetCurrentProcessId());
        FltReleaseFileNameInformation(nameInfo);
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// Registration table
const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, PreCreateCallback, nullptr },
    { IRP_MJ_WRITE,  0, PreWriteCallback,  nullptr },
    { IRP_MJ_SET_INFORMATION, 0, PreSetInfoCallback, nullptr },  // renames
    { IRP_MJ_OPERATION_END }
};

const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION,
    0, nullptr, Callbacks,
    FilterUnload, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr
};

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    FltRegisterFilter(DriverObject, &FilterRegistration, &g_FilterHandle);
    FltStartFiltering(g_FilterHandle);
    // ...
}
```

---

## 4. WFP (Windows Filtering Platform) Network Callout

WFP lets you inspect and optionally block every network packet.
EDRs use it to detect C2 beacons and data exfiltration.

```c
// Register a callout with the WFP engine
// This is complex — simplified concept below

#include <fwpsk.h>
#include <fwpmk.h>

// Called for every outbound TCP connection attempt
void ClassifyFn(
    const FWPS_INCOMING_VALUES* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT* classifyOut
) {
    // Extract destination IP + port
    FWP_VALUE localAddr  = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_LOCAL_ADDRESS].value;
    FWP_VALUE remoteAddr = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_REMOTE_ADDRESS].value;
    FWP_VALUE remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_REMOTE_PORT].value;

    UINT32 ip   = remoteAddr.uint32;
    UINT16 port = remotePort.uint16;

    DbgPrint("[EDR-NET] PID=%llu → %d.%d.%d.%d:%d\n",
             inMetaValues->processId,
             (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF,
             ntohs(port));

    // To BLOCK the connection:
    // classifyOut->actionType = FWP_ACTION_BLOCK;
    // classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}
```

---

## 5. Reporting Telemetry to User-Mode

Kernel collects events → needs to report them to a user-mode service for:
- Storage and indexing
- Pattern matching / detection rules
- Dashboard / alerting

Two common approaches:

**A. ETW provider in kernel:**
```c
// Register as an ETW provider, emit events
// User-mode consumer subscribes to your provider GUID
// Fast, built-in, works with any ETW consumer
REGHANDLE g_EtwHandle;
EventRegister(&MY_PROVIDER_GUID, nullptr, nullptr, &g_EtwHandle);
EventWrite(g_EtwHandle, &g_EventDescriptor, 0, nullptr);
```

**B. Shared memory ring buffer:**
```c
// Kernel writes events into a shared MDL-based ring buffer
// User-mode daemon reads them continuously
// Lower latency, more control, more complex
```

---

## 6. Detection Rules in the Sensor

Once you have telemetry, apply rules:

```cpp
// User-mode service processes events from kernel:
void onProcessCreate(const ProcessEvent& ev) {
    // Rule: process spawned from a Word/Excel document
    if (ev.parentImage.find("WINWORD.EXE") != std::string::npos ||
        ev.parentImage.find("EXCEL.EXE")  != std::string::npos) {
        if (ev.image.find("cmd.exe") != std::string::npos ||
            ev.image.find("powershell") != std::string::npos) {
            alert(HIGH, "Suspicious child process from Office", ev);
        }
    }

    // Rule: new process from TEMP or APPDATA
    if (ev.imagePath.find("\\Temp\\") != std::string::npos ||
        ev.imagePath.find("\\AppData\\") != std::string::npos) {
        alert(MEDIUM, "Process launched from user writable path", ev);
    }
}
```

---

## Exercises

- `ex01_process_callback_driver.c` — WDM driver using PsSetCreateProcessNotifyRoutineEx
- `ex02_image_load_callback.c` — detect DLL loads into suspicious processes
- `ex03_minifilter_skeleton.c` — minifilter with pre-create callback, log file access
- `ex04_usermode_service.cpp` — user-mode service consuming events from kernel driver via ETW or shared memory
