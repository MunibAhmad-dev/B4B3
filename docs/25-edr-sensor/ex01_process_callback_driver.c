/*
  Exercise 01 — Kernel Driver: Process Notification Callback
  -----------------------------------------------------------
  Use PsSetCreateProcessNotifyRoutineEx to get a callback for EVERY
  process creation and exit on the system.

  This is the core primitive of any EDR or process monitor:
  - No polling — the kernel calls you instantly.
  - Can BLOCK process creation (set CreateInfo->CreationStatus).
  - Sees the command line, image path, parent PID.

  Tasks:
  1. Complete ProcessNotifyCallback:
     - Print PID, parent PID, and image file name on process create.
     - Print PID on process exit.
  2. Implement a simple blocklist: block any process whose image name
     contains "badapp.exe" by setting CreateInfo->CreationStatus = STATUS_ACCESS_DENIED.
  3. Register the callback in DriverEntry, unregister in DriverUnload.

  BONUS:
  - Store events in a ring buffer and expose them via an IOCTL so a user-mode
    service can poll for new process events.
  - Check if the spawning process is running from a suspicious path
    (Temp, AppData) and set a "suspicious" flag in a shared list.

  Build: WDK + Visual Studio, test VM with test signing enabled.
    bcdedit /set testsigning on
  Load:
    sc create ProcCb type= kernel binPath= <path>\procCallback.sys
    sc start ProcCb
  Check DebugView (Sysinternals) for DbgPrint output.
*/

#include <ntddk.h>

// Simple "suspicious" check
static BOOLEAN isSuspiciousPath(PUNICODE_STRING imagePath) {
    if (!imagePath || !imagePath->Buffer) return FALSE;
    // Check for Temp directory
    UNICODE_STRING temp = RTL_CONSTANT_STRING(L"\\Temp\\");
    return (RtlFindUnicodePrefix(imagePath, &temp, 0) != nullptr);
}

// ---------- TODO 1+2: ProcessNotifyCallback ----------
VOID ProcessNotifyCallback(
    PEPROCESS             Process,
    HANDLE                ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo) {
        // Process is being CREATED
        DbgPrint("[EDR-PROC] CREATE: PID=%llu  Parent=%llu\n",
                 (ULONG64)(ULONG_PTR)ProcessId,
                 (ULONG64)(ULONG_PTR)CreateInfo->ParentProcessId);

        // TODO: print image file name if available
        // if (CreateInfo->ImageFileName) {
        //     DbgPrint("          Image: %wZ\n", CreateInfo->ImageFileName);
        // }

        // TODO: print command line if available
        // if (CreateInfo->CommandLine) {
        //     DbgPrint("          Cmd:   %wZ\n", CreateInfo->CommandLine);
        // }

        // TODO: block suspicious processes
        // if (CreateInfo->ImageFileName &&
        //     isSuspiciousPath(CreateInfo->ImageFileName)) {
        //     DbgPrint("[EDR-BLOCK] Blocking suspicious path: %wZ\n",
        //              CreateInfo->ImageFileName);
        //     CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
        // }

    } else {
        // Process is EXITING
        DbgPrint("[EDR-PROC] EXIT:   PID=%llu\n",
                 (ULONG64)(ULONG_PTR)ProcessId);
    }
}

// ---------- TODO 3: DriverUnload ----------
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    // Unregister the callback (second arg TRUE = remove)
    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);
    DbgPrint("[EDR-PROC] Callback unregistered\n");
}

// ---------- TODO 3: DriverEntry ----------
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;

    // Register the callback
    NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR-PROC] PsSetCreateProcessNotifyRoutineEx failed: 0x%08X\n", status);
        return status;
    }

    DbgPrint("[EDR-PROC] Process callback registered. Watch DebugView.\n");
    return STATUS_SUCCESS;
}
