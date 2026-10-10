/*
  Solution 01 — Kernel Driver: Process Notification Callback
  -----------------------------------------------------------
  Complete process notification driver that:
    - Registers PsSetCreateProcessNotifyRoutineEx for all process create/exit events.
    - Logs PID, parent PID, image name, and command line via DbgPrint.
    - Blocks any process whose image name ends in "malware.exe".
    - Creates a device + symbolic link so user-mode can send IOCTLs.
    - Properly unregisters the callback in DriverUnload.

  Build with WDK + Visual Studio (x64, kernel mode).
  Test with test signing enabled:
    bcdedit /set testsigning on   (reboot required)
  Load:
    sc create ProcCb type= kernel binPath= <path>\sol01.sys
    sc start  ProcCb
  Watch output in DebugView (Sysinternals) with kernel capture enabled.
*/

#include <ntddk.h>

// Device name and symbolic link for user-mode IOCTL access (optional)
#define DEVICE_NAME     L"\\Device\\EdrProcCb"
#define SYMLINK_NAME    L"\\DosDevices\\EdrProcCb"

static PDEVICE_OBJECT g_DeviceObject = NULL;

// ---- Helper: extract base filename from a full path ----
static VOID GetBaseName(PUNICODE_STRING fullPath, PUNICODE_STRING baseName) {
    *baseName = *fullPath;
    for (int i = (int)(fullPath->Length / sizeof(WCHAR)) - 1; i >= 0; i--) {
        if (fullPath->Buffer[i] == L'\\') {
            baseName->Buffer  = fullPath->Buffer + i + 1;
            baseName->Length  = (USHORT)((fullPath->Length / sizeof(WCHAR) - i - 1) * sizeof(WCHAR));
            baseName->MaximumLength = baseName->Length;
            return;
        }
    }
}

// ---- Helper: case-insensitive suffix check ----
static BOOLEAN EndsWithW(PUNICODE_STRING str, PCWSTR suffix) {
    UNICODE_STRING usSuffix;
    RtlInitUnicodeString(&usSuffix, suffix);
    if (str->Length < usSuffix.Length) return FALSE;

    UNICODE_STRING tail;
    tail.Buffer     = str->Buffer + (str->Length - usSuffix.Length) / sizeof(WCHAR);
    tail.Length     = usSuffix.Length;
    tail.MaximumLength = usSuffix.Length;

    return RtlEqualUnicodeString(&tail, &usSuffix, TRUE);
}

// ---- Process Notification Callback ----
VOID ProcessCallback(
    PEPROCESS             Process,
    HANDLE                ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo != NULL) {
        // ---- Process CREATION ----
        DbgPrint("[EDR-PROC] CREATE: PID=%llu  ParentPID=%llu\n",
                 (ULONG64)(ULONG_PTR)ProcessId,
                 (ULONG64)(ULONG_PTR)CreateInfo->ParentProcessId);

        if (CreateInfo->ImageFileName && CreateInfo->ImageFileName->Buffer) {
            DbgPrint("[EDR-PROC]         Image: %wZ\n", CreateInfo->ImageFileName);

            // Extract the base name for matching
            UNICODE_STRING baseName;
            GetBaseName(CreateInfo->ImageFileName, &baseName);

            // Block any process named "malware.exe"
            if (EndsWithW(&baseName, L"malware.exe")) {
                DbgPrint("[EDR-PROC] *** BLOCKING process: %wZ\n",
                         CreateInfo->ImageFileName);
                CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
                return;
            }

            // Alert on processes launched from suspicious paths
            UNICODE_STRING temp = RTL_CONSTANT_STRING(L"\\Temp\\");
            UNICODE_STRING appdata = RTL_CONSTANT_STRING(L"\\AppData\\");
            if (RtlFindUnicodePrefix(CreateInfo->ImageFileName, &temp, 0) ||
                RtlFindUnicodePrefix(CreateInfo->ImageFileName, &appdata, 0)) {
                DbgPrint("[EDR-PROC] *** SUSPICIOUS PATH: PID=%llu  %wZ\n",
                         (ULONG64)(ULONG_PTR)ProcessId,
                         CreateInfo->ImageFileName);
            }
        }

        if (CreateInfo->CommandLine && CreateInfo->CommandLine->Buffer) {
            DbgPrint("[EDR-PROC]         Cmd:   %wZ\n", CreateInfo->CommandLine);
        }

    } else {
        // ---- Process EXIT ----
        DbgPrint("[EDR-PROC] EXIT:   PID=%llu\n",
                 (ULONG64)(ULONG_PTR)ProcessId);
    }
}

// ---- IRP dispatch: just complete successfully (placeholder) ----
NTSTATUS DispatchPassthrough(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// ---- Driver Unload ----
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    // Unregister the process callback (second arg TRUE = remove)
    PsSetCreateProcessNotifyRoutineEx(ProcessCallback, TRUE);
    DbgPrint("[EDR-PROC] Process callback unregistered\n");

    // Remove symbolic link and device
    UNICODE_STRING symlinkName = RTL_CONSTANT_STRING(SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlinkName);

    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    DbgPrint("[EDR-PROC] Driver unloaded\n");
}

// ---- Driver Entry ----
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    DbgPrint("[EDR-PROC] DriverEntry called\n");

    // Set up dispatch routines
    DriverObject->DriverUnload = DriverUnload;
    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = DispatchPassthrough;

    // Create device object
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(DEVICE_NAME);
    status = IoCreateDevice(
        DriverObject,
        0,                        // no device extension
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR-PROC] IoCreateDevice failed: 0x%08X\n", status);
        return status;
    }

    // Create symbolic link for user-mode access
    UNICODE_STRING symlinkName = RTL_CONSTANT_STRING(SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR-PROC] IoCreateSymbolicLink failed: 0x%08X\n", status);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    // Register the process notification callback
    // FALSE = register (TRUE = unregister)
    status = PsSetCreateProcessNotifyRoutineEx(ProcessCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR-PROC] PsSetCreateProcessNotifyRoutineEx failed: 0x%08X\n", status);
        // Note: status 0xC0000022 means driver is not in an AllowedSigners list on some configs
        IoDeleteSymbolicLink(&symlinkName);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    DbgPrint("[EDR-PROC] Process callback registered. Monitoring all processes.\n");
    DbgPrint("[EDR-PROC] Any process named 'malware.exe' will be blocked.\n");
    return STATUS_SUCCESS;
}
