/*
  Solution 02 — IOCTL Communication Channel (Kernel Side)
  ---------------------------------------------------------
  Complete DriverEntry with device creation, IOCTL dispatch, and clean unload.

  BUILD: Requires WDK. Run only in test VM with test-signing enabled.
*/

#include <ntddk.h>
#include <wdm.h>

#define DEVICE_NAME     L"\\Device\\MyDriver"
#define DOS_DEVICE_NAME L"\\DosDevices\\MyDriver"

#define IOCTL_MYDRIVER_PING \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

// BONUS: return PID for a named process
#define IOCTL_MYDRIVER_GETPID \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

static PDEVICE_OBJECT g_DeviceObject = NULL;

// ── DriverUnload ──────────────────────────────────────────────────────────────
VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    UNICODE_STRING dosName = RTL_CONSTANT_STRING(DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&dosName);

    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }
    DbgPrint("[MyDriver] Unloaded\n");
}

// ── DispatchCreateClose ────────────────────────────────────────────────────────
NTSTATUS DispatchCreateClose(_In_ PDEVICE_OBJECT DevObject, _In_ PIRP Irp) {
    UNREFERENCED_PARAMETER(DevObject);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// ── DispatchIoControl ─────────────────────────────────────────────────────────
NTSTATUS DispatchIoControl(_In_ PDEVICE_OBJECT DevObject, _In_ PIRP Irp) {
    UNREFERENCED_PARAMETER(DevObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG  code   = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG  outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG  inLen  = stack->Parameters.DeviceIoControl.InputBufferLength;
    void*  buf    = Irp->AssociatedIrp.SystemBuffer;

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG    written = 0;

    switch (code) {

    case IOCTL_MYDRIVER_PING: {
        // Return "PONG\0" in output buffer
        static const char pong[] = "PONG";
        ULONG copyLen = sizeof(pong);  // includes null terminator
        if (outLen < copyLen) {
            status = STATUS_BUFFER_TOO_SMALL; break;
        }
        RtlCopyMemory(buf, pong, copyLen);
        written = copyLen;
        status  = STATUS_SUCCESS;
        DbgPrint("[MyDriver] PING → PONG\n");
        break;
    }

    case IOCTL_MYDRIVER_GETPID: {
        // Input: process name as ANSI string
        // Output: DWORD PID
        if (inLen == 0 || !buf) { status = STATUS_INVALID_PARAMETER; break; }
        if (outLen < sizeof(ULONG)) { status = STATUS_BUFFER_TOO_SMALL; break; }

        // Walk process list to find by image name
        // This is a simplified scan — in production use PsLookupProcessByProcessId
        // and iterate the LDR list, or ZwQuerySystemInformation class 5.
        // For this exercise we use a brute-force OpenProcess scan approach:
        ULONG foundPid = 0;
        char targetName[256] = { 0 };
        ULONG copyLen2 = min(inLen, (ULONG)sizeof(targetName)-1);
        RtlCopyMemory(targetName, buf, copyLen2);

        // Walk from PID 4 upward (simplified — real code walks EPROCESS list)
        for (ULONG pid = 4; pid < 65536; pid += 4) {
            PEPROCESS proc = NULL;
            if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc)))
                continue;
            char* imgName = (char*)PsGetProcessImageFileName(proc);
            if (imgName && _stricmp(imgName, targetName) == 0) {
                foundPid = pid;
                ObDereferenceObject(proc);
                break;
            }
            ObDereferenceObject(proc);
        }

        RtlCopyMemory(buf, &foundPid, sizeof(foundPid));
        written = sizeof(foundPid);
        status  = foundPid ? STATUS_SUCCESS : STATUS_NOT_FOUND;
        DbgPrint("[MyDriver] GETPID(%s) = %lu\n", targetName, foundPid);
        break;
    }

    default:
        DbgPrint("[MyDriver] Unknown IOCTL: 0x%08X\n", code);
        break;
    }

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = written;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// ── DriverEntry ───────────────────────────────────────────────────────────────
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    // 1. Create device object
    UNICODE_STRING devName = RTL_CONSTANT_STRING(DEVICE_NAME);
    status = IoCreateDevice(DriverObject,
                            0,                          // no device extension needed
                            &devName,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[MyDriver] IoCreateDevice failed: 0x%08X\n", status);
        return status;
    }

    // 2. Create symbolic link so user-mode can open "\\.\MyDriver"
    UNICODE_STRING dosName = RTL_CONSTANT_STRING(DOS_DEVICE_NAME);
    status = IoCreateSymbolicLink(&dosName, &devName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[MyDriver] IoCreateSymbolicLink failed: 0x%08X\n", status);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    // 3. Register dispatch routines
    DriverObject->DriverUnload                         = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoControl;

    // Use buffered I/O for simplicity
    g_DeviceObject->Flags |= DO_BUFFERED_IO;
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrint("[MyDriver] Loaded — device: %wZ  symlink: %wZ\n", &devName, &dosName);
    return STATUS_SUCCESS;
}
