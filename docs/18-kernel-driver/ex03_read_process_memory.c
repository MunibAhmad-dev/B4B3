/*
  Exercise 03 — Kernel: Read Process Memory via MmCopyVirtualMemory
  ------------------------------------------------------------------
  Extend the IOCTL channel from ex02 so that user-mode can issue a
  READ_MEMORY IOCTL and have the kernel copy bytes from another
  process's virtual address space.

  This is the primitive that game cheats, memory scanners, and some EDRs
  use: bypasses the "OpenProcess + ReadProcessMemory" API pair that EDRs
  hook, because it runs entirely in kernel mode.

  Kernel side (this file): handle IOCTL_READ_MEMORY.
  User-mode side: see ex03_read_memory_client.cpp.

  IOCTL input  (buffer sent by user-mode):
      struct ReadRequest { ULONG_PTR pid; ULONG_PTR address; SIZE_T length; };

  IOCTL output (buffer filled by kernel):
      Raw bytes read from the target process (up to 4096 bytes).

  Tasks:
  1. Declare IOCTL_READ_MEMORY using CTL_CODE with METHOD_BUFFERED.
  2. In DispatchIoctl: parse the ReadRequest from Irp->AssociatedIrp.SystemBuffer.
  3. Look up the EPROCESS for the target PID using PsLookupProcessByProcessId.
  4. Call MmCopyVirtualMemory to copy bytes into the output buffer.
  5. Set Irp->IoStatus.Information to bytes copied, complete the IRP.

  BONUS:
  - Validate that the requested length does not exceed 4096.
  - Check that the target address is in user space (< MmUserProbeAddress).
  - Return STATUS_ACCESS_DENIED if the target is a protected process.

  Build: requires WDK, Visual Studio, test signing mode on target VM.
  Add to your driver project and register the handler in DispatchIoctl.
*/

#include <ntddk.h>
#include <wdm.h>

#define DEVICE_NAME   L"\\Device\\MemReader"
#define SYMLINK_NAME  L"\\DosDevices\\MemReader"

// TODO: define IOCTL_READ_MEMORY using CTL_CODE
// CTL_CODE(DeviceType, Function, Method, Access)
// Use FILE_DEVICE_UNKNOWN, function 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS
#define IOCTL_READ_MEMORY  0 // replace with CTL_CODE(...)

typedef struct _READ_REQUEST {
    ULONG_PTR TargetPid;
    ULONG_PTR TargetAddress;
    SIZE_T    Length;
} READ_REQUEST, *PREAD_REQUEST;

PDEVICE_OBJECT g_DeviceObject = nullptr;

// Forward declaration for MmCopyVirtualMemory (undocumented, no header)
NTKERNELAPI NTSTATUS MmCopyVirtualMemory(
    PEPROCESS SourceProcess,
    PVOID     SourceAddress,
    PEPROCESS TargetProcess,
    PVOID     TargetAddress,
    SIZE_T    BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T   ReturnSize
);

NTSTATUS DispatchIoctl(PDEVICE_OBJECT DevObj, PIRP Irp) {
    UNREFERENCED_PARAMETER(DevObj);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR bytesReturned = 0;

    if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_READ_MEMORY) {
        ULONG inLen  = stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (inLen < sizeof(READ_REQUEST) || outLen == 0) {
            status = STATUS_BUFFER_TOO_SMALL;
            goto done;
        }

        // TODO: read the request from SystemBuffer
        PREAD_REQUEST req = (PREAD_REQUEST)Irp->AssociatedIrp.SystemBuffer;
        PVOID         out = Irp->AssociatedIrp.SystemBuffer; // same buffer for METHOD_BUFFERED output

        // Clamp length
        SIZE_T length = min(req->Length, (SIZE_T)outLen);
        length = min(length, (SIZE_T)4096);

        // TODO: look up target process
        PEPROCESS targetProcess = nullptr;
        // status = PsLookupProcessByProcessId((HANDLE)req->TargetPid, &targetProcess);
        // if (!NT_SUCCESS(status)) goto done;

        // TODO: copy memory
        // SIZE_T copied = 0;
        // status = MmCopyVirtualMemory(
        //     targetProcess, (PVOID)req->TargetAddress,
        //     PsGetCurrentProcess(), out,
        //     length, KernelMode, &copied);
        // bytesReturned = copied;

        // TODO: dereference the process object when done
        // ObDereferenceObject(targetProcess);

        (void)req; (void)out; (void)length; (void)targetProcess;
        status = STATUS_NOT_IMPLEMENTED; // remove when done
    }

done:
    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS DispatchPassthrough(PDEVICE_OBJECT DevObj, PIRP Irp) {
    UNREFERENCED_PARAMETER(DevObj);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNICODE_STRING sym = RTL_CONSTANT_STRING(SYMLINK_NAME);
    IoDeleteSymbolicLink(&sym);
    IoDeleteDevice(g_DeviceObject);
    DbgPrint("[MemReader] Unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    UNICODE_STRING devName = RTL_CONSTANT_STRING(DEVICE_NAME);
    UNICODE_STRING symName = RTL_CONSTANT_STRING(SYMLINK_NAME);

    NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName,
                                      FILE_DEVICE_UNKNOWN, 0, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status)) return status;

    IoCreateSymbolicLink(&symName, &devName);

    DriverObject->DriverUnload = DriverUnload;
    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = DispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;

    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    DbgPrint("[MemReader] Loaded\n");
    return STATUS_SUCCESS;
}
