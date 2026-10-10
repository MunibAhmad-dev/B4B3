/*
  Exercise 02 — IOCTL Communication Channel
  -------------------------------------------
  Add a Device Object to the driver so user-mode programs can talk to it
  via DeviceIoControl. This is the foundation for all "userland ↔ kernel"
  communication tools: memory readers, process hiders, network blockers.

  Tasks (kernel side — this file):
  1. In DriverEntry: call IoCreateDevice + IoCreateSymbolicLink.
  2. Register IRP dispatch routines: IRP_MJ_CREATE, IRP_MJ_CLOSE,
     IRP_MJ_DEVICE_CONTROL.
  3. In DispatchIoControl: handle IOCTL_MYDRIVER_PING — return "PONG\0"
     in the output buffer.
  4. In DriverUnload: IoDeleteSymbolicLink + IoDeleteDevice.

  After getting this working, look at ex02_ioctl_usermode.cpp (below) to
  write the user-mode client.

  IOCTL code (must match between driver and user-mode):
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
    = 0x00220000 | (0x800 << 2) = 0x00222000

  Build, load, test:
    sc start MyDriver
    ex02_ioctl_usermode.exe  → should print "Kernel says: PONG"

  BONUS:
  - Add a second IOCTL: IOCTL_MYDRIVER_GETPID — user sends a process name,
    kernel responds with the PID (PsLookupProcessByProcessId + PsGetProcessImageFileName).
*/

#include <ntddk.h>

#define DEVICE_NAME     L"\\Device\\MyDriver"
#define DOS_DEVICE_NAME L"\\DosDevices\\MyDriver"

// IOCTL code — must match user-mode definition
#define IOCTL_MYDRIVER_PING \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Forward declarations
DRIVER_UNLOAD       DriverUnload;
DRIVER_DISPATCH     DispatchCreateClose;
DRIVER_DISPATCH     DispatchIoControl;

PDEVICE_OBJECT g_DeviceObject = nullptr;

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    // TODO: Delete symbolic link and device object
    // UNICODE_STRING dosName = RTL_CONSTANT_STRING(DOS_DEVICE_NAME);
    // IoDeleteSymbolicLink(&dosName);
    // IoDeleteDevice(g_DeviceObject);

    DbgPrint("[MyDriver] Unloaded\n");
}

// Handle IRP_MJ_CREATE and IRP_MJ_CLOSE (open/close handle from user-mode)
NTSTATUS DispatchCreateClose(_In_ PDEVICE_OBJECT DevObject, _In_ PIRP Irp) {
    UNREFERENCED_PARAMETER(DevObject);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// Handle IRP_MJ_DEVICE_CONTROL (DeviceIoControl from user-mode)
NTSTATUS DispatchIoControl(_In_ PDEVICE_OBJECT DevObject, _In_ PIRP Irp) {
    UNREFERENCED_PARAMETER(DevObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code    = stack->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    // TODO: Handle IOCTL_MYDRIVER_PING
    // 1. Check code == IOCTL_MYDRIVER_PING
    // 2. Get output buffer: (char*)Irp->AssociatedIrp.SystemBuffer
    // 3. Get output buffer length: stack->Parameters.DeviceIoControl.OutputBufferLength
    // 4. Copy "PONG" into output buffer (check length first)
    // 5. Set Irp->IoStatus.Information = bytes written
    // 6. Set status = STATUS_SUCCESS

    Irp->IoStatus.Status      = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    UNREFERENCED_PARAMETER(RegistryPath);

    UNICODE_STRING devName = RTL_CONSTANT_STRING(DEVICE_NAME);
    UNICODE_STRING dosName = RTL_CONSTANT_STRING(DOS_DEVICE_NAME);

    // TODO: IoCreateDevice
    // NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName,
    //                                   FILE_DEVICE_UNKNOWN,
    //                                   FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject);

    // TODO: IoCreateSymbolicLink(&dosName, &devName);

    // TODO: Set DO_BUFFERED_IO so METHOD_BUFFERED IOCTLs work
    // g_DeviceObject->Flags |= DO_BUFFERED_IO;
    // g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DriverObject->DriverUnload                          = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoControl;

    DbgPrint("[MyDriver] Device driver loaded\n");
    return STATUS_SUCCESS;
}
