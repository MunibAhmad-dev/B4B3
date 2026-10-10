/*
  Module 18 — Kernel Driver
  Exercise 03 Solution — Read Process Memory via IOCTL + MmCopyVirtualMemory
  ===========================================================================
  Exposes a kernel-mode IOCTL that lets a privileged user-mode client read
  arbitrary virtual memory from any target process without going through the
  userland ReadProcessMemory API that EDRs commonly hook.

  Technique overview:
    - MmCopyVirtualMemory is an undocumented ntoskrnl export that copies
      bytes between process virtual address spaces entirely in kernel mode.
    - By wrapping it in a driver IOCTL, a red-team operator (or a memory
      scanner / cheat engine) can read game/target process memory while
      bypassing all user-mode hooks on NtReadVirtualMemory.
    - Blue-team use: detect kernel drivers that export this capability by
      monitoring driver loads and scanning driver images for the
      MmCopyVirtualMemory import.

  Build (WDK required):
    - Add this file to a WDK kernel-mode driver project.
    - Set Configuration Type = Driver.
    - Enable test-signing on the target VM:
        bcdedit /set testsigning on
        bcdedit /set nointegritychecks on   (dev VM only!)
    - Install and start the driver with sc.exe or OSR Driver Loader.

  IMPORTANT: Run only on a dedicated test VM — never on a production machine.
             Kernel bugs cause BSODs.
*/

#include <ntddk.h>
#include <wdm.h>

// ---------------------------------------------------------------------------
// Device / symlink names (user-mode opens \\.\MemReader)
// ---------------------------------------------------------------------------
#define DEVICE_NAME   L"\\Device\\MemReader"
#define SYMLINK_NAME  L"\\DosDevices\\MemReader"

// ---------------------------------------------------------------------------
// IOCTL definition
// ---------------------------------------------------------------------------
// CTL_CODE(DeviceType, Function, Method, Access)
//   FILE_DEVICE_UNKNOWN = 0x22
//   Function 0x901      = custom base for this driver
//   METHOD_BUFFERED     = OS copies in/out through a kernel buffer (safest)
//   FILE_ANY_ACCESS     = no special access required
#define IOCTL_READ_MEMORY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---------------------------------------------------------------------------
// Request structure (must match the user-mode client)
// ---------------------------------------------------------------------------
// For METHOD_BUFFERED IOCTLs the OS puts BOTH the input and output in the
// same SystemBuffer; the input bytes must be read out before the output is
// written back (or use separate fields in a union). Here the buffer is large
// enough: the request struct occupies the first sizeof(READ_REQUEST) bytes
// of the SystemBuffer, and the output bytes follow immediately after (or
// overlap if we just overwrite from offset 0 — which is fine because we
// have already read the request into local variables before writing).
typedef struct _READ_REQUEST {
    ULONG_PTR TargetPid;      // PID of process to read from
    ULONG_PTR TargetAddress;  // virtual address in that process
    SIZE_T    Length;         // number of bytes to read (capped at 4096)
} READ_REQUEST, *PREAD_REQUEST;

// Maximum bytes we will read in a single IOCTL — keeps the stack safe.
#define MAX_READ_LENGTH 4096

// ---------------------------------------------------------------------------
// Global device object — created in DriverEntry, deleted in DriverUnload
// ---------------------------------------------------------------------------
PDEVICE_OBJECT g_DeviceObject = NULL;

// ---------------------------------------------------------------------------
// Forward declaration for MmCopyVirtualMemory
// ---------------------------------------------------------------------------
// This function is exported by ntoskrnl but not declared in any public header.
// Declare it ourselves so the linker resolves it at load time.
NTKERNELAPI NTSTATUS MmCopyVirtualMemory(
    PEPROCESS SourceProcess,
    PVOID     SourceAddress,
    PEPROCESS TargetProcess,
    PVOID     TargetAddress,
    SIZE_T    BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T   ReturnSize
);

// ---------------------------------------------------------------------------
// DispatchIoctl — handles IRP_MJ_DEVICE_CONTROL
// ---------------------------------------------------------------------------
NTSTATUS DispatchIoctl(PDEVICE_OBJECT DevObj, PIRP Irp) {
    UNREFERENCED_PARAMETER(DevObj);

    PIO_STACK_LOCATION stack       = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS           status      = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR          bytesReturned = 0;

    if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_READ_MEMORY) {

        ULONG inLen  = stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;

        // ---------------------------------------------------------------
        // Validate buffer sizes.
        // ---------------------------------------------------------------
        if (inLen < sizeof(READ_REQUEST)) {
            DbgPrint("[MemReader] Input buffer too small (%lu < %zu)\n",
                     inLen, sizeof(READ_REQUEST));
            status = STATUS_BUFFER_TOO_SMALL;
            goto done;
        }
        if (outLen == 0) {
            DbgPrint("[MemReader] Output buffer is zero-length\n");
            status = STATUS_BUFFER_TOO_SMALL;
            goto done;
        }

        // ---------------------------------------------------------------
        // Parse the request.
        //
        // For METHOD_BUFFERED, both input and output share SystemBuffer.
        // Copy the request fields into locals BEFORE writing to the buffer.
        // ---------------------------------------------------------------
        PREAD_REQUEST req = (PREAD_REQUEST)Irp->AssociatedIrp.SystemBuffer;

        ULONG_PTR targetPid     = req->TargetPid;
        PVOID     targetAddress = (PVOID)req->TargetAddress;
        SIZE_T    length        = req->Length;

        // Clamp length to max and to available output buffer.
        if (length > (SIZE_T)outLen)  length = (SIZE_T)outLen;
        if (length > MAX_READ_LENGTH) length = MAX_READ_LENGTH;

        // ---------------------------------------------------------------
        // Bonus validation: reject kernel addresses.
        //
        // MmUserProbeAddress is the boundary; anything at or above it is
        // kernel space. Letting callers read kernel memory from user mode
        // is a significant privilege escalation risk.
        // ---------------------------------------------------------------
        if ((ULONG_PTR)targetAddress >= (ULONG_PTR)MmUserProbeAddress) {
            DbgPrint("[MemReader] Rejecting kernel-space address %p\n", targetAddress);
            status = STATUS_ACCESS_VIOLATION;
            goto done;
        }

        DbgPrint("[MemReader] READ_MEMORY: PID=%llu addr=%p len=%zu\n",
                 (ULONG64)targetPid, targetAddress, length);

        // ---------------------------------------------------------------
        // Look up the target EPROCESS by PID.
        // ---------------------------------------------------------------
        PEPROCESS targetProcess = NULL;
        status = PsLookupProcessByProcessId((HANDLE)targetPid, &targetProcess);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[MemReader] PsLookupProcessByProcessId PID=%llu failed: %08X\n",
                     (ULONG64)targetPid, status);
            goto done;
        }

        // ---------------------------------------------------------------
        // Bonus: refuse reads from protected processes (PPL / System).
        //
        // PsIsProtectedProcess is available from WDK 8.1+.
        // Comment out if you need to target protected processes (requires
        // a kernel exploit — outside scope of this exercise).
        // ---------------------------------------------------------------
#if (NTDDI_VERSION >= NTDDI_WINBLUE)
        if (PsIsProtectedProcess(targetProcess)) {
            DbgPrint("[MemReader] Target PID=%llu is a protected process — denied\n",
                     (ULONG64)targetPid);
            ObDereferenceObject(targetProcess);
            status = STATUS_ACCESS_DENIED;
            goto done;
        }
#endif

        // ---------------------------------------------------------------
        // Copy memory using MmCopyVirtualMemory.
        //
        // Arguments:
        //   SourceProcess  — process to read FROM (the target)
        //   SourceAddress  — virtual address in that process
        //   TargetProcess  — process to copy INTO (our driver's caller)
        //   TargetAddress  — where to put the bytes (SystemBuffer output)
        //   PreviousMode   — KernelMode suppresses probe-for-write checks
        //                    on the destination buffer (which is kernel memory)
        // ---------------------------------------------------------------
        PVOID  outBuffer = Irp->AssociatedIrp.SystemBuffer;  // reuse for output
        SIZE_T copied    = 0;

        __try {
            status = MmCopyVirtualMemory(
                targetProcess,   // source process
                targetAddress,   // source address
                PsGetCurrentProcess(), // destination process (this driver / kernel)
                outBuffer,       // destination (kernel SystemBuffer)
                length,
                KernelMode,
                &copied);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // MmCopyVirtualMemory can raise on invalid source pages.
            NTSTATUS exCode = GetExceptionCode();
            DbgPrint("[MemReader] Exception during MmCopyVirtualMemory: %08X\n", exCode);
            status = exCode;
            copied = 0;
        }

        bytesReturned = copied;

        if (NT_SUCCESS(status)) {
            DbgPrint("[MemReader] Copied %zu bytes from PID=%llu addr=%p\n",
                     copied, (ULONG64)targetPid, targetAddress);
        } else {
            DbgPrint("[MemReader] MmCopyVirtualMemory failed: %08X\n", status);
        }

        // ---------------------------------------------------------------
        // Release the reference acquired by PsLookupProcessByProcessId.
        // Every successful PsLookupProcessByProcessId call increments the
        // EPROCESS reference count; we must decrement it when done.
        // ---------------------------------------------------------------
        ObDereferenceObject(targetProcess);
    }

done:
    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// ---------------------------------------------------------------------------
// DispatchPassthrough — handles all other IRP major functions
// ---------------------------------------------------------------------------
NTSTATUS DispatchPassthrough(PDEVICE_OBJECT DevObj, PIRP Irp) {
    UNREFERENCED_PARAMETER(DevObj);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// DriverUnload — clean up device and symlink
// ---------------------------------------------------------------------------
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNICODE_STRING sym = RTL_CONSTANT_STRING(SYMLINK_NAME);
    IoDeleteSymbolicLink(&sym);
    if (g_DeviceObject) IoDeleteDevice(g_DeviceObject);
    DbgPrint("[MemReader] Unloaded\n");
}

// ---------------------------------------------------------------------------
// DriverEntry — create device, register dispatch routines
// ---------------------------------------------------------------------------
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    UNICODE_STRING devName = RTL_CONSTANT_STRING(DEVICE_NAME);
    UNICODE_STRING symName = RTL_CONSTANT_STRING(SYMLINK_NAME);

    // Create the device object.
    NTSTATUS status = IoCreateDevice(
        DriverObject,
        0,                    // no extension
        &devName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[MemReader] IoCreateDevice failed: %08X\n", status);
        return status;
    }

    // Expose as \\.\MemReader to user-mode.
    status = IoCreateSymbolicLink(&symName, &devName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[MemReader] IoCreateSymbolicLink failed: %08X\n", status);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    // Register dispatch routines.
    DriverObject->DriverUnload = DriverUnload;
    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = DispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;

    // Clear the initializing flag so the device is usable.
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrint("[MemReader] Loaded — IOCTL code: 0x%08X\n", IOCTL_READ_MEMORY);
    return STATUS_SUCCESS;
}
