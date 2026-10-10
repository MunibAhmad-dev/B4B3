/*
  Exercise 01 — Minimal WDM Kernel Driver
  -----------------------------------------
  Build, sign (test-sign), load, and unload a kernel driver that:
  1. Prints "Loaded!" to DebugView on start
  2. Prints "Unloaded!" on stop
  3. Accepts the sc start / sc stop commands cleanly

  This is the kernel equivalent of "Hello World". Every more complex driver
  is built on exactly this skeleton.

  SETUP (one-time):
  1. Install WDK: https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
  2. Enable test signing on the TEST VM (NOT your main machine):
       bcdedit /set testsigning on
       reboot
  3. Install Sysinternals DebugView (https://docs.microsoft.com/sysinternals)
     Run as admin, enable Kernel: Capture Kernel

  BUILD (Visual Studio):
  1. File → New → Project → "Kernel Mode Driver, Empty (KMDF)" or WDM
  2. Add this .c file as a source file
  3. Build → produces MyDriver.sys

  BUILD (manual with WDK tools + MSBuild):
  See WDK documentation for command-line build.

  LOAD AND TEST:
    sc create MyDriver type= kernel binPath= C:\full\path\MyDriver.sys
    sc start MyDriver      → should see "[MyDriver] Loaded!" in DebugView
    sc stop  MyDriver      → should see "[MyDriver] Unloaded!"
    sc delete MyDriver

  TASKS:
  1. Get the minimal driver below compiling and loading.
  2. Add DbgPrint that prints the OS version number (use RtlGetVersion or
     PsGetVersion) in DriverEntry.
  3. Add a counter: count how many times the driver has been started this
     boot session (use a static variable).

  NOTE: Kernel crashes (BSODs) are normal during development. Use a VM.
  The crash dump is in C:\Windows\MEMORY.DMP — open with WinDbg: !analyze -v
*/

#include <ntddk.h>

// Forward declaration
DRIVER_UNLOAD DriverUnload;

// Called when the driver is unloaded (sc stop MyDriver)
VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("[MyDriver] Unloaded!\n");
}

// Entry point — kernel calls this after loading the .sys file
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[MyDriver] Loaded!\n");

    // Register the unload routine — without this, sc stop returns an error
    DriverObject->DriverUnload = DriverUnload;

    // TODO 1: Print the OS version
    // RTL_OSVERSIONINFOW ver = { sizeof(ver) };
    // RtlGetVersion(&ver);
    // DbgPrint("[MyDriver] OS: %lu.%lu.%lu\n", ver.dwMajorVersion,
    //          ver.dwMinorVersion, ver.dwBuildNumber);

    // TODO 2: Print something about this driver object
    // DbgPrint("[MyDriver] Driver object at: %p\n", DriverObject);

    return STATUS_SUCCESS;
}
