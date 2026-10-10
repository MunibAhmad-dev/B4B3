/*
  Solution 01 — Minimal WDM Kernel Driver
  -----------------------------------------
  Complete implementation: DriverEntry, DriverUnload, OS version print,
  start counter.

  BUILD: Requires WDK + test-signing VM.
    1. Open Developer Command Prompt for VS
    2. Create a WDM project, add this file
    3. MSBuild → MyDriver.sys
    4. On test VM: sc create / sc start

  IMPORTANT: Run only in a test VM with bcdedit /set testsigning on
*/

#include <ntddk.h>

// Count how many times this driver has been started this boot session
static LONG g_StartCount = 0;

// ── DriverUnload ──────────────────────────────────────────────────────────────
VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("[MinDriver] Unloaded! (was started %ld time(s) this session)\n",
             g_StartCount);
}

// ── DriverEntry ───────────────────────────────────────────────────────────────
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    // Register unload routine (required to allow sc stop)
    DriverObject->DriverUnload = DriverUnload;

    // Increment start counter
    InterlockedIncrement(&g_StartCount);

    DbgPrint("[MinDriver] Loaded! Start count this session: %ld\n", g_StartCount);

    // Print OS version using RtlGetVersion (preferred; PsGetVersion is deprecated)
    RTL_OSVERSIONINFOW osVer = { 0 };
    osVer.dwOSVersionInfoSize = sizeof(osVer);
    NTSTATUS status = RtlGetVersion(&osVer);
    if (NT_SUCCESS(status)) {
        DbgPrint("[MinDriver] OS version: %lu.%lu build %lu\n",
                 osVer.dwMajorVersion,
                 osVer.dwMinorVersion,
                 osVer.dwBuildNumber);
    }

    return STATUS_SUCCESS;
}
