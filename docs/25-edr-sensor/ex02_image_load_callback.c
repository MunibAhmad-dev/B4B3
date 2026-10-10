/*
  Exercise 02 — Kernel Driver: Image Load Notification
  ------------------------------------------------------
  PsSetLoadImageNotifyRoutine fires every time a PE (EXE or DLL) is loaded
  into any process's address space.

  Use cases:
    - Detect malicious DLL injection (detect when a known-bad DLL loads)
    - Log every DLL loaded into a target process (process hollowing detection)
    - Detect unsigned DLLs being loaded into high-privilege processes
    - Detect reflective loaders (they load a PE with no image name)

  Tasks:
  1. Complete ImageLoadCallback:
     - Print the image name, PID, and load address.
     - Flag if FullImageName is NULL (possible reflective load / shellcode).
     - Flag if the image is being loaded into lsass.exe (credential access).
  2. In DriverEntry, also call PsSetCreateProcessNotifyRoutineEx so you
     can maintain a PID→name mapping (to know which process is LSASS).
  3. In DriverUnload, remove both callbacks.

  BONUS:
  - Check the image's signature status:
    SeQueryAuthenticationIdToken → is the DLL signed? (use CmVerifyBinaryType).
    Flag all unsigned DLLs loading into svchost.exe.
  - Build a "protected process list": if a DLL loads into a protected process,
    alert via DbgPrint with CRITICAL severity.

  Build: WDK required. See ex01 for build instructions.
*/

#include <ntddk.h>

// Simplified PID→name map (for real use, a proper hash map or red-black tree)
static HANDLE g_LsassPid  = nullptr;
static HANDLE g_LsassPid2 = nullptr; // some systems have >1 lsass

// ---------- TODO 1: ImageLoadCallback ----------
VOID ImageLoadCallback(
    PUNICODE_STRING FullImageName,   // path of the loaded image (may be NULL)
    HANDLE          ProcessId,       // PID it loaded into
    PIMAGE_INFO     ImageInfo        // load address, size, etc.
) {
    if (!FullImageName || !FullImageName->Buffer) {
        // NULL image name = anomalous: manual mapping or reflective injection
        DbgPrint("[EDR-IMG] *** ANONYMOUS LOAD: PID=%llu  addr=%p  size=0x%zX\n",
                 (ULONG64)(ULONG_PTR)ProcessId,
                 ImageInfo->ImageBase,
                 ImageInfo->ImageSize);
        return;
    }

    DbgPrint("[EDR-IMG] Load: PID=%llu  addr=%p  %wZ\n",
             (ULONG64)(ULONG_PTR)ProcessId,
             ImageInfo->ImageBase,
             FullImageName);

    // TODO: flag DLL loading into LSASS
    // if (ProcessId == g_LsassPid) {
    //     DbgPrint("[EDR-IMG] *** DLL loading into LSASS: %wZ\n", FullImageName);
    // }

    // TODO: flag injected DLLs (loading from Temp/AppData)
    // UNICODE_STRING temp = RTL_CONSTANT_STRING(L"\\Temp\\");
    // if (RtlFindUnicodePrefix(FullImageName, &temp, 0)) {
    //     DbgPrint("[EDR-IMG] *** DLL from suspicious path: %wZ\n", FullImageName);
    // }
}

// Process callback to track LSASS PID
VOID ProcessNotifyForLsass(
    PEPROCESS Process,
    HANDLE    ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    UNREFERENCED_PARAMETER(Process);
    if (!CreateInfo) return;
    if (!CreateInfo->ImageFileName) return;

    UNICODE_STRING lsass = RTL_CONSTANT_STRING(L"lsass.exe");
    UNICODE_STRING shortName;
    // Extract base name
    shortName = *CreateInfo->ImageFileName;
    for (int i = shortName.Length / 2 - 1; i >= 0; i--) {
        if (shortName.Buffer[i] == L'\\') {
            shortName.Buffer  += i + 1;
            shortName.Length  -= (USHORT)((i + 1) * 2);
            break;
        }
    }
    if (RtlEqualUnicodeString(&shortName, &lsass, TRUE)) {
        g_LsassPid = ProcessId;
        DbgPrint("[EDR-IMG] LSASS found: PID=%llu\n", (ULONG64)(ULONG_PTR)ProcessId);
    }
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);
    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyForLsass, TRUE);
    DbgPrint("[EDR-IMG] Unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;

    NTSTATUS status;

    // Register image load callback
    status = PsSetLoadImageNotifyRoutine(ImageLoadCallback);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR-IMG] PsSetLoadImageNotifyRoutine failed: 0x%08X\n", status);
        return status;
    }

    // Register process callback to track LSASS
    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyForLsass, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR-IMG] PsSetCreateProcessNotifyRoutineEx failed: 0x%08X\n", status);
        PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);
        return status;
    }

    DbgPrint("[EDR-IMG] Image load callback registered\n");
    return STATUS_SUCCESS;
}
