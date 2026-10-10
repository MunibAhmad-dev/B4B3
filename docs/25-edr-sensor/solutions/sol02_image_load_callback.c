/*
  Solution 02 — Kernel Driver: Image Load Notification
  ------------------------------------------------------
  Complete image load notification driver that:
    - Registers PsSetLoadImageNotifyRoutine for all DLL/EXE loads.
    - Flags NULL image names (anonymous loads — possible reflective injection).
    - Tracks the LSASS PID via a parallel process creation callback.
    - Extra alert for every DLL loaded into the LSASS process.
    - Alerts on DLLs loaded from Temp/AppData (likely injected).
    - Properly unregisters both callbacks on unload.

  Build with WDK. See sol01 for build/load instructions.
*/

#include <ntddk.h>

// LSASS PID tracking — volatile because written by process callback,
// read by image load callback (both run at PASSIVE_LEVEL / APC_LEVEL).
static volatile HANDLE g_LsassPid  = NULL;

// ---- Helper: extract base filename from a full path ----
static VOID GetBaseName(PUNICODE_STRING fullPath, PUNICODE_STRING baseName) {
    *baseName = *fullPath;
    for (int i = (int)(fullPath->Length / sizeof(WCHAR)) - 1; i >= 0; i--) {
        if (fullPath->Buffer[i] == L'\\') {
            baseName->Buffer     = fullPath->Buffer + i + 1;
            baseName->Length     = (USHORT)((fullPath->Length / sizeof(WCHAR) - i - 1) * sizeof(WCHAR));
            baseName->MaximumLength = baseName->Length;
            return;
        }
    }
}

// ---- Image Load Callback ----
VOID ImageLoadCallback(
    PUNICODE_STRING FullImageName,   // may be NULL for reflective loads
    HANDLE          ProcessId,
    PIMAGE_INFO     ImageInfo
) {
    if (!FullImageName || !FullImageName->Buffer) {
        // NULL image name = anomalous load: manual mapping, reflective injection,
        // or shellcode that mapped a PE without going through the loader.
        DbgPrint("[EDR-IMG] *** ANONYMOUS LOAD (possible reflective injection?)"
                 " in PID %llu  base=%p  size=0x%zX\n",
                 (ULONG64)(ULONG_PTR)ProcessId,
                 ImageInfo->ImageBase,
                 (SIZE_T)ImageInfo->ImageSize);
        return;
    }

    DbgPrint("[EDR-IMG] Load: PID=%llu  base=%p  %wZ\n",
             (ULONG64)(ULONG_PTR)ProcessId,
             ImageInfo->ImageBase,
             FullImageName);

    // Alert if loading into LSASS
    if (ProcessId == g_LsassPid) {
        UNICODE_STRING baseName;
        GetBaseName(FullImageName, &baseName);
        DbgPrint("[EDR-IMG] *** DLL LOADING INTO LSASS: PID=%llu  %wZ\n",
                 (ULONG64)(ULONG_PTR)ProcessId,
                 &baseName);
    }

    // Alert if DLL path contains \Temp\ or \AppData\ (potential injected DLL)
    UNICODE_STRING temp    = RTL_CONSTANT_STRING(L"\\Temp\\");
    UNICODE_STRING appdata = RTL_CONSTANT_STRING(L"\\AppData\\");

    // RtlFindUnicodePrefix is a prefix check; for a substring scan we use
    // a simple wcsstr-style check against the buffer.
    UNICODE_STRING haystack = *FullImageName;
    BOOLEAN fromSuspPath = FALSE;

    if (haystack.Length > temp.Length) {
        for (USHORT off = 0; off <= haystack.Length - temp.Length; off += sizeof(WCHAR)) {
            UNICODE_STRING sub;
            sub.Buffer     = (PWCH)((UCHAR*)haystack.Buffer + off);
            sub.Length     = temp.Length;
            sub.MaximumLength = temp.Length;
            if (RtlEqualUnicodeString(&sub, &temp, TRUE)) { fromSuspPath = TRUE; break; }
            if (!fromSuspPath && haystack.Length > appdata.Length &&
                off <= haystack.Length - appdata.Length) {
                sub.Buffer     = (PWCH)((UCHAR*)haystack.Buffer + off);
                sub.Length     = appdata.Length;
                sub.MaximumLength = appdata.Length;
                if (RtlEqualUnicodeString(&sub, &appdata, TRUE)) { fromSuspPath = TRUE; break; }
            }
        }
    }

    if (fromSuspPath) {
        DbgPrint("[EDR-IMG] *** SUSPICIOUS PATH DLL: PID=%llu  %wZ\n",
                 (ULONG64)(ULONG_PTR)ProcessId,
                 FullImageName);
    }
}

// ---- Process Callback: track LSASS PID ----
VOID ProcessNotifyForLsass(
    PEPROCESS             Process,
    HANDLE                ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    UNREFERENCED_PARAMETER(Process);
    if (!CreateInfo) return;             // process EXIT — ignore here
    if (!CreateInfo->ImageFileName) return;

    UNICODE_STRING baseName;
    GetBaseName(CreateInfo->ImageFileName, &baseName);

    UNICODE_STRING lsass = RTL_CONSTANT_STRING(L"lsass.exe");
    if (RtlEqualUnicodeString(&baseName, &lsass, TRUE)) {
        g_LsassPid = ProcessId;
        DbgPrint("[EDR-IMG] LSASS detected: PID=%llu\n",
                 (ULONG64)(ULONG_PTR)ProcessId);
    }
}

// ---- Driver Unload ----
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);
    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyForLsass, TRUE);
    DbgPrint("[EDR-IMG] Callbacks unregistered. Driver unloaded.\n");
}

// ---- Driver Entry ----
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    DriverObject->DriverUnload = DriverUnload;

    // Register image load callback first
    status = PsSetLoadImageNotifyRoutine(ImageLoadCallback);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR-IMG] PsSetLoadImageNotifyRoutine failed: 0x%08X\n", status);
        return status;
    }

    // Register process callback to track LSASS PID
    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyForLsass, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR-IMG] PsSetCreateProcessNotifyRoutineEx failed: 0x%08X\n", status);
        PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);
        return status;
    }

    DbgPrint("[EDR-IMG] Image load callback registered.\n");
    DbgPrint("[EDR-IMG] Watching for: anonymous loads, LSASS DLL loads, Temp/AppData DLLs.\n");
    return STATUS_SUCCESS;
}
