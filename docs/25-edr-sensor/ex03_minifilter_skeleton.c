/*
  Exercise 03 — Minifilter Driver Skeleton
  -----------------------------------------
  A minifilter intercepts file system I/O before it reaches the underlying
  file system driver. EDRs use minifilters to:
    - Log all file access (who opened what file, when)
    - Block writes to protected files
    - Detect ransomware by monitoring bulk file renames
    - Scan file content on write (like an on-access antivirus)

  This skeleton registers a minifilter with:
    - Pre-create callback: fires before any file is opened/created
    - Pre-write callback:  fires before any data is written

  Tasks:
  1. Complete PreCreateCallback:
     - Get the file name using FltGetFileNameInformation.
     - Print the accessing process PID and full file path.
     - Flag access to C:\Windows\System32\lsass.exe (any process reading lsass!).
  2. Complete PreWriteCallback:
     - Print file name + bytes being written.
     - Detect potential ransomware: if a process has renamed >10 files
       in the last 1 second, emit a WARNING.
  3. Add a pre-rename callback (IRP_MJ_SET_INFORMATION, FileRenameInformation)
     to track file renames per process.
  4. In DriverEntry, register with FltRegisterFilter + FltStartFiltering.

  BONUS:
  - Block writes to files with extensions .exe, .dll, .sys (simulates
    an integrity monitor).
  - Pass file content to a user-mode service via a shared ring buffer
    for YARA scanning before write completes.

  Build: WDK. Add "fltMgr.lib" to linker inputs.
  INF file required to install a minifilter — see WDK minifilter sample.
*/

#include <fltKernel.h>

PFLT_FILTER g_FilterHandle = nullptr;

// Rename tracker (process → rename count + timestamp)
static volatile LONG g_RenameCounter = 0;

// ---------- TODO 1: Pre-create callback ----------
FLT_PREOP_CALLBACK_STATUS PreCreateCallback(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PFLT_FILE_NAME_INFORMATION nameInfo = nullptr;
    NTSTATUS status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);

    if (NT_SUCCESS(status)) {
        FltParseFileNameInformation(nameInfo);

        ULONG_PTR pid = (ULONG_PTR)FltGetRequestorProcessId(Data);
        DbgPrint("[EDR-FS] Create: PID=%llu  %wZ\n", (ULONG64)pid, &nameInfo->Name);

        // TODO: flag access to lsass.exe
        // UNICODE_STRING lsass = RTL_CONSTANT_STRING(L"lsass.exe");
        // if (RtlEqualUnicodeString(&nameInfo->FinalComponent, &lsass, TRUE)) {
        //     DbgPrint("[EDR-FS] *** LSASS ACCESS: PID=%llu\n", (ULONG64)pid);
        // }

        FltReleaseFileNameInformation(nameInfo);
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ---------- TODO 2: Pre-write callback ----------
FLT_PREOP_CALLBACK_STATUS PreWriteCallback(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PFLT_FILE_NAME_INFORMATION nameInfo = nullptr;
    if (NT_SUCCESS(FltGetFileNameInformation(
            Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo))) {
        FltParseFileNameInformation(nameInfo);
        ULONG writeLen = Data->Iopb->Parameters.Write.Length;
        DbgPrint("[EDR-FS] Write: %wZ  bytes=%lu\n", &nameInfo->Name, writeLen);
        FltReleaseFileNameInformation(nameInfo);
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ---------- TODO 3: Pre-rename callback ----------
FLT_PREOP_CALLBACK_STATUS PreSetInfoCallback(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // Only care about rename
    if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass
            == FileRenameInformation) {
        // TODO: increment per-process rename counter
        // Check if > 10 renames in last second → ransomware warning
        LONG count = InterlockedIncrement(&g_RenameCounter);
        if (count > 10) {
            DbgPrint("[EDR-FS] *** HIGH RENAME RATE (%ld): possible ransomware!\n", count);
        }
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ---- Filter registration table ----
const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,         0, PreCreateCallback,  nullptr },
    { IRP_MJ_WRITE,          0, PreWriteCallback,   nullptr },
    { IRP_MJ_SET_INFORMATION,0, PreSetInfoCallback, nullptr },
    { IRP_MJ_OPERATION_END }
};

NTSTATUS FilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);
    FltUnregisterFilter(g_FilterHandle);
    DbgPrint("[EDR-FS] Minifilter unloaded\n");
    return STATUS_SUCCESS;
}

const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                   // flags
    nullptr,             // context registrations
    Callbacks,
    FilterUnload,
    nullptr,             // InstanceSetup
    nullptr,             // InstanceQueryTeardown
    nullptr,             // InstanceTeardownStart
    nullptr,             // InstanceTeardownComplete
    nullptr, nullptr, nullptr
};

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR-FS] FltRegisterFilter failed: 0x%08X\n", status);
        return status;
    }

    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_FilterHandle);
        return status;
    }

    DbgPrint("[EDR-FS] Minifilter registered and filtering\n");
    return STATUS_SUCCESS;
}
