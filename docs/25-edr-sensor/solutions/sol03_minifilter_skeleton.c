/*
  Solution 03 — Minifilter Driver (Ransomware Detection)
  -------------------------------------------------------
  Complete minifilter that hooks:
    IRP_MJ_CREATE        — log every file open/create with PID + path
    IRP_MJ_WRITE         — log file writes (process name + byte count)
    IRP_MJ_SET_INFORMATION — track file renames per process;
                             alert when a PID renames >10 files

  The rename counter is per-PID using a simple fixed-size table
  (real production code would use a hash map with proper locking).

  Build: WDK + Visual Studio. Add fltMgr.lib to linker inputs.
  Requires a minifilter INF file to install — see the WDK minifilter sample.
  A minimal INF and altitude value (e.g. 370030) are needed.

  Load (with INF):
    fltMC load   <filtername>
    fltMC unload <filtername>
*/

#include <fltKernel.h>
#include <wdm.h>

PFLT_FILTER g_FilterHandle = NULL;

// ---- Per-PID rename tracking ----
#define MAX_TRACKED_PIDS   256
#define RENAME_ALERT_THRESHOLD 10

typedef struct _PID_RENAME_ENTRY {
    ULONG_PTR  Pid;
    LONG       RenameCount;
    LARGE_INTEGER FirstRenameTime;  // 100-ns ticks
    BOOLEAN    Alerted;
} PID_RENAME_ENTRY;

static PID_RENAME_ENTRY g_RenameTable[MAX_TRACKED_PIDS];
static KSPIN_LOCK       g_RenameTableLock;

static VOID InitRenameTable(VOID) {
    KeInitializeSpinLock(&g_RenameTableLock);
    RtlZeroMemory(g_RenameTable, sizeof(g_RenameTable));
}

static VOID TrackRenameForPid(ULONG_PTR pid) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_RenameTableLock, &oldIrql);

    // Find existing slot or empty slot
    int slot = -1;
    for (int i = 0; i < MAX_TRACKED_PIDS; i++) {
        if (g_RenameTable[i].Pid == pid) { slot = i; break; }
        if (slot == -1 && g_RenameTable[i].Pid == 0) slot = i;
    }

    if (slot == -1) {
        // Table full — evict oldest (simplistic: slot 0)
        slot = 0;
        g_RenameTable[slot].Pid         = 0;
        g_RenameTable[slot].RenameCount = 0;
        g_RenameTable[slot].Alerted     = FALSE;
    }

    if (g_RenameTable[slot].Pid == 0) {
        // New entry
        g_RenameTable[slot].Pid = pid;
        g_RenameTable[slot].RenameCount = 0;
        g_RenameTable[slot].Alerted     = FALSE;
        KeQuerySystemTime(&g_RenameTable[slot].FirstRenameTime);
    }

    LONG count = InterlockedIncrement(&g_RenameTable[slot].RenameCount);

    BOOLEAN shouldAlert = FALSE;
    if (count > RENAME_ALERT_THRESHOLD && !g_RenameTable[slot].Alerted) {
        g_RenameTable[slot].Alerted = TRUE;
        shouldAlert = TRUE;
    }

    KeReleaseSpinLock(&g_RenameTableLock, oldIrql);

    if (shouldAlert) {
        DbgPrint("[EDR-FS] *** RANSOMWARE ALERT: PID %llu renamed more than %d files!\n",
                 (ULONG64)pid, RENAME_ALERT_THRESHOLD);
    }
}

// ---- Helper: alert on access to lsass.exe ----
static VOID CheckLsassAccess(PFLT_FILE_NAME_INFORMATION nameInfo, ULONG64 pid) {
    UNICODE_STRING lsass = RTL_CONSTANT_STRING(L"lsass.exe");
    if (RtlEqualUnicodeString(&nameInfo->FinalComponent, &lsass, TRUE)) {
        DbgPrint("[EDR-FS] *** LSASS FILE ACCESS: PID=%llu\n", pid);
    }
}

// ---- Pre-Create Callback ----
FLT_PREOP_CALLBACK_STATUS PreCreateCallback(
    PFLT_CALLBACK_DATA    Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID*                CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);

    if (NT_SUCCESS(status)) {
        FltParseFileNameInformation(nameInfo);

        ULONG64 pid = (ULONG64)(ULONG_PTR)FltGetRequestorProcessId(Data);
        DbgPrint("[EDR-FS] Create: PID=%llu  %wZ\n", pid, &nameInfo->Name);

        CheckLsassAccess(nameInfo, pid);
        FltReleaseFileNameInformation(nameInfo);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ---- Pre-Write Callback ----
FLT_PREOP_CALLBACK_STATUS PreWriteCallback(
    PFLT_CALLBACK_DATA    Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID*                CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    ULONG64 pid      = (ULONG64)(ULONG_PTR)FltGetRequestorProcessId(Data);
    ULONG   writeLen = Data->Iopb->Parameters.Write.Length;

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    if (NT_SUCCESS(FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &nameInfo))) {
        FltParseFileNameInformation(nameInfo);
        DbgPrint("[EDR-FS] Write: PID=%llu  bytes=%lu  %wZ\n",
                 pid, writeLen, &nameInfo->FinalComponent);
        FltReleaseFileNameInformation(nameInfo);
    } else {
        DbgPrint("[EDR-FS] Write: PID=%llu  bytes=%lu  (path unavailable)\n",
                 pid, writeLen);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ---- Pre-SetInformation Callback (rename tracking) ----
FLT_PREOP_CALLBACK_STATUS PreSetInfoCallback(
    PFLT_CALLBACK_DATA    Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID*                CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // Only care about rename operations
    FILE_INFORMATION_CLASS infoClass =
        Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    if (infoClass != FileRenameInformation &&
        infoClass != FileRenameInformationEx) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    ULONG_PTR pid = (ULONG_PTR)FltGetRequestorProcessId(Data);
    TrackRenameForPid(pid);

    DbgPrint("[EDR-FS] Rename: PID=%llu\n", (ULONG64)pid);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ---- Filter Operation Table ----
const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,          0, PreCreateCallback,  NULL },
    { IRP_MJ_WRITE,           0, PreWriteCallback,   NULL },
    { IRP_MJ_SET_INFORMATION, 0, PreSetInfoCallback, NULL },
    { IRP_MJ_OPERATION_END }
};

// ---- Filter Unload ----
NTSTATUS FilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);
    FltUnregisterFilter(g_FilterHandle);
    DbgPrint("[EDR-FS] Minifilter unloaded\n");
    return STATUS_SUCCESS;
}

// ---- Filter Registration ----
const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,          // flags
    NULL,       // context registrations
    Callbacks,
    FilterUnload,
    NULL,       // InstanceSetup
    NULL,       // InstanceQueryTeardown
    NULL,       // InstanceTeardownStart
    NULL,       // InstanceTeardownComplete
    NULL,       // GenerateFileName
    NULL,       // NormalizeNameComponent
    NULL        // NormalizeContextCleanup
};

// ---- Driver Entry ----
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    InitRenameTable();

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR-FS] FltRegisterFilter failed: 0x%08X\n", status);
        return status;
    }

    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR-FS] FltStartFiltering failed: 0x%08X\n", status);
        FltUnregisterFilter(g_FilterHandle);
        return status;
    }

    DbgPrint("[EDR-FS] Minifilter registered and active.\n");
    DbgPrint("[EDR-FS] Rename threshold = %d (ransomware detection).\n",
             RENAME_ALERT_THRESHOLD);
    return STATUS_SUCCESS;
}
