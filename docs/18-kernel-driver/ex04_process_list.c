/*
  Exercise 04 — Kernel: Process List & DKOM Hide
  ------------------------------------------------
  Two parts:

  PART A — Walk the kernel process list
  Read the ActiveProcessLinks doubly-linked list in the kernel to enumerate
  all running processes. This is what rootkits compare against Toolhelp32
  to find hidden processes.

  PART B — Hide a process with DKOM
  Remove a PEPROCESS entry from the ActiveProcessLinks list so that any
  user-mode enumerator (Toolhelp32, NtQuerySystemInformation, Task Manager)
  can no longer see the process. The process itself keeps running.

  This is a classic rootkit / red-team technique.
  Blue-team use: writing a detector that finds DKOM-hidden processes by
  comparing the kernel list against brute-force PID scanning.

  Tasks:
  1. Implement listProcesses() — walk ActiveProcessLinks from the SYSTEM
     process (PsInitialSystemProcess) and print each PID + image name.
     Use CONTAINING_RECORD and the ActiveProcessLinks offset.
  2. Implement hideProcess(ULONG_PTR pid) — find the PEPROCESS for the given
     PID and remove it from ActiveProcessLinks (Flink/Blink surgery).

  IMPORTANT OFFSETS (Windows 10/11 x64):
      ActiveProcessLinks offset: 0x448
      UniqueProcessId   offset: 0x440
      ImageFileName     offset: 0x5A8

  These offsets change between Windows versions — in production you'd
  read them from the PDB or from a pre-built offset table.

  BONUS:
  - Use ZwQuerySystemInformation(SystemModuleInformation) to verify the
    hidden process is gone from the user-mode list.
  - Restore the process to the list in DriverUnload (for cleanup).
  - Use PsGetProcessId and PsGetProcessImageFileName (public APIs) instead
    of raw offsets.

  Build: WDK required. Test in a VM with test signing enabled.
*/

#include <ntddk.h>
#include <wdm.h>

// Offsets for Windows 10/11 x64 (20H2 and later)
#define OFFSET_UNIQUE_PROCESS_ID    0x440
#define OFFSET_ACTIVE_PROCESS_LINKS 0x448
#define OFFSET_IMAGE_FILE_NAME      0x5A8

extern PLIST_ENTRY PsActiveProcessHead;  // exported by ntoskrnl on some builds
                                          // alternatively use PsInitialSystemProcess

// Get PID from PEPROCESS using raw offset
static HANDLE getProcessId(PEPROCESS proc) {
    return *(HANDLE*)((PBYTE)proc + OFFSET_UNIQUE_PROCESS_ID);
}

// Get image name from PEPROCESS using raw offset
static const char* getImageName(PEPROCESS proc) {
    return (const char*)((PBYTE)proc + OFFSET_IMAGE_FILE_NAME);
}

// TODO: Walk ActiveProcessLinks and print each process
VOID listProcesses(void) {
    // Hint: start from PsInitialSystemProcess (the SYSTEM process, PID 4)
    // Its ActiveProcessLinks is at offset OFFSET_ACTIVE_PROCESS_LINKS
    // Walk Flink until you return to the starting entry
    //
    // PLIST_ENTRY head = (PLIST_ENTRY)((PBYTE)PsInitialSystemProcess + OFFSET_ACTIVE_PROCESS_LINKS);
    // PLIST_ENTRY cur  = head->Flink;
    // while (cur != head) {
    //     PEPROCESS proc = (PEPROCESS)((PBYTE)cur - OFFSET_ACTIVE_PROCESS_LINKS);
    //     DbgPrint("[PLIST] PID=%llu  %s\n",
    //              (ULONG64)(ULONG_PTR)getProcessId(proc), getImageName(proc));
    //     cur = cur->Flink;
    // }

    DbgPrint("[PLIST] listProcesses not implemented yet\n");
}

// TODO: Remove process from ActiveProcessLinks (DKOM)
VOID hideProcess(ULONG_PTR pid) {
    // 1. Use PsLookupProcessByProcessId to get PEPROCESS
    // 2. Get the PLIST_ENTRY at OFFSET_ACTIVE_PROCESS_LINKS
    // 3. Remove it: entry->Blink->Flink = entry->Flink;
    //               entry->Flink->Blink = entry->Blink;
    //               entry->Flink = entry->Blink = entry; (optional self-loop)
    // 4. ObDereferenceObject when done

    PEPROCESS target = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &target);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[DKOM] PID %llu not found: %08X\n", (ULONG64)pid, status);
        return;
    }

    // YOUR CODE HERE
    DbgPrint("[DKOM] hideProcess not implemented yet (target found: %p)\n", target);

    ObDereferenceObject(target);
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("[ProcList] Unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;

    DbgPrint("[ProcList] Loaded — listing processes:\n");
    listProcesses();

    // To test hiding: hideProcess(target_pid);
    // Replace 1234 with a real PID you want to hide in your test VM
    // hideProcess(1234);

    return STATUS_SUCCESS;
}
