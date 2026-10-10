// ex01_eprocess_walk.cpp — Walk process list via NtQuerySystemInformation
// Exercise: enumerate all processes and print PID, PPID, name, and session
// Compile: g++ -std=c++17 -o ex01.exe ex01_eprocess_walk.cpp

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <vector>

// TODO 1: Call NtQuerySystemInformation(SystemProcessInformation, ...) with a
//         growing buffer until it returns STATUS_SUCCESS.

// TODO 2: Walk the linked list of SYSTEM_PROCESS_INFORMATION structs.
//         Each entry has: UniqueProcessId, InheritedFromUniqueProcessId,
//         ImageName (UNICODE_STRING), SessionId, NumberOfThreads.

// TODO 3: Print a table: PID | PPID | Session | Threads | Name

// TODO 4: Also print each process's thread TIDs by walking the Threads[]
//         array embedded after SYSTEM_PROCESS_INFORMATION.

// Hint: NextEntryOffset == 0 means last entry.
// Hint: typedef NTSTATUS(WINAPI* NtQSI_t)(ULONG,PVOID,ULONG,PULONG);
//       auto NtQSI = (NtQSI_t)GetProcAddress(GetModuleHandleA("ntdll"),"NtQuerySystemInformation");

int main() {
    // YOUR CODE HERE
    printf("EPROCESS walk exercise — implement the TODOs above\n");
    return 0;
}
