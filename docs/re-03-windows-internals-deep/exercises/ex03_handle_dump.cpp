// ex03_handle_dump.cpp — Dump handles for a process using SystemHandleInformation
// Exercise: find all handles owned by a target PID and print type + object address
// Compile: g++ -std=c++17 -o ex03.exe ex03_handle_dump.cpp

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <vector>

// SystemHandleInformation = 16
// SYSTEM_HANDLE_ENTRY layout:
//   ULONG  OwnerPid
//   BYTE   ObjectType
//   BYTE   HandleFlags
//   USHORT HandleValue
//   PVOID  ObjectPointer
//   ULONG  AccessMask

// TODO 1: NtQuerySystemInformation(16, ...) with growing buffer.
//         The return structure is: ULONG HandleCount, followed by HandleCount entries.

// TODO 2: Filter by OwnerPid == target_pid.

// TODO 3: For each matching handle, print HandleValue, ObjectType, ObjectPointer, AccessMask.

// TODO 4 (bonus): Duplicate the handle into your process with NtDuplicateObject,
//         then call NtQueryObject(ObjectTypeInformation) to get the type name string.

// Usage: ex03.exe <pid>

int main(int argc, char* argv[]) {
    if (argc < 2) { printf("Usage: ex03.exe <pid>\n"); return 1; }
    DWORD target = (DWORD)strtoul(argv[1], nullptr, 10);
    printf("Handle dump for PID %lu — implement the TODOs above\n", target);
    return 0;
}
