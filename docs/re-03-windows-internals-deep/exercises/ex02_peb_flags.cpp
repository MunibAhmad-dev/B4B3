// ex02_peb_flags.cpp — Read PEB fields directly via GS/FS register
// Exercise: read BeingDebugged, NtGlobalFlag, ImageBase, and module list from own PEB
// Compile: g++ -std=c++17 -o ex02.exe ex02_peb_flags.cpp

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <stdio.h>

// TODO 1: Read PEB pointer from GS:[0x60] (x64) using __readgsqword.
//         Cast to PEB* and print BeingDebugged (+0x002) and NtGlobalFlag (+0x068 x64).

// TODO 2: Walk PEB->Ldr->InLoadOrderModuleList and print each module:
//         DllBase, SizeOfImage, FullDllName.Buffer

// TODO 3: Read PEB->ProcessParameters->CommandLine and ImagePathName.

// TODO 4: Patch your own BeingDebugged byte to 0 and verify IsDebuggerPresent()
//         returns FALSE afterward.

// Hint for NtGlobalFlag offset x64: PEB is at GS:[0x60]; NtGlobalFlag is at PEB+0xBC

int main() {
    printf("PEB flags exercise — implement the TODOs above\n");
    return 0;
}
