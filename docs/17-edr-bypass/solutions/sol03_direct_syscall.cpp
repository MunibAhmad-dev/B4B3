/*
  Solution 03 — Direct Syscall (complete)
*/
#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <iomanip>
#include <cstring>

typedef NTSTATUS (NTAPI *pfnNtAllocVirt)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

void buildSyscallStub(BYTE* buf, DWORD syscallNumber) {
    // mov r10, rcx
    buf[0] = 0x4C; buf[1] = 0x8B; buf[2] = 0xD1;
    // mov eax, <syscall_number>
    buf[3] = 0xB8;
    memcpy(buf + 4, &syscallNumber, 4);
    // syscall
    buf[8] = 0x0F; buf[9] = 0x05;
    // ret
    buf[10] = 0xC3;
}

DWORD getSyscallNumberFromNtdll(const char* funcName) {
    PBYTE stub = (PBYTE)GetProcAddress(GetModuleHandleA("ntdll.dll"), funcName);
    if (!stub) return (DWORD)-1;
    if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 && stub[3] == 0xB8)
        return *(DWORD*)(stub + 4);
    return (DWORD)-1;
}

int main() {
    printf("=== Direct Syscall Demo ===\n\n");

    DWORD ssn = getSyscallNumberFromNtdll("NtAllocateVirtualMemory");
    if (ssn == (DWORD)-1) { printf("[-] Could not read syscall number\n"); return 1; }
    printf("[+] NtAllocateVirtualMemory = 0x%02X\n", ssn);

    BYTE* stubMem = (BYTE*)VirtualAlloc(nullptr, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!stubMem) { printf("[-] VirtualAlloc stub failed\n"); return 1; }

    buildSyscallStub(stubMem, ssn);

    printf("[+] Stub: ");
    for (int i = 0; i < 11; i++) printf("%02X ", stubMem[i]);
    printf("\n");

    auto directAlloc = (pfnNtAllocVirt)stubMem;

    PVOID  base = nullptr;
    SIZE_T size = 4096;
    NTSTATUS status = directAlloc(GetCurrentProcess(), &base, 0, &size,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (status == 0 && base) {
        printf("[+] Allocated %zu bytes at %p via direct syscall\n", size, base);
        *(DWORD*)base = 0xDEADBEEF;
        printf("[+] Test write OK: 0x%08X\n", *(DWORD*)base);
        VirtualFree(base, 0, MEM_RELEASE);
    } else {
        printf("[-] Failed: 0x%08X\n", status);
    }

    VirtualFree(stubMem, 0, MEM_RELEASE);
    return 0;
}
