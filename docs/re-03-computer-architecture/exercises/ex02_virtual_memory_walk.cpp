// Exercise 2: Virtual Memory Walk (Windows)
// Enumerate and analyze the virtual address space of a process.
//
// TASKS:
//  1. Run the tool against itself — understand each region type.
//  2. Identify: stack, heap, PE image, PEB/TEB, ntdll, kernel32.
//  3. Find all RWX (read-write-execute) regions — these are suspicious!
//  4. Calculate total committed memory vs reserved memory.
//  5. Add a function that searches all readable regions for a magic pattern.
//
// COMPILE: cl /W4 /std:c++17 ex02_virtual_memory_walk.cpp /Fe:ex02.exe

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#include <cstdio>
#include <cstdint>
#pragma comment(lib, "psapi.lib")

const char* protect_str(DWORD prot) {
    switch (prot & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE)) {
        case PAGE_NOACCESS:           return "---";
        case PAGE_READONLY:           return "R--";
        case PAGE_READWRITE:          return "RW-";
        case PAGE_WRITECOPY:          return "RWC";
        case PAGE_EXECUTE:            return "--X";
        case PAGE_EXECUTE_READ:       return "R-X";
        case PAGE_EXECUTE_READWRITE:  return "RWX";  // SUSPICIOUS
        case PAGE_EXECUTE_WRITECOPY:  return "RWX(C)";
        default:                      return "???";
    }
}

const char* type_str(DWORD type) {
    switch (type) {
        case MEM_IMAGE:   return "IMAGE  ";
        case MEM_MAPPED:  return "MAPPED ";
        case MEM_PRIVATE: return "PRIVATE";
        default:          return "FREE   ";
    }
}

const char* state_str(DWORD state) {
    switch (state) {
        case MEM_COMMIT:   return "COMMIT ";
        case MEM_RESERVE:  return "RESERVE";
        case MEM_FREE:     return "FREE   ";
        default:           return "?      ";
    }
}

// Try to get the mapped file name for this region
void get_region_name(HANDLE hProcess, LPCVOID addr, char* out, size_t outlen) {
    out[0] = 0;
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) return;
    if (mbi.Type == MEM_IMAGE) {
        char path[MAX_PATH] = {};
        if (GetMappedFileNameA(hProcess, (LPVOID)addr, path, MAX_PATH)) {
            // Shorten path to just filename
            const char* p = strrchr(path, '\\');
            strncpy(out, p ? p+1 : path, outlen-1);
        }
    }
}

void walk_vas(HANDLE hProcess) {
    printf("\n%-20s  %-10s  %-8s  %-8s  %-8s  %s\n",
           "Address", "Size(KB)", "State", "Type", "Prot", "Module");
    printf("%-20s  %-10s  %-8s  %-8s  %-8s  %s\n",
           "--------------------","----------","--------","--------","--------","------");

    uintptr_t addr   = 0;
    size_t total_commit   = 0;
    size_t total_reserved = 0;
    size_t total_rwx      = 0;
    int    rwx_count      = 0;

    MEMORY_BASIC_INFORMATION mbi;
    while (VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi))) {
        if (mbi.State != MEM_FREE) {
            char name[MAX_PATH] = {};
            get_region_name(hProcess, (LPCVOID)addr, name, sizeof(name));

            printf("%18p  %10zu  %s  %s  %-8s  %s\n",
                   mbi.BaseAddress,
                   mbi.RegionSize / 1024,
                   state_str(mbi.State),
                   type_str(mbi.Type),
                   protect_str(mbi.Protect),
                   name);

            if (mbi.State == MEM_COMMIT) {
                total_commit += mbi.RegionSize;
                if ((mbi.Protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) {
                    total_rwx += mbi.RegionSize;
                    rwx_count++;
                    printf("  *** RWX REGION DETECTED ***\n");
                }
            } else if (mbi.State == MEM_RESERVE) {
                total_reserved += mbi.RegionSize;
            }
        }

        if ((uintptr_t)mbi.BaseAddress + mbi.RegionSize <= addr) break;
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }

    printf("\n=== Summary ===\n");
    printf("Total committed:   %zu KB (%.1f MB)\n", total_commit/1024, total_commit/1048576.0);
    printf("Total reserved:    %zu KB (%.1f MB)\n", total_reserved/1024, total_reserved/1048576.0);
    printf("RWX regions:       %d (%.1f KB total) %s\n",
           rwx_count, total_rwx/1024.0,
           rwx_count > 0 ? "<-- SUSPICIOUS" : "(clean)");
}

// Task 5: search all readable committed regions for a pattern
size_t search_pattern(HANDLE hProcess, const uint8_t* pattern, size_t patlen) {
    // TODO:
    // 1. Enumerate all MEM_COMMIT regions with readable protection
    // 2. ReadProcessMemory each region into a local buffer
    // 3. Search for the pattern using memmem equivalent
    // 4. Print each match address
    // 5. Return total match count
    (void)hProcess; (void)pattern; (void)patlen;
    printf("[TODO] search_pattern not implemented\n");
    return 0;
}

int main() {
    printf("Virtual Memory Walker\n");
    printf("=====================\n");
    printf("PID: %lu\n", GetCurrentProcessId());

    HANDLE hSelf = GetCurrentProcess();

    // Walk our own VAS
    walk_vas(hSelf);

    // Show our own PEB and TEB addresses
    PTEB teb = NtCurrentTeb();
    PPEB peb = teb->ProcessEnvironmentBlock;
    printf("\n=== Key Addresses ===\n");
    printf("PEB:              %p\n", (void*)peb);
    printf("TEB (this thread):%p\n", (void*)teb);
    printf("Image base:       %p\n", (void*)peb->Reserved3[1]);
    printf("Stack base:       %p\n", (void*)teb->Reserved1[1]);
    printf("Stack limit:      %p\n", (void*)teb->Reserved1[2]);

    // Search for MZ header in our image
    printf("\n=== Pattern Search: MZ header (4D 5A) ===\n");
    const uint8_t mz[] = { 0x4D, 0x5A };
    search_pattern(hSelf, mz, sizeof(mz));

    return 0;
}
#else
int main() { puts("Windows only."); return 0; }
#endif
