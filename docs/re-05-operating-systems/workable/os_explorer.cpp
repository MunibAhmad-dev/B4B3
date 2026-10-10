// os_explorer.cpp — OS concepts explorer
// Compile: g++ -std=c++17 -o os_explorer.exe os_explorer.cpp
// Usage: os_explorer.exe vad | threads | shm-server | shm-client | sync-demo

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <cmath>

// ─── vad: virtual address descriptor walk ─────────────────────────────────────

static void cmd_vad() {
    printf("=== Virtual Address Space ===\n");
    printf("%-18s  %-10s  %-12s  %-10s  %s\n",
           "Base","Size","State","Protect","Flags");
    printf("%s\n", std::string(70,'-').c_str());

    uint8_t* addr = nullptr;
    MEMORY_BASIC_INFORMATION mbi{};
    uint64_t total_commit = 0, total_free = 0, total_reserve = 0;
    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        const char* state = mbi.State==MEM_COMMIT?"COMMIT":mbi.State==MEM_RESERVE?"RESERVE":"FREE";
        bool mz = false;
        if (mbi.State == MEM_COMMIT && mbi.RegionSize >= 2) {
            uint8_t* p = (uint8_t*)mbi.BaseAddress;
            __try { mz = (p[0]=='M' && p[1]=='Z'); } __except(1) {}
        }
        if (mbi.State != MEM_FREE || mbi.RegionSize < 0x100000) {
            printf("0x%-16p  0x%-8X  %-12s  0x%-8X  %s\n",
                   mbi.BaseAddress, (DWORD)mbi.RegionSize, state, mbi.Protect,
                   mz ? "[MZ]" : "");
        }
        if (mbi.State==MEM_COMMIT)  total_commit  += mbi.RegionSize;
        if (mbi.State==MEM_FREE)    total_free    += mbi.RegionSize;
        if (mbi.State==MEM_RESERVE) total_reserve += mbi.RegionSize;
        addr = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
        if (!mbi.RegionSize) break;
    }
    printf("\n  Committed: %.2f MB  Reserved: %.2f MB  Free: %.2f GB\n",
           total_commit/1048576.0, total_reserve/1048576.0, total_free/1073741824.0);
}

// ─── threads: list threads + priorities ───────────────────────────────────────

static void cmd_threads() {
    DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te{ sizeof(te) };
    printf("=== Threads for PID %lu ===\n", pid);
    printf("%-8s  %-8s  %-6s\n","TID","BasePri","Delta");
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            printf("  %-8lu  %-8d  %d\n", te.th32ThreadID, te.tpBasePri, te.tpDeltaPri);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

// ─── shm-server / shm-client ─────────────────────────────────────────────────

#define SHM_NAME  "Local\\OsExplorerShm"
#define EVT_READY "Local\\OsExplorerReady"
#define EVT_DONE  "Local\\OsExplorerDone"
#define SHM_SIZE  4096

static void cmd_shm_server() {
    printf("[*] SHM server — writing data\n");
    HANDLE hMap = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr,
                                     PAGE_READWRITE, 0, SHM_SIZE, SHM_NAME);
    if (!hMap) { fprintf(stderr,"CreateFileMapping: %lu\n",GetLastError()); return; }
    char* mem = (char*)MapViewOfFile(hMap, FILE_MAP_WRITE, 0, 0, SHM_SIZE);

    HANDLE hReady = CreateEventA(nullptr, FALSE, FALSE, EVT_READY);
    HANDLE hDone  = CreateEventA(nullptr, FALSE, FALSE, EVT_DONE);

    snprintf(mem, SHM_SIZE, "Hello from server at tick=%lu", GetTickCount());
    printf("[+] Wrote: %s\n", mem);
    SetEvent(hReady);

    printf("[*] Waiting for client to acknowledge...\n");
    WaitForSingleObject(hDone, 10000);
    printf("[+] Done\n");

    UnmapViewOfFile(mem); CloseHandle(hMap); CloseHandle(hReady); CloseHandle(hDone);
}

static void cmd_shm_client() {
    printf("[*] SHM client — waiting for data\n");
    HANDLE hReady = OpenEventA(SYNCHRONIZE, FALSE, EVT_READY);
    if (!hReady) { fprintf(stderr,"OpenEvent(READY): %lu\n",GetLastError()); return; }
    WaitForSingleObject(hReady, 10000);

    HANDLE hMap = OpenFileMappingA(FILE_MAP_READ, FALSE, SHM_NAME);
    if (!hMap) { fprintf(stderr,"OpenFileMapping: %lu\n",GetLastError()); return; }
    const char* mem = (const char*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, SHM_SIZE);
    printf("[+] Received: %s\n", mem);

    HANDLE hDone = OpenEventA(EVENT_MODIFY_STATE, FALSE, EVT_DONE);
    if (hDone) { SetEvent(hDone); CloseHandle(hDone); }

    UnmapViewOfFile(mem); CloseHandle(hMap); CloseHandle(hReady);
}

// ─── sync-demo: mutex + event + critical section ─────────────────────────────

static void cmd_sync_demo() {
    printf("=== Synchronization Demo ===\n");
    // Critical section: fast intra-process lock
    CRITICAL_SECTION cs;
    InitializeCriticalSection(&cs);
    int shared = 0;
    auto worker = [&](int id) {
        for (int i = 0; i < 100000; ++i) {
            EnterCriticalSection(&cs);
            ++shared;
            LeaveCriticalSection(&cs);
        }
    };
    std::thread t1(worker, 1), t2(worker, 2);
    t1.join(); t2.join();
    DeleteCriticalSection(&cs);
    printf("  CriticalSection test: shared=%d (expected 200000) %s\n",
           shared, shared==200000?"[OK]":"[RACE!]");

    // Named mutex (single-instance check)
    HANDLE hMx = CreateMutexA(nullptr, FALSE, "Local\\OsExplorerMutex");
    DWORD err = GetLastError();
    if (err == ERROR_ALREADY_EXISTS) printf("  Mutex: already exists (single-instance enforced)\n");
    else printf("  Mutex created (first instance)\n");
    CloseHandle(hMx);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage:\n"
               "  os_explorer.exe vad\n"
               "  os_explorer.exe threads\n"
               "  os_explorer.exe shm-server   (run first)\n"
               "  os_explorer.exe shm-client   (run second)\n"
               "  os_explorer.exe sync-demo\n");
        return 1;
    }
    std::string cmd(argv[1]);
    if      (cmd == "vad")        cmd_vad();
    else if (cmd == "threads")    cmd_threads();
    else if (cmd == "shm-server") cmd_shm_server();
    else if (cmd == "shm-client") cmd_shm_client();
    else if (cmd == "sync-demo")  cmd_sync_demo();
    else { fprintf(stderr,"Unknown command\n"); return 1; }
    return 0;
}
