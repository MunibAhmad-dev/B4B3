// debug_helper.cpp — debugger helper CLI (debug API lab)
// Compile: g++ -std=c++17 -o debug_helper.exe debug_helper.cpp
// Usage: debug_helper.exe attach <pid> | find <pid> <hex> | patch <pid> <addr_hex> <bytes_hex> | regs <pid>

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdio.h>
#include <string>
#include <vector>

static std::vector<uint8_t> hex_decode(const char* s) {
    std::vector<uint8_t> out;
    size_t n = strlen(s);
    for (size_t i=0; i+1<n; i+=2) { char b[3]={s[i],s[i+1],0}; out.push_back((uint8_t)strtoul(b,nullptr,16)); }
    return out;
}

// ─── attach: debug-attach, print first 5 exceptions, detach ──────────────────

static void cmd_attach(DWORD pid) {
    if (!DebugActiveProcess(pid)) { fprintf(stderr,"DebugActiveProcess: %lu\n",GetLastError()); return; }
    DebugSetProcessKillOnExit(FALSE);
    printf("[*] Attached to PID %lu\n", pid);
    int hits=0;
    DEBUG_EVENT de{};
    while (hits < 5 && WaitForDebugEvent(&de, 3000)) {
        DWORD st = DBG_CONTINUE;
        if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            auto& ex = de.u.Exception.ExceptionRecord;
            printf("[EX] code=0x%08lX addr=0x%p first=%d\n",
                   ex.ExceptionCode, ex.ExceptionAddress, de.u.Exception.dwFirstChance);
            if (ex.ExceptionCode != EXCEPTION_BREAKPOINT) st = DBG_EXCEPTION_NOT_HANDLED;
            ++hits;
        }
        if (de.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT)
            CloseHandle(de.u.CreateProcessInfo.hFile);
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st);
    }
    DebugActiveProcessStop(pid);
    printf("[*] Detached\n");
}

// ─── find: search memory for a byte pattern ──────────────────────────────────

static void cmd_find(DWORD pid, const char* hex) {
    auto pattern = hex_decode(hex);
    if (pattern.empty()) { fprintf(stderr,"Invalid hex pattern\n"); return; }
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, pid);
    if (!hProc) { fprintf(stderr,"OpenProcess: %lu\n",GetLastError()); return; }

    uint8_t* addr = nullptr;
    MEMORY_BASIC_INFORMATION mbi{};
    int found = 0;
    while (VirtualQueryEx(hProc,addr,&mbi,sizeof(mbi))) {
        if (mbi.State==MEM_COMMIT && !(mbi.Protect&PAGE_GUARD)) {
            std::vector<uint8_t> buf(mbi.RegionSize);
            SIZE_T rd=0;
            if (ReadProcessMemory(hProc,mbi.BaseAddress,buf.data(),mbi.RegionSize,&rd)&&rd>0) {
                for (size_t i=0; i+pattern.size()<=rd; ++i) {
                    if (memcmp(buf.data()+i,pattern.data(),pattern.size())==0) {
                        printf("  Found at 0x%p\n",(uint8_t*)mbi.BaseAddress+i);
                        ++found;
                    }
                }
            }
        }
        addr=(uint8_t*)mbi.BaseAddress+mbi.RegionSize;
        if(!mbi.RegionSize) break;
    }
    CloseHandle(hProc);
    printf("Total: %d match(es)\n",found);
}

// ─── patch: write bytes to remote process ────────────────────────────────────

static void cmd_patch(DWORD pid, const char* addr_s, const char* bytes_s) {
    uintptr_t addr = (uintptr_t)strtoull(addr_s,nullptr,16);
    auto bytes = hex_decode(bytes_s);
    if (bytes.empty()) { fprintf(stderr,"Invalid bytes hex\n"); return; }

    HANDLE hProc = OpenProcess(PROCESS_VM_WRITE|PROCESS_VM_OPERATION, FALSE, pid);
    if (!hProc) { fprintf(stderr,"OpenProcess: %lu\n",GetLastError()); return; }

    DWORD old=0;
    VirtualProtectEx(hProc,(LPVOID)addr,bytes.size(),PAGE_EXECUTE_READWRITE,&old);
    SIZE_T written=0;
    if (WriteProcessMemory(hProc,(LPVOID)addr,bytes.data(),bytes.size(),&written))
        printf("[+] Patched %zu bytes at 0x%llX\n",written,(unsigned long long)addr);
    else fprintf(stderr,"WriteProcessMemory: %lu\n",GetLastError());
    VirtualProtectEx(hProc,(LPVOID)addr,bytes.size(),old,&old);
    CloseHandle(hProc);
}

// ─── regs: dump thread registers ─────────────────────────────────────────────

static void cmd_regs(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) { fprintf(stderr,"OpenProcess: %lu\n",GetLastError()); return; }

    if (!DebugActiveProcess(pid)) { fprintf(stderr,"DebugActiveProcess: %lu\n",GetLastError()); CloseHandle(hProc); return; }
    DebugSetProcessKillOnExit(FALSE);

    DEBUG_EVENT de{};
    HANDLE hThread = nullptr;
    bool got = false;
    while (!got && WaitForDebugEvent(&de,3000)) {
        if (de.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT) {
            hThread = de.u.CreateProcessInfo.hThread;
            CloseHandle(de.u.CreateProcessInfo.hFile);
        }
        if (de.dwDebugEventCode==EXCEPTION_DEBUG_EVENT && hThread) {
            CONTEXT ctx{}; ctx.ContextFlags=CONTEXT_ALL;
            SuspendThread(hThread);
            GetThreadContext(hThread,&ctx);
#ifdef _WIN64
            printf("RIP=0x%016llX  RSP=0x%016llX  RBP=0x%016llX\n",(unsigned long long)ctx.Rip,(unsigned long long)ctx.Rsp,(unsigned long long)ctx.Rbp);
            printf("RAX=0x%016llX  RBX=0x%016llX  RCX=0x%016llX  RDX=0x%016llX\n",(unsigned long long)ctx.Rax,(unsigned long long)ctx.Rbx,(unsigned long long)ctx.Rcx,(unsigned long long)ctx.Rdx);
#else
            printf("EIP=0x%08lX  ESP=0x%08lX  EBP=0x%08lX\n",ctx.Eip,ctx.Esp,ctx.Ebp);
#endif
            ResumeThread(hThread);
            got = true;
        }
        ContinueDebugEvent(de.dwProcessId,de.dwThreadId,DBG_CONTINUE);
    }
    DebugActiveProcessStop(pid);
    CloseHandle(hProc);
}

int main(int argc, char* argv[]) {
    if (argc<2) { printf("Usage: debug_helper.exe attach <pid> | find <pid> <hex> | patch <pid> <addr> <bytes> | regs <pid>\n"); return 1; }
    std::string cmd(argv[1]);
    if      (cmd=="attach"&&argc>=3) cmd_attach((DWORD)strtoul(argv[2],nullptr,10));
    else if (cmd=="find"&&argc>=4)   cmd_find((DWORD)strtoul(argv[2],nullptr,10),argv[3]);
    else if (cmd=="patch"&&argc>=5)  cmd_patch((DWORD)strtoul(argv[2],nullptr,10),argv[3],argv[4]);
    else if (cmd=="regs"&&argc>=3)   cmd_regs((DWORD)strtoul(argv[2],nullptr,10));
    else { fprintf(stderr,"Unknown command\n"); return 1; }
    return 0;
}
