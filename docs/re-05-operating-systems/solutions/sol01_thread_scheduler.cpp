// sol01_thread_scheduler.cpp — solution
// Compile: g++ -std=c++17 -o sol01.exe sol01_thread_scheduler.cpp
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <vector>
#include <atomic>
#include <thread>
#include <chrono>

struct WorkerCtx { int priority; uint64_t count; };

static DWORD WINAPI worker(LPVOID arg) {
    auto* ctx = (WorkerCtx*)arg;
    SetThreadPriority(GetCurrentThread(), ctx->priority);
    auto end = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (std::chrono::steady_clock::now() < end) ++ctx->count;
    return 0;
}

int main() {
    const struct { int prio; const char* name; } cfg[] = {
        {THREAD_PRIORITY_BELOW_NORMAL,  "BELOW_NORMAL"},
        {THREAD_PRIORITY_NORMAL,        "NORMAL"},
        {THREAD_PRIORITY_ABOVE_NORMAL,  "ABOVE_NORMAL"},
        {THREAD_PRIORITY_HIGHEST,       "HIGHEST"},
    };
    const int N = 4;
    WorkerCtx ctxs[N]{};
    HANDLE handles[N]{};
    for (int i = 0; i < N; ++i) {
        ctxs[i].priority = cfg[i].prio;
        handles[i] = CreateThread(nullptr, 0, worker, &ctxs[i], 0, nullptr);
    }
    WaitForMultipleObjects(N, handles, TRUE, INFINITE);
    for (int i = 0; i < N; ++i) CloseHandle(handles[i]);

    printf("Priority scheduling results (2-second spin):\n");
    for (int i = 0; i < N; ++i)
        printf("  %-20s  iters=%llu\n", cfg[i].name, (unsigned long long)ctxs[i].count);
    return 0;
}
