# RE-05: Operating Systems Concepts for Security

## Processes, Threads, and Scheduling

**Process** = address space + one or more threads + handle table + security token.
**Thread**  = execution unit; has own stack (default 1MB), TEB, registers.

Windows scheduler: preemptive, priority-based (0–31).
- Real-time (16–31): PROCESS_PRIORITY_CLASS_REALTIME — can starve system threads
- Dynamic (1–15): boosted/decayed by I/O completion, foreground boost

Sleep(0) yields the current quantum; SwitchToThread() yields to a same-priority thread.

---

## Virtual Memory

Each 64-bit process gets 128TB user-space VA. Pages are 4 KB (or 2 MB large pages).

Page states: **Free** → **Reserved** → **Committed** → **Mapped**

Key APIs: `VirtualAlloc`, `VirtualProtect`, `VirtualQuery`, `VirtualFree`

Page fault handler: checks VAD (Virtual Address Descriptor) tree; maps physical page.
COW (Copy-on-Write): DLL sections are shared until a page is written.

**Guard pages**: access triggers STATUS_GUARD_PAGE_VIOLATION — used for stack growth
and heap canaries. Malware uses guard pages to detect memory scanning.

---

## Synchronization Primitives

| Primitive | Kernel? | Use case |
|-----------|---------|----------|
| CRITICAL_SECTION | No (user-mode spin) | Fast intra-process lock |
| Mutex (named) | Yes | Cross-process mutual exclusion; malware uses for single-instance check |
| Semaphore | Yes | Counting lock |
| Event | Yes | Signal between threads/processes |
| WaitOnAddress | No (NTDLL) | Futex-like; Windows 8+ |

Malware pattern: `CreateMutex("Global\\<guid>")` → if ERROR_ALREADY_EXISTS, exit.

---

## IPC Mechanisms

| Mechanism | Speed | Notes |
|-----------|-------|-------|
| Named Pipe | Medium | Full-duplex, message-mode; used by Cobalt Strike |
| Shared Memory | Fast | CreateFileMapping + MapViewOfFile |
| Mailslot | Slow | Broadcast one-way |
| RPC | Variable | Marshalled; large attack surface |
| COM | Variable | Object model over RPC; exploited by UAC bypass |

---

## System Calls

User → `ntdll.dll` stub → `syscall` instruction → kernel `SSDT` index → KiServiceTable.
EDRs hook ntdll stubs (at user-mode) or SSDT (kernel) to intercept calls.

`NtAllocateVirtualMemory` = underlying call behind `VirtualAlloc`.
`NtCreateThreadEx` = `CreateRemoteThread` → malware uses direct syscall to bypass hooks.

---

## Exercises

1. `ex01_thread_scheduler.cpp` — Create 4 threads at different priorities; measure runtime distribution with RDTSC
2. `ex02_vad_walk.cpp`        — Walk own VAD with VirtualQuery; print all committed regions, flags, and MZ headers
3. `ex03_ipc_shm.cpp`         — Shared-memory producer/consumer using CreateFileMapping + Event sync

## Key References

- *Windows Internals 7th ed.* Part 1, Chapters 3-4
- MSDN: VirtualAlloc, CreateThread, CreateFileMapping
- *The Art of Memory Forensics* — Ligh et al.
