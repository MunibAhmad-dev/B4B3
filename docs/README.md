# RAT Engineering — Complete Learning Roadmap

This curriculum takes you from zero C++ knowledge to being able to design, build,
and explain every component of a Windows RAT (Remote Access Tool) from scratch —
without relying on AI or copying existing code.

---

## Who this is for

Someone who:
- Knows basic programming concepts but not C++ deeply
- Wants to do real red-team / security research work
- Wants to understand Windows at the system level
- Wants to stop copying and start reasoning

---

## How to use this

1. Read the `theory.md` in each module top-to-bottom.
2. Open the exercise `.cpp` files and attempt them **without** reading solutions.
3. Compile and run your attempt. Fix errors yourself first.
4. Only then compare with `solutions/`.
5. Understand every line of the solution — if you don't, re-read the theory.

Compile command for all exercises (MinGW):
```
g++ -std=c++17 -Wall -o out.exe exercise.cpp
```
For Windows API exercises add:
```
g++ -std=c++17 -Wall -o out.exe exercise.cpp -luser32 -ladvapi32 -lkernel32
```

---

## Roadmap

### Part 1 — Core RAT Engineering (Modules 01–09)
```
Module 01  C++ Basics              ~1 week
Module 02  C++ Intermediate        ~1 week
Module 03  C++ Advanced            ~1 week
Module 04  Windows Internals       ~2 weeks
Module 05  Processes & Threads     ~1 week
Module 06  Memory Management       ~1 week
Module 07  Networking (Winsock)    ~1 week
Module 08  AV Evasion Theory       ~1 week
Module 09  RAT Architecture        ~2 weeks
```

### Part 2 — Broader Context (Modules 10–15)
```
Module 10  Advanced Persistence    ~1 week
Module 11  Credential Access       ~1 week
Module 12  Defensive Tools         ~2 weeks
Module 13  Exploit Concepts        ~2 weeks
Module 14  Network Tools           ~1 week
Module 15  Ransomware Simulation   ~1 week
```

### Part 3 — Advanced Security Engineering (Modules 16–30)
```
Module 16  Injection Variants      ~1 week
Module 17  EDR Bypass              ~2 weeks
Module 18  Kernel Driver           ~3 weeks
Module 19  ETW Consumer            ~1 week
Module 20  Custom C2 Framework     ~2 weeks
Module 21  Coverage Fuzzer         ~2 weeks
Module 22  Binary Analysis         ~1 week
Module 23  Memory Forensics        ~1 week
Module 24  Lateral Movement        ~2 weeks
Module 25  EDR Sensor (Kernel)     ~2 weeks
Module 26  YARA Scanner            ~1 week
Module 27  Windows Service         ~1 week
Module 28  TLS MITM Proxy          ~1 week
Module 29  Shellcode Development   ~2 weeks
Module 30  Patch Differ            ~1 week
```

Total: ~45 weeks of consistent daily study (2–3 hours/day).

After completing both parts, see [company-scenarios/](company-scenarios/README.md)
for 10 real-world briefs to test your skills against.

---

## Module Index

### Part 1 — C++ & RAT Core

| # | Module | What you will be able to do after |
|---|--------|----------------------------------|
| 01 | [C++ Basics](01-cpp-basics/theory.md) | Write, compile, debug C++ programs |
| 02 | [C++ Intermediate](02-cpp-intermediate/theory.md) | Use OOP, STL, file I/O, multi-threading |
| 03 | [C++ Advanced](03-cpp-advanced/theory.md) | Templates, move semantics, memory layout |
| 04 | [Windows Internals](04-windows-internals/theory.md) | Win32 API, handles, registry, PE format |
| 05 | [Processes & Threads](05-processes-threads/theory.md) | Spawn/kill processes, thread sync, injection |
| 06 | [Memory Management](06-memory/theory.md) | VirtualAlloc, heap, memory scanning |
| 07 | [Networking](07-networking/theory.md) | Winsock TCP, WinINet HTTPS, custom C2 protocol |
| 08 | [AV Evasion](08-av-evasion/theory.md) | How AV works, string obfuscation, sandbox detection |
| 09 | [RAT Architecture](09-rat-architecture/theory.md) | Design and build a complete RAT from scratch |

### Part 2 — Broader Security Engineering

| # | Module | What you will be able to do after |
|---|--------|----------------------------------|
| 10 | [Advanced Persistence](10-persistence-advanced/theory.md) | COM hijack, DLL hijack, WMI subscriptions, IFEO |
| 11 | [Credential Access](11-credential-access/theory.md) | DPAPI, Chrome passwords, WiFi PSK, Credential Manager |
| 12 | [Defensive Tools](12-defensive-tools/theory.md) | FIM, process monitor, network monitor, memory scanner |
| 13 | [Exploit Concepts](13-exploit-concepts/theory.md) | Buffer overflow, ROP, format strings, fuzzing |
| 14 | [Network Tools](14-network-tools/theory.md) | Port scanner, DNS resolver, HTTP server, packet capture |
| 15 | [Ransomware Simulation](15-ransomware-sim/theory.md) | Safe AES file encryption, enumeration, recovery |

### Part 3 — Advanced Security Engineering

| # | Module | What you will be able to do after |
|---|--------|----------------------------------|
| 16 | [Injection Variants](16-injection-variants/theory.md) | APC injection, Early Bird, process doppelgänging |
| 17 | [EDR Bypass](17-edr-bypass/theory.md) | Detect/remove API hooks, direct syscalls, NTDLL unhooking |
| 18 | [Kernel Driver](18-kernel-driver/theory.md) | Write WDM drivers, IOCTL channels, cross-process memory read |
| 19 | [ETW Consumer](19-etw-consumer/theory.md) | Consume ETW events, build a process-create monitor |
| 20 | [Custom C2 Framework](20-custom-c2/theory.md) | Build a full C2 server + agent with task engine |
| 21 | [Coverage Fuzzer](21-coverage-fuzzer/theory.md) | WinAFL harness, breakpoint coverage, crash triage |
| 22 | [Binary Analysis](22-binary-analysis/theory.md) | String extraction, XOR brute-force, Zydis disassembly |
| 23 | [Memory Forensics](23-memory-forensics/theory.md) | Scan live process memory, dump, detect hidden processes |
| 24 | [Lateral Movement](24-lateral-movement/theory.md) | Named pipe impersonation, remote service install, token enum |
| 25 | [EDR Sensor (Kernel)](25-edr-sensor/theory.md) | Process/image callbacks, minifilter, ETW consumer |
| 26 | [YARA Scanner](26-yara-scanner/theory.md) | Write YARA rules, scan files and live process memory |
| 27 | [Windows Service](27-windows-service/theory.md) | Write install/stop/IPC services, detect rogue persistence |
| 28 | [TLS MITM Proxy](28-tls-mitm-proxy/theory.md) | Generate CA, intercept HTTPS, bypass cert pinning |
| 29 | [Shellcode Development](29-shellcode-dev/theory.md) | PEB walk, export resolution, BOF, XOR encoder stubs |
| 30 | [Patch Differ](30-patch-differ/theory.md) | Byte diff, PE section diff, function hash matching |

### Part 4 — Network Auditing & WiFi Security

| # | Module | What you will be able to do after |
|---|--------|----------------------------------|
| 37 | [WiFi Network Audit & ARP Analysis](37-wifi-network-audit/theory.md) | Discover all devices, run ARP MITM, intercept traffic, detect poisoning |

### Real-World Briefs

| | | |
|-|-|-|
| [Company Scenarios](company-scenarios/README.md) | 10 real briefs matching what companies actually request | After Part 3 |

---

## What you build along the way

**Part 1 — RAT Core:**
- A process lister (Module 05)
- A registry persistence tool (Module 04)
- A TCP C2 client (Module 07)
- A screenshot capture utility (Module 09)
- A keylogger thread (Module 05 + 09)
- A full sandbox-aware loader (Module 08)
- A working RAT stub with C2 (Module 09)

**Part 2 — Broader Context:**
- A persistence scanner (Module 10 + 12)
- A credential harvester (Module 11)
- A file integrity monitor (Module 12)
- A mutation fuzzer (Module 13)
- A network inventory tool (Module 14)
- A ransomware simulator + recovery tool (Module 15)

**Part 3 — Advanced Security Engineering:**
- An APC / Early-Bird injector (Module 16)
- An NTDLL unhooker + direct syscall stub (Module 17)
- A kernel driver with IOCTL + cross-process memory read (Module 18)
- A live ETW process monitor (Module 19)
- A full Node.js C2 server + WinINet agent with task engine (Module 20)
- A WinAFL harness + coverage tracker + crash triage tool (Module 21)
- A binary string extractor, disassembler, and API scorer (Module 22)
- A live memory scanner, string hunter, and hidden PID detector (Module 23)
- Named-pipe impersonation server + remote service installer (Module 24)
- A kernel EDR sensor with process/image callbacks + minifilter (Module 25)
- A YARA rule set + file and process scanner (Module 26)
- A Windows service with named-pipe IPC and persistence detector (Module 27)
- A TLS MITM proxy with CA generator and cert pinning bypass (Module 28)
- PEB-walk shellcode + XOR encoder + BOF skeleton (Module 29)
- A patch differ: byte → section → function → side-by-side disasm (Module 30)

---

## Prerequisites

- A Windows machine (10 or 11)
- MinGW-w64 installed (`g++` available in PATH)
- A text editor (VS Code recommended)
- No prior C++ knowledge required
