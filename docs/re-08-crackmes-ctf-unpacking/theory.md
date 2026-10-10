# RE-08: Crackmes, CTF, and Unpacking

## What is a Crackme?

A deliberately obfuscated binary whose goal is to find a valid serial, password,
or keygen. Crackmes teach: anti-debug bypass, algorithm reversing, and keygen writing.
Source: crackmes.one, VirusTotal Intelligence (for live malware samples).

---

## CTF Reverse Engineering

Common challenge types:

| Type | Technique |
|------|-----------|
| License check | Find comparison; patch JNZ→JMP or compute valid input |
| Custom encoding | Identify encode/decode loop; implement inverse |
| VM/bytecode | Reverse the interpreter; write a disassembler for the VM ISA |
| Anti-debug | Bypass IsDebuggerPresent, timing checks, TLS callbacks |
| Unpacking | Find OEP; dump; fix IAT |
| Flag hash | Brute-force (short flags) or reverse the hash function |

---

## Packer Identification

Indicators:
- Very few imports (often only LoadLibrary + GetProcAddress)
- High-entropy sections (entropy > 7.0)
- Empty first section (.text has SizeOfRawData=0, large VirtualSize)
- Entry point in last section (instead of .text)
- Non-standard section names: UPX0, UPX1, .nsp0, .vmp0, .themida

Tools: Detect-It-Easy (DIE), ExeinfoPE, PEiD.

---

## Manual Unpacking Workflow (UPX as example)

```
1. Load in x64dbg
2. Set BP on GetProcAddress (unpacker uses it to rebuild IAT)
3. Run → hit BP
4. Single-step until you see JMP to original code (PUSHAD → ... → POPAD → JMP)
   This is the OEP epilogue pattern
5. Note the JMP destination = OEP
6. Use Scylla (plugin) → IAT Autosearch → Get Imports → Fix Dump
7. Save fixed PE
```

---

## Anti-Debug Techniques (and Bypasses)

| Technique | API / Method | Bypass |
|-----------|-------------|--------|
| IsDebuggerPresent | PEB.BeingDebugged | Patch PEB byte to 0 |
| CheckRemoteDebuggerPresent | NtQueryInformationProcess(7) | Patch return value |
| Timing (RDTSC) | delta > threshold | NOP the check |
| Heap flags | NtGlobalFlag 0x70 | Patch NtGlobalFlag |
| TLS callback anti-debug | Runs before main | BP at TLS callback address |
| Hardware BPs | CONTEXT.Dr0–Dr7 != 0 | Clear DR regs via SetThreadContext |
| NtQueryInformationProcess | ProcessDebugPort ≠ 0 | Hook ntdll stub |
| OutputDebugString | Exception if not debugged | NOP the call |
| INT3 scan | Scan own memory for 0xCC | NOP scanner or patch BPs |

---

## Writing a Keygen

After reversing the serial check:
1. Identify the transformation: serial = f(name)
2. Re-implement f in C/Python
3. Fuzz edge cases (empty, null bytes, max length)

---

## Exercises

1. `ex01_crackme_target.cpp`  — A compiled crackme: find the valid serial (XOR-check + sum-check)
2. `ex02_anti_debug_gauntlet.cpp` — A program that exits if a debugger is detected; bypass all checks
3. `ex03_mini_packer.cpp`     — A packer stub: XOR-encodes a payload at build time, decodes at runtime; unpack it

## Key References

- crackmes.one
- x64dbg plugin: ScyllaHide
- *The Art of Unpacking* — Mark Vincent Yason (PDF)
- *Reversing: Secrets of Reverse Engineering* — Eldad Eilam
