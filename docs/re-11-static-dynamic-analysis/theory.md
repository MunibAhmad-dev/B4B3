# RE-11: Static and Dynamic Analysis

## Static Analysis

Analysis without executing the binary. Safe for unknown/hostile samples.

### Level 1 — File Profiling
- File type (magic bytes), size, entropy (>7.0 → packed/encrypted)
- PE metadata: compilation timestamp, linker, import count, section count
- Hash: MD5/SHA256 for VirusTotal lookup

### Level 2 — String Extraction
- ASCII: printable runs ≥ 6 chars
- Wide (UTF-16): every other byte is 0x00 in many strings
- Interesting: URLs, IPs, registry keys, mutex names, error messages
- Stack strings: not found by strings tool — need disassembler

### Level 3 — Import Analysis
- Import table → DLL + function → infer capabilities:

| DLL | Functions | Capability |
|-----|-----------|------------|
| WinINet/WinHTTP | InternetOpen, HttpSendRequest | Network C2 |
| KERNEL32 | VirtualAllocEx, WriteProcessMemory | Injection |
| ADVAPI32 | RegSetValueEx, CryptEncrypt | Persistence, Encryption |
| USER32 | GetAsyncKeyState, SetWindowsHookEx | Keylogging |
| NTDLL | NtUnmapViewOfSection | Process hollowing |

### Level 4 — Disassembly
- Ghidra auto-analysis: CFG, type inference, decompiler
- IDA Pro: superior cross-references, FLIRT signatures for library code
- Focus areas: entry point, DllMain, WinMain, TLS callbacks
- Look for: obfuscated calls (call [rax+N*8]), dynamic API resolution (PEB walk)

---

## Dynamic Analysis

Execute in an isolated environment (VM, sandbox, Docker).

### Behavioral Monitoring

| Category | Tool | What to record |
|----------|------|----------------|
| File I/O | Procmon | Created/modified/deleted paths |
| Registry | Procmon/RegShot before+after | Added keys, run persistence |
| Network | Wireshark + Fakenet-NG | DNS queries, C2 URLs, JA3/JA3S |
| Process | Procmon / Sysmon Event 1 | Spawned children, injected processes |
| Memory | x64dbg + Scylla | Unpacked payload extraction |

### Debugger Workflow
1. Set BP on entry point; verify environment
2. Find decryption/decompression loop (entropy of buffer before/after)
3. Set BP on VirtualAlloc — dump returned memory after write for second stage
4. Set BP on CreateProcess/WinExec/ShellExecute
5. For network: set BP on WSAConnect/InternetOpen to capture C2 config

### Dynamic API Resolution Tracing
- Many malware samples use PEB walk + hash to avoid import table strings
- x64dbg: set BP on every `call rax` / `call [rsp+N]`; check RAX = target API
- ScyllaHide: auto-bypass anti-debug tricks

---

## Diff Analysis (Binary Diffing)

Compare patched/updated binary to previous version:
- BinDiff (IDA plugin): function-level diff by CFG similarity
- Diaphora: open-source BinDiff alternative for Ghidra/IDA
- Patch analysis: find the 1-3 functions that changed → new vuln location
- Procedure:
  1. Export function list + CFG from old binary
  2. Export from new binary
  3. Diff → matched functions (>80% similar) + unmatched (new/removed)

---

## Timeline Reconstruction

Build attacker timeline from forensic artifacts:
1. Windows Event Log (EVTX): 4688 (process create), 4624/4625 (logon)
2. Prefetch: `C:\Windows\Prefetch\*.pf` — last-run timestamps, file references
3. Registry: `HKCU\...\UserAssist` (base64-obfuscated execution history)
4. NTFS MFT: `$MFT` — file create/modify/access times for every file
5. Shellbags: recently-browsed folder timestamps
6. LNK files in Recent: target path + access time

---

## Exercises

1. `ex01_static_pipeline.cpp` — Automated static analysis pipeline: hash, entropy, strings, imports
2. `ex02_dynamic_hooks.cpp`   — IAT hook to trace CreateFile, RegSetValue, WSAConnect at runtime
3. `ex03_binary_diff.cpp`     — Compare two PE binaries; report changed functions by export hash

## Key References

- FLARE VM: automated malware analysis environment
- Cuckoo Sandbox / ANY.RUN: cloud dynamic analysis
- VirusTotal: hash, string, behavior lookups
- *The Art of Memory Forensics* — Ligh et al.
