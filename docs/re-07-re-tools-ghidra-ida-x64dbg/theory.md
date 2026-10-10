# RE-07: RE Tools — Ghidra, IDA Pro, x64dbg

## Choosing a Tool

| Tool | Cost | Best for |
|------|------|----------|
| Ghidra (NSA) | Free | Full static analysis, scripting (Java/Python), team analysis |
| IDA Pro | Paid | Industry standard; best auto-analysis; IDApython ecosystem |
| IDA Free | Free | Limited; up to 64-bit; no decompiler |
| Binary Ninja | Paid | Clean API; good for automation |
| x64dbg | Free | Live debugging; patching; trace recording |
| WinDbg (Preview) | Free | Kernel debugging; TTD (Time Travel Debugging) |

---

## Ghidra Workflow

1. `File → Import File` → auto-analysis
2. `Listing` view = disassembly; `Decompiler` view = pseudo-C
3. Rename functions/variables: press `L` (label), `N` (name)
4. Cross-references: right-click → "References To"
5. Script Manager: run Java/Python scripts against the program database
6. Export to C headers for re-use in reversing tooling

**Tip**: Ghidra auto-analysis sometimes mis-identifies code. Use
`Edit → Code Unit / Define Function` to fix.

---

## IDA Pro Workflow

1. `F5` in function → Hex-Rays decompiler (paid)
2. `N` → rename; `Y` → retype; `:` → comment
3. `Alt+T` → text search; `Alt+B` → byte search
4. FLIRT signatures: `File → Load File → FLIRT Signature` to identify library code
5. IDAPython: `File → Script file` or `Alt+F7`
6. Struct editor: `View → Open subviews → Local Types` → import from .h

---

## x64dbg Workflow

1. `F9` = run; `F8` = step over; `F7` = step into; `F2` = toggle breakpoint
2. Memory map tab: shows regions + protection
3. Command bar: `bp <addr>` / `bph <addr>` (hardware BP)
4. Patch: right-click byte in dump → `Modify bytes`
5. Plugins: ScyllaHide (anti-anti-debug), xAnalyzer (auto-comments), OllyDumpEx (dump)
6. Trace recording: `Debug → Run trace` → logs every executed instruction

**Common BP recipes:**

```
bp CreateFileA     ; catch file opens
bp VirtualAllocEx  ; catch injection allocation
bph <addr>,r,4     ; hardware breakpoint on read of 4 bytes at addr
```

---

## Pattern: Finding Unpacking Stubs

1. `bp VirtualAlloc` → note returned address
2. `bph <returned_addr>,x` → hardware execute BP on the new buffer
3. Hit: you're at OEP of unpacked code
4. Dump with Scylla → fix IAT → save PE

---

## Exercises

1. `ex01_debug_attach.cpp`    — Attach to a target, set a software BP at an address, single-step 10 instructions, print register states
2. `ex02_find_pattern.cpp`    — Search process memory for a hex pattern (like shellcode prologue) and report offsets
3. `ex03_patch_bytes.cpp`     — Write INT3 breakpoint at a given address; restore on keypress

## Key References

- Ghidra: ghidra.re/ghidra_docs/api/
- *The IDA Pro Book* — Eagle
- x64dbg: help.x64dbg.com
- *Practical Malware Analysis* — Sikorski & Honig
