# RE-03: Windows Internals Deep

## Why This Matters for Reversers

Most Windows malware exploits undocumented kernel structures. To reverse it you need
to know what EPROCESS, PEB, TEB, and the object manager actually look like in memory —
not just the documented API layer.

---

## The NT Object Model

Every kernel resource (process, thread, file, registry key, event, mutex) is an
*NT Object* with a common header (OBJECT_HEADER → TypeIndex, HandleCount, PointerCount)
followed by the type-specific body.

```
OBJECT_HEADER
  ├── TypeIndex       → points to OBJECT_TYPE
  ├── HandleCount
  ├── PointerCount
  └── Body            → EPROCESS / ETHREAD / FILE_OBJECT / …
```

Object Manager namespace: `\Device`, `\KnownDlls`, `\BaseNamedObjects`, `\Sessions`.
Tools: WinObj (Sysinternals), `!object \` in WinDbg.

---

## EPROCESS (simplified, Windows 10/11 x64)

Key fields (offsets shift per build — always confirm in WinDbg/symbol file):

| Offset (≈) | Field                | Notes                              |
|-----------|----------------------|------------------------------------|
| +0x000    | Pcb (KPROCESS)       | Kernel process block               |
| +0x2E0    | UniqueProcessId      | PID                                |
| +0x2E8    | ActiveProcessLinks   | LIST_ENTRY — all processes linked  |
| +0x3C8    | Token                | EX_FAST_REF to TOKEN object        |
| +0x450    | ImageFileName[15]    | Short exe name (char)              |
| +0x550    | Peb                  | Pointer to PEB (usermode)          |

DKOM (Direct Kernel Object Manipulation): unlink from ActiveProcessLinks to hide process.
Detection: cross-reference with PspCidTable (handle table), thread back-pointers.

---

## PEB / TEB (usermode, x64)

**TEB** at `GS:[0]`:
- `+0x000` NtTib.StackBase / StackLimit
- `+0x030` ProcessEnvironmentBlock → PEB pointer
- `+0x100` ThreadLocalStoragePointer

**PEB** at `GS:[0x60]` (x64) / `FS:[0x30]` (x86):
- `+0x002` BeingDebugged (checked by IsDebuggerPresent)
- `+0x010` ImageBaseAddress
- `+0x018` Ldr → PEB_LDR_DATA (module list)
- `+0x020` ProcessParameters (command line, env)
- `+0x068` NtGlobalFlag (heap flags; 0x70 in debugger)
- `+0x0BC` NumberOfProcessors

Anti-debug: patch `BeingDebugged` + `NtGlobalFlag` after attach.

---

## Handle Tables

Each process has a `HANDLE_TABLE` (EPROCESS.ObjectTable).
A handle is an index into this table → resolves to `OBJECT_HEADER`.

`NtQuerySystemInformation(SystemHandleInformation)` dumps all handles system-wide.
Used by tools like Process Hacker and by malware to find LSASS handle for credential access.

---

## Registry Internals

Registry hive on disk: `.hiv` format (REGF signature).
- Hive header → root cell → BIN → NK (key) / VK (value) / SK (security) / LF/LH (index)
- In-memory: `CMHIVE` → `HBASE_BLOCK` per hive
- Each open key: EKEY_BODY NT object

Malware writes persistence to Run keys; blue team audits with
`NtQueryKey` / `RegEnumKeyEx` and ETW Microsoft-Windows-Registry.

---

## Exercises

1. `ex01_eprocess_walk.cpp` — Walk EPROCESS list via `NtQuerySystemInformation(SystemProcessInformation)`
2. `ex02_peb_flags.cpp`     — Read PEB fields (BeingDebugged, NtGlobalFlag, module list) directly from memory
3. `ex03_handle_dump.cpp`   — Dump all handles for a given PID using `SystemHandleInformation`

## Key References

- *Windows Internals 7th ed.* — Russinovich, Solomon, Ionescu
- WinDbg: `dt nt!_EPROCESS`, `!peb`, `!teb`, `!handle`
- ReactOS / ntddk.h for structure definitions
