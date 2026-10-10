# Module RE-03: Computer Architecture for Security Researchers

## Why Architecture Matters

Cache timing attacks, Spectre/Meltdown, ROP chains, heap sprays — all exploit how the
hardware actually works, not how the abstraction suggests it works.
As a malware analyst, you need to know WHY an exploit works physically.

---

## 1. CPU Pipeline

Modern CPUs use a multi-stage pipeline: Fetch → Decode → Execute → Writeback.

**Out-of-Order Execution**: The CPU may execute instructions in a different order than
written, as long as the observable result is the same (from the program's perspective).
*Spectre exploits this* — the CPU speculatively executes past a branch and leaves
microarchitectural side-effects even if the branch isn't taken.

**Branch Prediction**: The CPU predicts which branch will be taken. Wrong prediction =
pipeline flush = ~15 cycle penalty. *JIT spraying* shapes memory so mispredicts land
on attacker code.

### What this means for RE
- Compiler-generated code is optimized for pipeline efficiency
- `NOP` sleds in shellcode fill the pipeline
- Instruction reordering is normal — the disasm order != execution order

---

## 2. Cache Hierarchy

| Level | Name   | Size (typical) | Latency | Shared? |
|-------|--------|----------------|---------|---------|
| L1    | Data   | 32 KB          | 4 cy    | Per core|
| L1    | Instr  | 32 KB          | 4 cy    | Per core|
| L2    | Unified| 256 KB         | 12 cy   | Per core|
| L3    | LLC    | 6–32 MB        | 40 cy   | All cores|
| RAM   | DRAM   | GBs            | 200 cy  | System  |

**Cache line**: 64 bytes — the unit of transfer between cache and RAM.
Accessing `buf[0]` and `buf[63]` = same cache line = one fetch.
Accessing `buf[0]` and `buf[64]` = two cache lines = two fetches.

### Security Implications
**Flush+Reload (cache side-channel)**:
1. `clflush` — flush a cache line from L1/L2/L3
2. Victim accesses memory (may or may not touch the flushed line)
3. Attacker measures access time — cache hit (<100 ns) or miss (>300 ns)
4. Infers whether victim accessed specific memory

**Used in**: Spectre, Meltdown, AES timing attacks, cross-VM covert channels.

---

## 3. Virtual Memory

Every process gets its own virtual address space (VAS):
- **x86**: 4 GB VAS (2 GB user, 2 GB kernel by default)
- **x64**: 128 TB user VAS (48-bit addressing), 128 TB kernel

### Page Tables (x64)
4-level paging: PML4 → PDPT → PD → PT → Physical page

```
Virtual address (48-bit):
[47:39] PML4 index (9 bits)
[38:30] PDPT index (9 bits)
[29:21] PD index   (9 bits)
[20:12] PT index   (9 bits)
[11:0]  Page offset (12 bits) = 4096 bytes per page
```

### Page Permissions (PTE flags)
- **P** (Present): page in memory
- **RW**: read-write (cleared = read-only)
- **US**: user/supervisor (cleared = kernel only)
- **XD/NX**: execute-disable (set = no-execute)
- **G**: global (TLB entry not flushed on CR3 switch)

**DEP/NX**: setting XD bit on data pages prevents shellcode execution.
**ROP chains** bypass DEP by reusing existing executable code (gadgets).

### Memory Regions in a Process
```
0x0000000000001000  Low addresses (null page protection)
...
0x00007FF600000000  Image base (typical x64 exe)
0x00007FF700000000  Image + DLLs
0x00007FFFFFFF0000  TEB/PEB/NTDLL
0xFFFF800000000000  Kernel (not accessible from user mode)
```

### ASLR (Address Space Layout Randomization)
- Base address of exe, stack, heap, DLLs randomized on each load
- Entropy: 8–16 bits on Windows (256–65536 possible positions)
- Bypass techniques: info leak, heap spray, non-ASLR modules

---

## 4. x64 Memory Segmentation (Flat Model + FS/GS)

Modern x64 uses a flat memory model — segments don't restrict memory.
**Exception**: FS and GS are used as thread-local base registers.

```
Windows x64:  GS → TEB (Thread Environment Block)
Linux x64:    FS → thread-local storage

GS:[0x00]  → TEB.ExceptionList
GS:[0x08]  → TEB.StackBase
GS:[0x10]  → TEB.StackLimit
GS:[0x18]  → TEB.SubSystemTib
GS:[0x20]  → TEB.FiberData
GS:[0x28]  → TEB.ArbitraryUserPointer
GS:[0x30]  → TEB itself (self-referential)
GS:[0x60]  → TEB.ProcessEnvironmentBlock (PEB ptr)
GS:[0x68]  → TEB.LastErrorValue
```

Shellcode and malware use `mov rax, gs:[0x60]` to find the PEB without
needing any imports.

---

## 5. Calling Conventions Review (Architecture View)

### How the Stack Grows
The stack grows **downward** (toward lower addresses):
- `push rax` → RSP -= 8; [RSP] = RAX
- `pop rax`  → RAX = [RSP]; RSP += 8

### Red Zone (Linux x64 / SysV ABI only)
The 128 bytes BELOW RSP are guaranteed not to be clobbered by signal handlers.
Code can use `[rsp-8]`, `[rsp-16]`, etc. without adjusting RSP.
Windows x64 does NOT have a red zone — ABI uses shadow space instead.

### Stack Alignment
Before a `call` instruction: RSP must be aligned to **16 bytes**.
The `call` pushes an 8-byte return address → RSP becomes 8-byte aligned inside the called function.
Hence the prologue: `sub rsp, 8` to realign, or `push rbp` serves dual purpose.

---

## 6. Interrupts and Exceptions (Ring Model)

### Privilege Rings
- **Ring 0**: Kernel — full hardware access
- **Ring 1–2**: Not used by Windows/Linux
- **Ring 3**: User mode — restricted access

### System Calls (x64 Windows: syscall instruction)
```asm
mov r10, rcx         ; syscall doesn't use RCX for arg1 (RIP-clobbering)
mov eax, <syscall_number>
syscall              ; enters Ring 0 via LSTAR MSR
```
- Malware uses direct syscalls to bypass user-mode hooks (EDR)
- Syscall number changes between Windows versions!

### Exception Handling (Windows SEH)
- **32-bit**: Chain of `_EXCEPTION_REGISTRATION_RECORD` on stack, linked via FS:[0]
- **64-bit**: Table-based (`.pdata` section) — no stack-based chain
- Anti-debug: `SetUnhandledExceptionFilter` or raising exceptions deliberately

---

## 7. Hardware Security Features

| Feature | Purpose | Bypass Used In |
|---------|---------|----------------|
| NX/DEP  | No-execute on data pages | ROP chains |
| ASLR    | Randomize layout | Info leaks, heap sprays |
| SMEP    | Kernel can't exec user pages | Kernel exploits |
| SMAP    | Kernel can't access user data | Kernel exploits |
| KASLR   | Randomize kernel base | Kernel info leaks |
| CET     | Shadow stack (return address) | Advanced ROP defenses |
| CFG     | Control Flow Guard (Windows) | CFG bypass techniques |
| VBS     | Virtualization-Based Security | Hypervisor-level |

---

## 8. Key Architecture Concepts in Malware Analysis

### Why Heap Spray Works
Large heap allocations map physical pages in predictable virtual ranges.
Fill with NOP sled + shellcode → guess approximate landing address.
With ASLR weaknesses, probability becomes acceptable.

### Why ROP Works
- NX/DEP prevents executing shellcode on the stack/heap
- ROP chains call existing executable code snippets (gadgets) ending in `ret`
- Each gadget does a tiny operation; chained together = Turing-complete
- Bypasses DEP/NX entirely because code is in legitimate .text sections

### Why Spectre/Meltdown Are Architectural
- Exploit speculative execution (CPU runs ahead)
- Cache state is observable (timing side-channel)
- Can read kernel/hypervisor memory from user space
- Software mitigation = retpoline, IBRS/STIBP (massive performance cost)

---

## Summary: Architecture Checklist for RE

1. Virtual address → physical address mapping (page tables, permissions)
2. Cache hierarchy → timing side-channels
3. GS:[0x60] → PEB (shellcode starting point)
4. Stack growth direction → stack frame layout in disasm
5. Ring 0 vs Ring 3 → syscall mechanism, kernel exploits
6. NX/DEP + ASLR → why ROP exists
7. x64 calling convention + shadow space
