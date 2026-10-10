# RE-04: Computer Architecture for Security

## Why This Matters

Understanding CPU internals lets you exploit micro-architectural side-channels
(Spectre, Meltdown, Flush+Reload), write faster shellcode, and reason about
timing-based anti-debug and sandbox-detection tricks.

---

## CPU Internals

### CPUID Instruction

`CPUID` with EAX=leaf returns processor info in EAX/EBX/ECX/EDX.

| Leaf | Returns |
|------|---------|
| 0x00 | Max leaf + vendor string (GenuineIntel / AuthenticAMD) |
| 0x01 | Family/Model/Stepping; ECX bit 31 = hypervisor present |
| 0x07 | Extended features (AVX-512, SGX, …) |
| 0x40000000 | Hypervisor vendor (VMware: "VMwareVMware"; VBox: "VBoxVBoxVBox") |
| 0x80000002–04 | Processor brand string |

**Anti-VM detection**: CPUID leaf 1, ECX bit 31. VMware also returns
"VMwareVMware" at leaf 0x40000000.

### RDTSC / RDTSCP

`RDTSC` reads the Time Stamp Counter — cycle count since reset.
Used to measure function execution time to detect single-stepping:

```
RDTSC → save t1
<code under test>
RDTSC → t2
if (t2 - t1 > threshold) // debugger detected
```

### Branch Prediction & Spectre

Modern CPUs speculatively execute past branches. Spectre variant 1 exploits
mis-speculation to leak data via cache side-channels. Blue team: retpoline
(compiler), IBRS (hardware), LFENCE after branch.

---

## Cache Hierarchy & Side-Channels

Typical latencies:
- L1 cache hit: ~4 cycles
- L2 cache hit: ~12 cycles
- L3 cache hit: ~40 cycles
- DRAM access: ~200–300 cycles

**Flush+Reload**: attacker flushes a cache line (`CLFLUSH`), victim accesses
shared memory, attacker measures reload time — if fast, victim touched it.

**Prime+Probe**: attacker fills a cache set, victim runs, attacker re-accesses
and measures — evicted lines reveal victim's access pattern.

---

## SIMD (SSE2 / AVX2)

SSE2 gives 128-bit XMM registers (16 bytes at once).
AVX2 gives 256-bit YMM registers (32 bytes at once).

Useful for: fast XOR encryption/decryption, string search, entropy calculation.
Malware uses CPUID to check AVX availability before using it.

---

## Memory Ordering & Fences

- **SFENCE**: store fence — previous stores visible before fence
- **LFENCE**: load fence — previous loads complete before subsequent loads
- **MFENCE**: full fence

Needed when writing lock-free shellcode or shared memory between threads.

---

## Exercises

1. `ex01_cpuid_dump.cpp`  — Call CPUID leaves 0x00, 0x01, 0x07, 0x40000000; print results
2. `ex02_cache_timing.cpp` — Measure L1 vs RAM access latency with RDTSC; detect sandbox by timing anomaly
3. `ex03_simd_xor.cpp`    — XOR-encrypt a buffer using SSE2 intrinsics (_mm_xor_si128); compare speed vs scalar

## Key References

- Intel® 64 and IA-32 Architectures Software Developer's Manual (Vol. 2)
- "A Survey of Microarchitectural Side-Channel Attacks" (Ge et al.)
- `<intrin.h>`, `<immintrin.h>` — MSVC/GCC intrinsic headers
