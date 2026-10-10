# Module 21 — Coverage-Guided Fuzzing

## Why mutation fuzzing isn't enough

The simple fuzzer from Module 13 mutates inputs blindly. After millions of
iterations, it mostly re-explores the same paths. It can find obvious bugs
but misses deep ones guarded by conditions like:

```cpp
if (magic == 0xDEADBEEF) {
    if (version == 3) {
        if (checksum == computeCrc(data)) {
            // ← bug here — mutation fuzzer almost never reaches this
        }
    }
}
```

A mutation fuzzer might hit `magic == 0xDEADBEEF` by chance but is
unlikely to simultaneously satisfy all three conditions.

**Coverage-guided fuzzing** solves this by tracking which basic blocks (branches)
each input exercises. When a new input reaches a NEW branch, it's saved to the
corpus and mutated further. Over time the corpus grows to cover more of the
program's paths.

---

## 2. How Coverage Is Measured

**AFL-style bitmap approach:**
- Instrument every branch in the target with a tiny hook that XORs a bitmap entry
- Bitmap entry = `hash(from_block, to_block)` → entry in shared memory
- After each run: compare bitmap to previous corpus coverage
- If new bits are set: the input found new coverage → add to corpus

**Instrumentation methods:**

| Method | How | When |
|--------|-----|-------|
| Compile-time (AFL, libFuzzer) | Add hooks during compilation with a compiler pass | Need source code |
| Binary instrumentation (WinAFL) | DynamoRIO rewrites basic blocks at run-time | Works on closed binaries |
| Hardware tracing (Intel PT) | CPU records taken branches at hardware speed | Fastest, needs CPU support |

---

## 3. WinAFL Setup (Windows coverage-guided fuzzing)

**WinAFL** = AFL port for Windows, uses DynamoRIO for binary instrumentation.

```
Tool chain:
  WinAFL (fuzzer driver + harness)
  └── DynamoRIO (dynamic binary instrumentation framework)
      └── target.exe (what you're fuzzing)

Corpus: initial valid input files (seed corpus)
  → WinAFL mutates them
  → DynamoRIO runs target + records coverage
  → Interesting inputs (new coverage) go back into corpus
  → Crashes saved to crashes/ directory
```

**Basic usage:**
```
afl-fuzz.exe -i seeds\ -o findings\ -t 5000 --
  drrun.exe -c winafl.dll -target_module target.exe
            -target_function parseInput -fuzz_iterations 5000
  -- target.exe @@
```

`@@` is replaced by the path to the current test input.

---

## 4. Writing a Harness

A harness wraps the target function so WinAFL can call it repeatedly
without restarting the process (much faster):

```cpp
// harness.cpp — compiled into target.exe
// WinAFL calls this function for each test case
extern "C" __declspec(dllexport) int fuzz(const char* filename) {
    // Read the test file
    FILE* f = fopen(filename, "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END); size_t sz = ftell(f); rewind(f);
    std::vector<uint8_t> data(sz);
    fread(data.data(), 1, sz, f);
    fclose(f);

    // Call the function under test
    __try {
        parseInput(data.data(), data.size());  // the function you're fuzzing
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // let WinAFL handle the crash
    }
    return 0;
}
```

**Using persistent mode (much faster — no process restart):**
```cpp
// Instead of restarting for each input, WinAFL resets state and calls again
while (__afl_persistent_loop(10000)) {
    // Read from stdin or the current file
    parseInput(data, size);
}
```

---

## 5. Writing Your Own Simple Coverage Fuzzer in C++

Without DynamoRIO, you can approximate coverage using:
- **Breakpoint-based coverage**: set INT3 breakpoints at function entry points,
  remove them when hit (one-shot breakpoints), count unique hit addresses
- **Binary rewriting**: parse the PE, insert jump hooks before basic blocks
  (complex but educational)
- **Address space layout**: run the target in a subprocess, use `GetModuleInformation`
  + debugger APIs to track which addresses were executed

**Simpler approach for learning: track basic block entry via debug API**

```cpp
// Run target as a debug child, set hardware breakpoints on interesting addresses
PROCESS_INFORMATION pi = {};
STARTUPINFOA si = { sizeof(si) };
CreateProcessA(target, nullptr, nullptr, nullptr,
               FALSE, DEBUG_ONLY_THIS_PROCESS, nullptr, nullptr, &si, &pi);

// Debug loop
DEBUG_EVENT de = {};
while (WaitForDebugEvent(&de, INFINITE)) {
    if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
        if (de.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
            // Our INT3 was hit — record the address, remove the breakpoint
            DWORD addr = (DWORD)de.u.Exception.ExceptionRecord.ExceptionAddress;
            coverage.insert(addr);
            // Restore original byte
            restoreBreakpoint(pi.hProcess, addr);
        }
    }
    ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
}
```

---

## 6. Corpus Management

A good corpus strategy:
```
1. Start with valid seed inputs (real files your target accepts)
2. For each mutation:
   a. Run target, measure coverage
   b. If new coverage: add to corpus (interesting!)
   c. If crash: save to crashes/ with the input
   d. If no new coverage: discard this input
3. Minimize the corpus periodically (remove redundant inputs)
   → keep only the smallest input that exercises each unique branch
```

**AFL-style minimization (afl-tmin):**
Reduces a crashing input to the smallest file that still triggers the same crash.
Essential for bug reporting — you want a 10-byte PoC, not a 100KB random blob.

---

## 7. Reading Crash Triage

When the fuzzer finds a crash:
1. Save the crashing input
2. Run the target under a debugger with the crashing input
3. Record: exception type, faulting address, register state, call stack
4. Classify: is this exploitable?
   - Write-what-where (controllable write to controlled address) → CRITICAL
   - Read past end of heap/stack → probably info-leak or DoS
   - NULL dereference → likely DoS only
5. Create a minimal PoC (afl-tmin)
6. File a bug report with: reproduction steps, crash dump, classification

---

## Exercises

- `ex01_winafl_harness.cpp` — target with harness function + simple file parser
- `ex02_coverage_tracker.cpp` — debug-API-based coverage tracker (breakpoints)
- `ex03_corpus_manager.cpp` — corpus deduplication and minimization tool
- `ex04_crash_triage.cpp` — automated crash classification (read/write, exploitable?)
