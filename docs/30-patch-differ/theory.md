# Module 30 — Patch Differ / Binary Diff

## Why binary diffing matters

When a software vendor releases a security patch, they often don't publish
the vulnerability details. But the patch itself reveals everything:
compare the patched and unpatched binary, find the changed bytes, and
you've found the vulnerability.

**Security uses:**
- **Reverse engineering patches**: understand what was fixed → write an exploit before users patch.
- **Regression testing**: verify that a specific bugfix (byte change) is present in a build.
- **Malware analysis**: diff a clean vs. infected binary to find what was patched in.
- **License protection analysis**: find where a license check was replaced with a NOP.

---

## 2. Types of Binary Diff

| Type | What it shows | Tool |
|------|--------------|------|
| Raw byte diff | Which bytes changed and where | BinDiff, vbindiff |
| Structural (function-level) | Which functions changed | BinDiff, Diaphora |
| Semantic | What behavior changed | Manual + Ghidra |

---

## 3. Function-Level Diffing (BinDiff approach)

```
1. Disassemble both binaries.
2. For each function: compute a hash (mnemonic sequence, call graph, etc.)
3. Match functions by hash similarity.
4. Functions with different hashes → changed functions.
5. Drill into changed functions to see byte-level diffs.
```

---

## 4. Basic Byte-Level Diff Algorithm

```cpp
struct DiffHunk {
    size_t offset;
    std::vector<BYTE> oldBytes;
    std::vector<BYTE> newBytes;
};

std::vector<DiffHunk> byteDiff(
    const std::vector<BYTE>& a,
    const std::vector<BYTE>& b)
{
    std::vector<DiffHunk> hunks;
    size_t n = std::min(a.size(), b.size());

    DiffHunk current;
    bool inHunk = false;

    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            if (!inHunk) {
                current = { i, {}, {} };
                inHunk = true;
            }
            current.oldBytes.push_back(a[i]);
            current.newBytes.push_back(b[i]);
        } else {
            if (inHunk) {
                hunks.push_back(current);
                inHunk = false;
            }
        }
    }
    if (inHunk) hunks.push_back(current);

    // Handle size difference
    if (a.size() != b.size()) {
        DiffHunk h;
        h.offset = n;
        for (size_t i = n; i < a.size(); i++) h.oldBytes.push_back(a[i]);
        for (size_t i = n; i < b.size(); i++) h.newBytes.push_back(b[i]);
        hunks.push_back(h);
    }
    return hunks;
}
```

---

## 5. Function Hashing for Structural Diff

```cpp
// Hash a function's mnemonic sequence (ignoring operand values)
// so ASLR and relocation changes don't affect the hash
uint32_t hashFunction(ZydisDecoder* dec, const BYTE* code, size_t size) {
    uint32_t h = 5381;
    ZydisDecodedInstruction instr;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    size_t off = 0;
    while (off < size &&
           ZYAN_SUCCESS(ZydisDecoderDecodeFull(dec, code+off, size-off, &instr, operands))) {
        // Use mnemonic ID (not operands) for the hash
        h = h * 33 + instr.mnemonic;
        off += instr.length;
    }
    return h;
}
```

---

## 6. Patch Analysis Workflow

1. Obtain both binaries (e.g., from Windows Update downloads).
2. Extract individual PE sections for comparison.
3. Run byte diff → find changed sections.
4. For each changed function:
   - Disassemble the original and patched version side-by-side.
   - Look for: removed bounds checks, added NULL checks, changed constants.
5. Form a hypothesis about the vulnerability.
6. Write a proof-of-concept to verify.

**Example: CVE-XXXX-YYYY analysis pattern:**
```
Old: cmp eax, ecx   → jbe .continue   (no bounds check on length)
New: cmp eax, 0x1000 → ja .error      (added upper bound check)
     cmp eax, ecx   → jbe .continue
```
→ Integer overflow / heap overflow was possible when `eax > 0x1000`.

---

## 7. Tools

| Tool | Use |
|------|-----|
| BinDiff (Zynamics/Google) | Best commercial function-level differ |
| Diaphora | Open-source IDA plugin, similar to BinDiff |
| vbindiff | Terminal hex differ |
| bindiff (CLI) | Basic byte differ |
| radiff2 (radare2) | Open-source, scriptable |

---

## Exercises

- `ex01_byte_differ.cpp` — raw byte diff between two files, print hunks
- `ex02_pe_section_diff.cpp` — diff at PE section level (compare .text, .data independently)
- `ex03_function_matcher.cpp` — hash functions in both PEs, find changed/added/removed ones
- `ex04_patch_analyzer.cpp` — for each changed function, disassemble both sides and print the delta
