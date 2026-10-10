# Module RE-01: C/C++ for Reverse Engineers

## Why C/C++ First

Every piece of malware, every Windows driver, every exploit shellcode is compiled C or C++.
Before you can read disassembly, you need to be able to mentally compile and decompile C.
This module trains you to see C patterns in raw assembly output.

---

## 1. Memory Layout of C Types

### Primitive sizes (x64 Windows)
| Type       | Size | Alignment |
|------------|------|-----------|
| char       | 1    | 1         |
| short      | 2    | 2         |
| int        | 4    | 4         |
| long       | 4    | 4         |
| long long  | 8    | 8         |
| pointer    | 8    | 8         |
| float      | 4    | 4         |
| double     | 8    | 8         |

### Struct padding rules
The compiler inserts padding so each member is naturally aligned:

```c
struct Padded {
    char  a;    // offset 0
    // 3 bytes padding
    int   b;    // offset 4
    char  c;    // offset 8
    // 7 bytes padding
    void* d;    // offset 16
};              // total: 24 bytes
```

**In IDA/Ghidra** you'll see `mov dword ptr [rax+4], ebx` — the +4 is the offset of field `b`.
Learning to read struct offsets in disasm is the skill. Structs are everywhere: HANDLE tables,
LIST_ENTRY, PEB, TEB, OVERLAPPED, etc.

### Union — same memory, multiple views
```c
union IpAddr {
    uint32_t raw;
    uint8_t  octets[4];
};
```
Used heavily in malware for IP/port obfuscation.

---

## 2. Pointers — The Core Skill

### Pointer arithmetic
```c
int arr[5] = {10,20,30,40,50};
int* p = arr;
p++;   // advances by sizeof(int) = 4 bytes
// in asm: lea rax, [rax+4]
```

### Double pointers (pointer-to-pointer)
```c
void** ppVoid;   // used constantly in Windows API: LPVOID*, HANDLE*, etc.
```
When you see `mov rax, [rbx]` followed by `mov rax, [rax]` — that's a double dereference.

### Function pointers
```c
typedef int (*PFUNC)(int, int);
PFUNC fp = my_add;
int r = fp(3, 4);
// asm: call rax   (indirect call — key indicator of callbacks/hooks)
```
Malware uses function pointers constantly to avoid import-table detection.

---

## 3. Calling Conventions (Windows x64)

### x64 __fastcall (default on Windows)
- First 4 integer/pointer args: **RCX, RDX, R8, R9**
- First 4 float args: **XMM0–XMM3**
- Remaining args pushed on stack right-to-left
- Caller allocates 32-byte **shadow space** (home space) on stack before call
- Return value in **RAX** (or XMM0 for float)
- Caller-saved (volatile): RAX, RCX, RDX, R8, R9, R10, R11
- Callee-saved (non-volatile): RBX, RBP, RDI, RSI, R12–R15

```
; foo(a=1, b=2, c=3, d=4, e=5)
mov  rcx, 1       ; arg1
mov  rdx, 2       ; arg2
mov  r8,  3       ; arg3
mov  r9,  4       ; arg4
mov  [rsp+20h], 5 ; arg5 on stack AFTER shadow space
sub  rsp, 28h     ; 20h shadow + 8h alignment
call foo
add  rsp, 28h
```

### x86 __cdecl (32-bit, stack-based)
- All args pushed right-to-left
- Caller cleans stack
- Return in EAX

### x86 __stdcall (WinAPI 32-bit)
- Args pushed right-to-left
- **Callee** cleans stack (RETN N)
- Return in EAX

**Key RE insight**: count the `RETN N` byte to find arg count in 32-bit code.
`retn 0x10` → 16 bytes → 4 args (4 bytes each).

---

## 4. Stack Frames

```c
int add(int a, int b) {
    int result = a + b;  // local variable on stack
    return result;
}
```

Generated prologue/epilogue (x64):
```asm
add proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 10h          ; space for locals + alignment
    mov     [rbp-4], ecx      ; save arg a (RCX) to local
    mov     [rbp-8], edx      ; save arg b (RDX) to local
    mov     eax, [rbp-4]
    add     eax, [rbp-8]
    mov     [rbp-0Ch], eax    ; result
    mov     eax, [rbp-0Ch]
    add     rsp, 10h
    pop     rbp
    ret
add endp
```

In IDA/Ghidra locals appear as `var_4`, `var_8`, etc. — negative RBP offsets.

---

## 5. C++ Specific Patterns

### Constructors / Destructors
```cpp
class Foo {
    int x;
public:
    Foo(int v) : x(v) {}
    ~Foo() {}
    int get() { return x; }
};
```
In asm: `mov [this+0], val` — writes member `x`. The `this` pointer is the first argument (RCX).

### Virtual Functions / vtable
```cpp
class Animal {
public:
    virtual void speak() = 0;
};
class Dog : public Animal {
public:
    void speak() override { /* ... */ }
};
```
Object layout in memory:
```
[vptr]   ← points to vtable (array of function pointers)
[member1]
[member2]
```
In asm:
```asm
mov rax, [rcx]        ; load vptr from object (this = RCX)
call [rax+8]          ; call vtable[1] (second virtual function)
```
When you see a double dereference before a call — it's a virtual dispatch.

### RTTI (Run-Time Type Information)
Object→vptr→vtable→RTTI descriptor. Used by Ghidra/IDA to identify class names in malware.

### std::string internals
MSVC `std::string` stores inline buffer (15 chars) or heap pointer + size + capacity.
Regex: find strings by looking for `lea rcx, [rbp-20h]` followed by string setup.

---

## 6. Patterns to Recognize in Disasm

| C Construct          | Assembly Pattern                              |
|----------------------|-----------------------------------------------|
| `if (a == b)`        | `cmp eax, ebx; jne`                           |
| `while (i < 10)`     | `cmp [var], 0Ah; jge exit`                    |
| `for` loop           | init → cmp → jge exit → body → inc → jmp     |
| `switch`             | jump table: `jmp [rax*8+table]` or chain of `cmp/je` |
| `malloc(n)`          | `mov ecx, n; call malloc` → ptr in RAX        |
| `free(p)`            | `mov rcx, p; call free`                       |
| `strlen(s)`          | `repne scasb` or loop counting zeros           |
| `memcpy(d,s,n)`      | `rep movsb` or vectorized `movdqu`            |
| Virtual call         | `mov rax,[rcx]; call [rax+N]`                 |
| Function ptr call    | `call rax` / `call [rbx+N]`                  |
| Struct field access  | `[reg+offset]`                                |

---

## 7. Compiler Optimizations That Trip Up Beginners

### Inlining
Small functions get inlined — no call instruction at all.

### Tail-call optimization
Last call in function replaced with `jmp` not `call`.
```asm
jmp  SomeFunction   ; not a loop — tail call
```

### Loop unrolling
A `for(i=0;i<4;i++)` may compile to 4 separate operations with no loop.

### Dead code elimination
Unused variables and branches simply don't appear in release builds.
Always use debug symbols or analyze with heuristics.

### SIMD
String operations, crypto, memcpy → SSE/AVX instructions (`movdqu`, `pxor`, `pcmpeqb`).

---

## 8. Windows-Specific C Patterns in Malware

### HANDLE semantics
```c
HANDLE hFile = CreateFileA(...);
if (hFile == INVALID_HANDLE_VALUE) { /* error */ }
// In asm: cmp rax, 0FFFFFFFFFFFFFFFFh; je error
```

### Error checking via GetLastError
```c
if (!ReadFile(...)) {
    DWORD err = GetLastError();
}
// In asm after WinAPI call: call GetLastError; mov [var], eax
```

### WideChar vs ANSI
`CreateFileA` = ANSI, `CreateFileW` = Unicode (UTF-16LE, 2 bytes/char).
Malware uses W variants to support international paths.

### PEB walkthrough (manual GetProcAddress)
Modern malware avoids the import table:
```c
// Walk PEB→Ldr→InMemoryOrderModuleList to find kernel32
// Parse PE export table manually
// Compute hash of each export name, match target hash
```
This is the #1 pattern in shellcode and fileless malware.

---

## Summary: Skills to Build

1. Look at C code → mentally produce the assembly
2. Look at assembly → mentally reconstruct the C
3. Identify struct offsets in memory dumps
4. Recognize calling convention from register usage
5. Spot virtual dispatch (double deref + indirect call)
6. Identify loop patterns and switch tables
7. Read WinAPI usage from call sites
