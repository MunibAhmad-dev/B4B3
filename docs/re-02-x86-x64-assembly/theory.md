# Module RE-02: x86/x64 Assembly for Reverse Engineers

## Why Assembly

When you open a binary in Ghidra or x64dbg, what you see IS assembly (or the decompiled
pseudo-C derived from it). You don't need to write it from scratch — you need to READ it
fluently. This module teaches you to read like a disassembler.

---

## 1. Registers

### x64 General-Purpose Registers
| 64-bit | 32-bit | 16-bit | 8-bit (lo) | Purpose (calling conv) |
|--------|--------|--------|------------|------------------------|
| RAX    | EAX    | AX     | AL         | Return value / scratch |
| RBX    | EBX    | BX     | BL         | Callee-saved           |
| RCX    | ECX    | CX     | CL         | Arg 1                  |
| RDX    | EDX    | DX     | DL         | Arg 2                  |
| RSP    | ESP    | SP     | SPL        | Stack pointer          |
| RBP    | EBP    | BP     | BPL        | Base pointer (frame)   |
| RSI    | ESI    | SI     | SIL        | Callee-saved / src idx |
| RDI    | EDI    | DI     | DIL        | Callee-saved / dst idx |
| R8–R15 | R8d–R15d| R8w–R15w| R8b–R15b| R8/R9=Arg3/4; rest volatile(R10,R11) or callee-saved(R12-R15)|

### Special Registers
- **RIP**: instruction pointer (program counter) — not directly writable in user mode
- **RFLAGS**: status flags (ZF, CF, SF, OF, PF, DF, IF)
- **Segment regs**: CS, DS, SS, ES, FS, GS — in 64-bit mode mostly unused except FS/GS
  - GS base (Windows) → TEB (Thread Environment Block) at `gs:[0x30]`
  - FS base (Linux x64) → TLS / thread data

### Writing to 32-bit register zeros upper 32 bits
```asm
mov eax, 1        ; RAX = 0x0000000000000001 (upper 32 zeroed)
mov ax, 1         ; only AX changed, upper 48 bits preserved
mov al, 1         ; only AL changed, upper 56 bits preserved
```

---

## 2. Instruction Set Fundamentals

### Data Movement
```asm
mov  rax, rbx          ; rax = rbx
mov  rax, [rbx]        ; rax = *rbx (load from memory)
mov  [rax], rbx        ; *rax = rbx (store to memory)
mov  rax, 0x1234       ; rax = immediate value
lea  rax, [rbx+8]      ; rax = rbx+8  (address, NOT the value at that address)
xchg rax, rbx          ; swap
movsx rax, eax         ; sign-extend EAX into RAX
movzx rax, ax          ; zero-extend AX into RAX
push rax               ; rsp -= 8; *rsp = rax
pop  rax               ; rax = *rsp; rsp += 8
```

### Arithmetic
```asm
add  rax, rbx          ; rax += rbx
sub  rax, rbx          ; rax -= rbx
mul  rbx               ; RDX:RAX = RAX * RBX (unsigned)
imul rax, rbx          ; rax *= rbx (signed, 2-operand form)
div  rbx               ; RAX = RDX:RAX / RBX; RDX = remainder
inc  rax               ; rax++
dec  rax               ; rax--
neg  rax               ; rax = -rax (two's complement negate)
```

### Logic & Bit Operations
```asm
and  rax, rbx          ; rax &= rbx
or   rax, rbx          ; rax |= rbx
xor  rax, rbx          ; rax ^= rbx
not  rax               ; rax = ~rax
shl  rax, cl           ; rax <<= CL (logical left shift)
shr  rax, cl           ; rax >>= CL (logical right, zero fill)
sar  rax, cl           ; rax >>= CL (arithmetic, sign fill)
rol  rax, cl           ; rotate left
ror  rax, cl           ; rotate right
bsf  rax, rbx          ; bit scan forward (index of lowest set bit)
bsr  rax, rbx          ; bit scan reverse (index of highest set bit)
bt   rax, rbx          ; bit test: CF = rax[rbx]
```

**Key shortcut**: `xor eax, eax` zeros RAX — fastest way to zero a register.

### Comparison and Jumps
```asm
cmp  rax, rbx          ; sets flags: rax-rbx (no result stored)
test rax, rax          ; sets flags: rax&rax (ZF=1 if zero)
test rax, rbx          ; sets flags: rax&rbx

; Conditional jumps (after cmp/test):
je  / jz               ; jump if equal / zero (ZF=1)
jne / jnz              ; not equal / not zero
jg  / jnle             ; greater (signed)
jge / jnl              ; greater or equal (signed)
jl  / jnge             ; less (signed)
jle / jng              ; less or equal (signed)
ja  / jnbe             ; above (unsigned)
jb  / jnae             ; below (unsigned)
jae / jnb              ; above or equal (unsigned)
js                     ; sign (SF=1, result was negative)
jns                    ; not sign
jc                     ; carry
jnc                    ; no carry
jo                     ; overflow
jno                    ; no overflow
jmp label              ; unconditional jump
```

### Function Call/Return
```asm
call SomeFunction      ; push rip; jmp SomeFunction
ret                    ; pop rip; jmp rip
retn 0x20              ; pop rip; add rsp, 0x20; jmp (stdcall cleanup)
```

---

## 3. Memory Addressing Modes

General form: `[base + index*scale + displacement]`
- **base**: any register
- **index**: any register except RSP
- **scale**: 1, 2, 4, or 8
- **displacement**: signed constant

```asm
mov eax, [rsp+8]           ; base + disp
mov eax, [rbx+rsi*4]       ; base + index*scale
mov eax, [rbx+rsi*4+0x20]  ; base + index*scale + disp
mov eax, [rip+0x1234]      ; RIP-relative (common in x64 for globals)
```

### Pointer sizes
```asm
mov byte  ptr [rax], 1    ; 1-byte write
mov word  ptr [rax], 1    ; 2-byte write
mov dword ptr [rax], 1    ; 4-byte write
mov qword ptr [rax], 1    ; 8-byte write
```

---

## 4. Stack Frame Anatomy

```asm
; Function prologue (frame pointer style)
push rbp              ; save caller's base pointer
mov  rbp, rsp         ; establish our own frame
sub  rsp, 0x30        ; allocate locals + alignment

; Access locals: [rbp-8], [rbp-16], etc.
; Access shadow: [rbp+0x10] = arg1 home, [rbp+0x18] = arg2, etc.

; Function epilogue
mov  rsp, rbp         ; restore stack
pop  rbp              ; restore caller's base pointer
ret
```

Without frame pointer (`/O2` optimization):
```asm
; No push rbp — compiler tracks RSP offsets directly
sub  rsp, 0x28        ; alloc locals + 0x20 shadow + 8 alignment
; locals at [rsp+N], shadows at [rsp+0], [rsp+8], [rsp+16], [rsp+24]
add  rsp, 0x28
ret
```

**Key RE skill**: determine if frame pointer is used (rbp appears in first 3 instructions)
vs frameless (only rsp-relative accesses).

---

## 5. Common Patterns in Malware / Compiled Code

### XOR encryption loop
```asm
xor_loop:
    mov al, [rsi+rcx]    ; al = buf[i]
    xor al, [rdx+rcx]    ; al ^= key[i % keylen]
    mov [rdi+rcx], al    ; out[i] = al
    inc rcx
    cmp rcx, r8          ; i < len?
    jl  xor_loop
```

### PEB walk (manual API resolution — shellcode staple)
```asm
; x64: gs:[0x60] = PEB
mov rax, gs:[0x60]        ; PEB
mov rax, [rax+0x18]       ; PEB.Ldr
mov rax, [rax+0x20]       ; Ldr.InMemoryOrderModuleList.Flink (first entry)
mov rax, [rax]            ; .Flink again (second module = ntdll or kernel32)
mov rax, [rax+0x20]       ; DllBase of second module
; ... then walk export table
```

### API hashing loop
```asm
; Compute FNV hash of export name string
mov  edi, 0x811C9DC5      ; FNV offset basis
hash_loop:
    movzx eax, byte ptr [rsi]  ; load char
    test al, al
    jz   done
    xor  edi, eax              ; h ^= char
    imul edi, 0x01000193       ; h *= FNV prime
    inc  rsi
    jmp  hash_loop
done:
    cmp edi, ebx               ; does hash match target?
    je  found
```

### `rep movsb` / `rep stosb` — bulk memory ops
```asm
; memcpy equivalent:
mov rsi, src
mov rdi, dst
mov rcx, count
rep movsb          ; copies RCX bytes from [RSI] to [RDI]

; memset equivalent (zero memory):
xor  eax, eax
mov  rdi, ptr
mov  rcx, count
rep stosb          ; fills RCX bytes at [RDI] with AL
```

### Computed jump / switch table
```asm
cmp  eax, 5          ; bounds check: case 0–5
ja   default
lea  rcx, [rip+table_offset]
movsxd rax, dword ptr [rcx+rax*4]  ; load table entry (relative offset)
add  rax, rcx
jmp  rax             ; jump to case handler
```

### Anti-debug: RDTSC timing
```asm
rdtsc                ; read timestamp counter → EDX:EAX
mov [t1], eax
; ... some work ...
rdtsc
sub eax, [t1]
cmp eax, 0x10000     ; if delta > threshold, debugger present
jg  detected
```

---

## 6. x64 vs x86 Key Differences

| Feature             | x86 (32-bit)               | x64 (64-bit)              |
|---------------------|----------------------------|---------------------------|
| General regs        | EAX–EDI (8)                | RAX–R15 (16)              |
| Pointer size        | 4 bytes                    | 8 bytes                   |
| Calling conv        | stack-based (cdecl/stdcall)| register-based (fastcall) |
| Stack alignment     | 4 bytes                    | 16 bytes (before call)    |
| SEH                 | Stack-based (FS:[0])       | Table-based (.pdata)      |
| TEB                 | FS segment                 | GS segment                |
| RIP-relative addr   | No                         | Yes (`[rip+offset]`)      |
| Stack cleanup       | Callee (stdcall) or caller | Always caller             |

---

## 7. SIMD — What to Expect in Decompilers

Modern compilers auto-vectorize. You'll see:
```asm
movdqu xmm0, [rsi]        ; load 16 bytes
pxor   xmm0, xmm1         ; XOR 16 bytes at once (AES, RC4, etc.)
pcmpeqb xmm0, xmm2        ; compare 16 bytes for equality
movdqu [rdi], xmm0        ; store 16 bytes
```

In Ghidra/IDA these often decompile badly. If you see `__int128` or odd vector ops,
suspect auto-vectorized crypto or string operations.

---

## 8. Reading Disasm Checklist

1. Find function entry: prologue (`push rbp` or `sub rsp, N`)
2. Identify calling convention from first 4 register uses
3. Map locals (negative RBP offsets or RSP+N offsets)
4. Follow control flow: `cmp/test` + conditional jump = branch
5. Look for `call [rax]` or `call [rbx+N]` = indirect call (vtable or fn ptr)
6. Look for `mov rax, gs:[0x60]` = PEB access
7. Recognize string constants via `lea rcx, [rip+N]`
8. Spot loops: back-edge jump to address < current
9. `xor eax, eax` before return = `return 0`
10. `inc eax; ret` or `mov eax, 1; ret` = `return 1` / `return true`
