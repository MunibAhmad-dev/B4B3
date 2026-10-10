# Exercise 1: Read the Disassembly (Paper Exercise)

These are real compiler-generated assembly listings. For each snippet:
- Write what the original C code likely looked like
- Identify the pattern (loop, branch, struct access, etc.)
- Answer the specific question

---

## Snippet A — What does this function do?

```asm
; function: ??? (x64, MSVC release)
mystery_a proc
    xor     eax, eax          ; 1
    test    rcx, rcx          ; 2
    jz      short return_0    ; 3
loop_top:
    movzx   edx, byte ptr [rcx+rax]  ; 4
    test    dl, dl            ; 5
    jz      short return_0    ; 6
    inc     rax               ; 7
    jmp     short loop_top    ; 8
return_0:
    ret                       ; 9
mystery_a endp
```

**Questions:**
1. What does RCX contain on entry?
2. What does RAX contain on return?
3. Write the C equivalent (3 lines or fewer).
4. What standard C library function does this implement?

---

## Snippet B — What condition is being checked?

```asm
; function returns 1 if condition true, 0 if false
check proc
    mov     eax, ecx          ; arg1 = ecx
    and     eax, edx          ; and with arg2
    cmp     eax, edx          ; 
    sete    al                ; al = (result == edx) ? 1 : 0
    movzx   eax, al
    ret
check endp
```

**Questions:**
1. What does `sete` do?
2. What is the mathematical relationship being tested?
3. Write the C equivalent. (Hint: think bit manipulation)
4. Where might you see this in malware code?

---

## Snippet C — Identify the data structure

```asm
; called as: traverse(Node* head)  RCX=head
traverse proc
    push    rbx
    sub     rsp, 20h
    test    rcx, rcx
    jz      short done
    mov     rbx, rcx
loop:
    mov     rcx, rbx
    call    process_node         ; process_node(node)
    mov     rbx, [rbx+8]         ; rbx = rbx->???
    test    rbx, rbx
    jnz     short loop
done:
    add     rsp, 20h
    pop     rbx
    ret
traverse endp
```

**Questions:**
1. What data structure is being traversed?
2. What is the type of the field at offset +8?
3. What is the `sub rsp, 20h` for?
4. Write the C struct definition and function.

---

## Snippet D — Identify the algorithm

```asm
; entry: RCX = uint8_t* buf, RDX = size_t len
; modifies buf in place
encode proc
    test    rdx, rdx
    jz      short done
    xor     r8d, r8d            ; i = 0
loop_top:
    movzx   eax, byte ptr [rcx+r8]   ; al = buf[i]
    movzx   r9d, r8b                  ; r9 = (uint8_t)i
    add     al, r9b                   ; al += (uint8_t)i
    mov     [rcx+r8], al             ; buf[i] = al
    inc     r8                        ; i++
    cmp     r8, rdx                   ; i < len?
    jb      short loop_top
done:
    ret
encode endp
```

**Questions:**
1. Write the C implementation.
2. Is this a real encryption algorithm? Why or why not?
3. How would you reverse this (write the decode function)?
4. What's the key weakness?

---

## Snippet E — Struct field access pattern (RE exam level)

```asm
; entry: RCX = void* some_struct
get_info proc
    push    rbx
    sub     rsp, 20h
    mov     rbx, rcx
    mov     eax, [rbx]           ; field at offset 0
    test    eax, eax
    jz      fail
    cmp     eax, 0DEADh
    jne     fail
    movzx   ecx, word ptr [rbx+4]    ; field at offset 4
    movzx   edx, word ptr [rbx+6]    ; field at offset 6
    imul    ecx, edx
    mov     [rbx+8], ecx             ; field at offset 8
    mov     rcx, [rbx+16]            ; field at offset 16
    call    qword ptr [rbx+24]       ; field at offset 24 — what type?
    mov     eax, 1
    add     rsp, 20h
    pop     rbx
    ret
fail:
    xor     eax, eax
    add     rsp, 20h
    pop     rbx
    ret
get_info endp
```

**Questions:**
1. Write the C struct with correct field types and offsets.
2. What is at offset 24? What does `call qword ptr [rbx+24]` mean?
3. What is the magic value check for? Where have you seen this pattern?
4. When does the function return 0 vs 1?

---

## Answers (after you attempt each)

See `../solutions/sol01_read_disasm_answers.md`
