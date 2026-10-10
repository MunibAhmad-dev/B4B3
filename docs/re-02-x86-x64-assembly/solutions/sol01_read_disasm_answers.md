# Solution 1: Disassembly Reading Answers

## Snippet A

**C equivalent:**
```c
size_t strlen(const char* s) {
    size_t len = 0;
    if (!s) return 0;
    while (s[len]) len++;
    return len;
}
```
- RCX = `const char* s` (arg1)
- RAX = return value (length)
- Standard C library function: `strlen`
- Pattern: null-check, then loop incrementing counter until null byte found

---

## Snippet B

**C equivalent:**
```c
int is_subset(int a, int b) {
    return (a & b) == b;
}
```
- `sete al` sets AL=1 if ZF=1, else 0 — it's a conditional set, not a jump
- Tests: is every set bit in `b` also set in `a`? (b is a bitmask, a is the value)
- In malware: checking if a flags/capabilities field has specific bits set
- Example: `if ((perm_flags & REQUIRED_FLAGS) == REQUIRED_FLAGS)`

---

## Snippet C

**C struct and function:**
```c
struct Node {
    // offset 0: some data (used by process_node)
    // offset 8: Node* next  ← this is what [rbx+8] reads
};

void traverse(Node* head) {
    if (!head) return;
    Node* cur = head;
    do {
        process_node(cur);
        cur = cur->next;     // [rbx+8] = ->next pointer
    } while (cur);
}
```
- Data structure: **singly linked list**
- Field at +8: `Node* next` (pointer, 8 bytes)
- `sub rsp, 20h` = 32-byte shadow space required by x64 Windows calling convention
  before calling `process_node`

---

## Snippet D

**C implementation:**
```c
void encode(uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        buf[i] += (uint8_t)i;
}

void decode(uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        buf[i] -= (uint8_t)i;   // reverse: subtract instead of add
}
```
- NOT a real encryption algorithm — no secret key, easily reversible
- Key weakness: the "key" is predictable (the index itself)
- Used in simple obfuscation to hide strings or payloads in malware
- Decode: subtract the same index value from each byte

---

## Snippet E

**C struct:**
```c
struct InfoBlock {
    uint32_t magic;         // offset 0   — must be 0xDEAD
    // 2 bytes implicit alignment
    uint16_t width;         // offset 4
    uint16_t height;        // offset 6
    uint32_t area;          // offset 8   — written by function
    // 4 bytes padding
    void*    context;       // offset 16  — loaded, passed to callback
    void (*callback)(void*); // offset 24  — function pointer!
};

int get_info(InfoBlock* blk) {
    if (!blk) return 0;
    if (blk->magic != 0xDEAD) return 0;
    blk->area = (uint32_t)blk->width * blk->height;
    blk->callback(blk->context);
    return 1;
}
```

- Offset 24 is a **function pointer** — `call qword ptr [rbx+24]` dereferences it
  and calls whatever function it points to. This is how plugin/hook architectures work.
- The `0xDEAD` check is a **magic number validation** — common in file formats,
  network protocols, and struct-based C APIs to verify the struct is valid/initialized.
- Returns 0 on: null ptr, wrong magic. Returns 1 on success.
- The magic pattern appears in PE headers (0x5A4D "MZ"), network packets, config blobs.
