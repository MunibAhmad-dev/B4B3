# Module 03 — C++ Advanced

## 1. Templates

A template lets you write code that works with any type.

```cpp
template <typename T>
T maxOf(T a, T b) {
    return (a > b) ? a : b;
}

maxOf(3, 5);          // T = int
maxOf(3.14, 2.71);    // T = double
maxOf('A', 'Z');      // T = char
```

**Template classes** — used for containers like `vector<T>`:

```cpp
template <typename T>
class Ring {
    T _data[16];
    int _head = 0, _tail = 0;
public:
    void push(const T& val) { _data[_head++ % 16] = val; }
    T    pop()               { return _data[_tail++ % 16]; }
};

Ring<int>         intRing;
Ring<std::string> strRing;
```

**Why this matters for security:** The obfuscation macro `S("string")` in the
existing codebase is essentially a template trick — it generates a different
XOR-decode sequence at compile time for every string. Templates let AV evasion
logic be evaluated at compile time with zero runtime overhead.

---

## 2. constexpr and Compile-time evaluation

`constexpr` means the value is computed at compile time — no runtime cost, and
the result is embedded directly as a constant in the binary.

```cpp
constexpr int XOR_KEY = 0x5A;

constexpr char encChar(char c) {
    return c ^ XOR_KEY;
}

// Evaluated at compile time — no function call in the binary
constexpr char enc_A = encChar('A');  // = 'A' ^ 0x5A = 0x1B
```

**String obfuscation with constexpr:**

```cpp
template <size_t N>
struct ObfStr {
    char data[N];
    constexpr ObfStr(const char (&s)[N]) {
        for (size_t i = 0; i < N; i++)
            data[i] = s[i] ^ 0x5A;
    }
    // decode at runtime
    std::string decode() const {
        std::string out(data, N - 1);
        for (char& c : out) c ^= 0x5A;
        return out;
    }
};

// The string "cmd.exe" never appears in plaintext in the binary:
constexpr ObfStr cmd("cmd.exe");
std::string s = cmd.decode();  // decoded only at runtime
```

This is exactly what the `S()` macro in the existing code does.

---

## 3. Move Semantics

Copying large objects (like `std::string`, `std::vector`) is slow because it
duplicates all the memory. **Move semantics** transfers ownership instead of copying.

```cpp
std::string big(1000000, 'A');  // 1MB string

// Copy — allocates 1MB and copies all bytes
std::string copy = big;

// Move — transfers ownership, big is now empty, no allocation
std::string moved = std::move(big);
// big.empty() == true after this
```

**When to use `std::move`:**
- Returning a local variable from a function (often automatic, called NRVO)
- Passing a temporary into a function that takes `&&` (rvalue reference)
- Storing data into a container when you no longer need the source

```cpp
void storeData(std::vector<char>& buffer, std::vector<char> data) {
    buffer = std::move(data);  // no copy — just pointer swap
}
```

---

## 4. Memory Layout — What the Linker Produces

Understanding the binary layout is core to security work.

```
PE File sections:
  .text   — compiled machine code (your functions)
  .rdata  — read-only data: string literals, vtables, const globals
  .data   — writable globals and statics
  .bss    — zero-initialized globals
  .rsrc   — resources (icon, version info, manifest)
  .idata  — import table (list of DLLs and functions used)
  .edata  — export table (functions this DLL exports)
  .reloc  — relocation table (for ASLR)
```

**Why `.rdata` matters for AV:**
Every string literal you write (`"SOFTWARE\\...\\Run"`, `"cmd.exe"`) lands in
`.rdata` verbatim. AV scanners grep `.rdata` for known strings. Obfuscation
moves the plaintext out of `.rdata` by XOR-encrypting at compile time and
decoding at runtime.

**Import table (`.idata`):**
Contains every DLL + function your binary calls. AV checks this for
"suspicious" API combinations:
- `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` = injection triad → flagged
- `NtMapViewOfSection` + `NtCreateThreadEx` → advanced injection → flagged

To hide API calls: resolve them at runtime using `GetProcAddress` so they
don't appear in the static import table.

---

## 5. Runtime API Resolution (Avoiding the Import Table)

```cpp
#include <windows.h>

// Declare function pointer type matching the API signature
typedef LPVOID (WINAPI *pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);

// At runtime, resolve the address:
HMODULE hKernel = GetModuleHandleA("kernel32.dll");
pVirtualAlloc myVirtualAlloc = (pVirtualAlloc)GetProcAddress(hKernel, "VirtualAlloc");

// Now call it:
if (myVirtualAlloc) {
    LPVOID mem = myVirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}
```

`GetModuleHandleA` + `GetProcAddress` will still appear in your import table,
but that is unavoidable unless you resolve those too via the PEB.

---

## 6. The PEB (Process Environment Block)

Every Windows process has a PEB — a data structure in memory that holds
information about the process. It contains the **loader data**, which is a
linked list of all loaded DLLs with their base addresses.

Walking the PEB lets you resolve API addresses without `GetProcAddress`
appearing in your import table at all:

```cpp
// PEB walk — x64 version
// FS register (x86) / GS register (x64) points to TEB (Thread Environment Block)
// TEB+0x60 = pointer to PEB
// PEB+0x18 = pointer to PEB_LDR_DATA
// PEB_LDR_DATA contains InMemoryOrderModuleList — walk it to find ntdll, kernel32

// This is an advanced technique — covered in Module 06 (Memory).
// For now, understand the concept: you can find any loaded DLL's base address
// without calling any Win32 API.
```

---

## 7. Function Pointers and Callbacks

Windows API uses callbacks extensively.

```cpp
// SetWindowsHookEx takes a callback function pointer for the keyboard hook:
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        KBDLLHOOKSTRUCT* ks = (KBDLLHOOKSTRUCT*)lParam;
        // ks->vkCode = virtual key code
    }
    return CallNextHookEx(nullptr, nCode, wParam, lParam);
}

HHOOK hook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, nullptr, 0);
```

The **callback signature must match exactly** — wrong parameter types cause
crashes or silent failures.

---

## Exercises

- `ex01_templates.cpp` — write a typed ring buffer, an XOR encrypt template
- `ex02_constexpr_obfuscation.cpp` — compile-time string obfuscation
- `ex03_memory_layout.cpp` — examine where different variables live in memory
- `ex04_function_pointers.cpp` — function pointer array as a command dispatch table
