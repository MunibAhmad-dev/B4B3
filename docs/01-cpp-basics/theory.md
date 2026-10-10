# Module 01 — C++ Basics

## 1. Why C++ for security?

C++ compiles to native machine code. There is no virtual machine, no runtime
interpreter between your code and the CPU. This means:

- You control **exactly** what instructions run.
- You control **exactly** what memory is allocated and when it is freed.
- You can call Windows APIs directly by name — no wrappers.
- The produced binary has no external dependency on Python, Java, .NET, etc.

These properties are why every serious implant, RAT, and AV engine is written
in C or C++.

---

## 2. Compilation model

A C++ program goes through these stages:

```
Source (.cpp)
    ↓  Preprocessor   — #include, #define, #ifdef resolved
    ↓  Compiler        — C++ → object file (.o / .obj)
    ↓  Linker          — object files + libraries → executable (.exe)
```

Understanding this matters for security because:
- **Static analysis** (AV scanning) runs on the final linked binary.
- Knowing what the linker includes lets you control the binary's content.
- `#include <windows.h>` pulls in Win32 API declarations only — the actual
  code lives in `kernel32.dll` and is linked at load time.

---

## 3. Your first program

```cpp
#include <iostream>   // declares std::cout, std::cin

int main() {
    std::cout << "Hello\n";
    return 0;         // 0 = success, any other value = error code
}
```

Compile:
```
g++ -o hello.exe hello.cpp
```

Run:
```
hello.exe
```

`main()` is the entry point for **console** programs.
`WinMain()` is the entry point for **GUI** (windowless) programs — you will
use this for every RAT stub so no console window appears.

---

## 4. Variables and types

```cpp
int    a = 10;       // 32-bit signed integer
long   b = 100L;     // 32-bit on Windows (same as int in MSVC/MinGW)
long long c = 100LL; // 64-bit signed integer  ← use this for large numbers
unsigned int d = 5u; // 32-bit unsigned (no negatives)
float  f = 3.14f;    // 32-bit floating point
double g = 3.14;     // 64-bit floating point
char   h = 'A';      // 8-bit character (ASCII value 65)
bool   ok = true;    // true or false
```

**Windows-specific types** (defined in `<windows.h>`):
```cpp
DWORD   = unsigned long  (32-bit, used everywhere in Win32)
HANDLE  = void*          (opaque pointer to a kernel object)
BOOL    = int            (TRUE = 1, FALSE = 0 — NOT the same as bool)
LPSTR   = char*          (pointer to char string)
LPWSTR  = wchar_t*       (pointer to wide string)
BYTE    = unsigned char  (8-bit, used for raw byte buffers)
```

---

## 5. Operators

```cpp
// Arithmetic
int x = 5 + 3;   // 8
int y = 10 % 3;  // 1  (modulo / remainder)

// Comparison — returns bool
bool eq  = (x == 8);   // true
bool neq = (x != 7);   // true
bool gt  = (x > 3);    // true

// Logical
bool both = (x > 3) && (y < 5);  // AND
bool either = (x > 3) || (y > 5); // OR
bool inv = !(x == 8);              // NOT

// Bitwise — critical for security work
BYTE flags = 0b00001010;
flags |= 0x04;   // set bit 2  → 0b00001110
flags &= ~0x02;  // clear bit 1 → 0b00001100
flags ^= 0x08;   // toggle bit 3
bool set = (flags & 0x04) != 0;  // test if bit 2 is set
```

Bitwise ops appear constantly in:
- PE header parsing (characteristics flags)
- Network protocol parsing
- Obfuscation (XOR encryption)

---

## 6. Control flow

```cpp
// if / else
if (x > 5) {
    // ...
} else if (x == 5) {
    // ...
} else {
    // ...
}

// for loop — run N times
for (int i = 0; i < 10; i++) {
    // i goes 0, 1, 2 ... 9
}

// while loop — run while condition is true
int count = 0;
while (count < 5) {
    count++;
}

// do-while — always runs at least once
do {
    count--;
} while (count > 0);

// switch
switch (x) {
    case 1:  /* ... */ break;
    case 2:  /* ... */ break;
    default: /* ... */ break;
}
```

---

## 7. Functions

A function is a named block of reusable code.

```cpp
// Declaration (tells compiler the function exists)
int add(int a, int b);

// Definition (the actual code)
int add(int a, int b) {
    return a + b;
}

int main() {
    int result = add(3, 4);  // result = 7
}
```

**Return types matter:**
- `void` = returns nothing
- `int` = returns a 32-bit integer
- `bool` = returns true/false
- `char*` = returns a pointer to a string

**Parameters are copied by default:**
```cpp
void doubleIt(int x) {
    x = x * 2;  // modifies the COPY, not the original
}
```

To modify the original, pass by **reference** or **pointer** (Module 01 covers
pointers below).

---

## 8. Pointers — the most important concept in C++

A pointer is a variable that stores a **memory address**.

```
Memory:
Address  Value
0x1000   42      ← int x = 42;
0x1004   0x1000  ← int* p = &x;  (p holds the address of x)
```

```cpp
int x = 42;
int* p = &x;     // & = "address of"

// Read through pointer (dereference)
int val = *p;    // val = 42

// Write through pointer
*p = 100;        // x is now 100

// Pointer arithmetic
int arr[3] = {10, 20, 30};
int* ap = arr;   // points to arr[0]
ap++;            // now points to arr[1]
int second = *ap; // = 20
```

**Why pointers matter for security:**
- All Win32 API functions pass data through pointers or handles.
- Buffer overflows exploit pointer arithmetic going wrong.
- Shellcode is raw bytes at a memory address — you call it via a function pointer.
- Understanding pointers lets you read and write arbitrary memory.

**NULL pointer:**
```cpp
int* p = nullptr;  // points to address 0 = nothing
if (p != nullptr) {
    *p = 5;  // only safe to dereference if not null
}
```

Dereferencing a null pointer crashes the process. Always check before
dereferencing a pointer you received from outside your code.

---

## 9. Arrays and strings

```cpp
// Fixed-size array
int nums[5] = {1, 2, 3, 4, 5};
int n = nums[2];       // = 3 (0-indexed)
int sz = sizeof(nums) / sizeof(nums[0]);  // = 5

// C-style string (null-terminated char array)
char name[32] = "Alice";
// Memory: ['A','l','i','c','e','\0', ...]
//                               ^^^^ null terminator

// String length
#include <cstring>
size_t len = strlen(name);  // = 5 (not counting \0)

// C++ std::string (much easier)
#include <string>
std::string s = "Hello";
s += " World";
size_t l = s.length();     // = 11
const char* raw = s.c_str(); // get raw C pointer when Win32 API needs it
```

**Security note:** C-style strings are dangerous because `strcpy`, `gets`,
`sprintf` don't check buffer bounds. Buffer overflows happen when you write
more bytes than the array can hold. Always use `strncpy`, `snprintf`, or
`std::string`.

---

## 10. The Stack and the Heap

Every C++ program has two regions of memory for your data:

**Stack:**
- Local variables live here.
- Allocated automatically when a function is called.
- Freed automatically when the function returns.
- Fast, but limited size (~1–8 MB typical).

```cpp
void foo() {
    int x = 5;      // on the stack
    char buf[256];  // also on the stack
}  // x and buf are gone after foo() returns
```

**Heap:**
- Memory you allocate manually with `new` / `delete`.
- Persists until you explicitly free it.
- Large (limited only by available RAM).
- Slower to allocate than stack.

```cpp
int* p = new int(42);   // allocate one int on heap
int* arr = new int[100]; // allocate array of 100 ints

*p = 100;
arr[5] = 99;

delete p;      // free single object
delete[] arr;  // free array — must use []
p = nullptr;   // good habit: nullify after delete
```

**Memory leak:** forgetting to `delete` causes the memory to stay allocated
forever (until the process exits). In a long-running implant this causes the
process to slowly eat RAM.

---

## Exercises

See the exercise files in this folder. Attempt each one before reading solutions.

- `ex01_variables_types.cpp` — variables, types, sizeof
- `ex02_control_flow.cpp` — loops, conditions
- `ex03_functions.cpp` — write and call functions
- `ex04_pointers.cpp` — pointer read/write, arrays
- `ex05_strings.cpp` — C-string and std::string manipulation
