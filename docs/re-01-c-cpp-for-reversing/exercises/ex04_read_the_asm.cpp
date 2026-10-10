// Exercise 4: Read the Assembly — RE Drills
// Goal: given obfuscated/compiled-looking C code, produce the assembly mentally,
//       then verify by compiling with /FA or -S.
//
// TASKS:
//  For each function below:
//    A) Write out the expected x64 assembly (pseudocode is fine, use the mnemonics)
//    B) Compile in release mode and compare your prediction to real output
//    C) Answer the question in the comment above each function
//
// COMPILE: cl /O2 /FA /std:c++17 ex04_read_the_asm.cpp
//   (GCC): g++ -O2 -S -masm=intel ex04_read_the_asm.cpp

#include <cstdint>
#include <cstdio>
#include <cstring>

// QUESTION: What is this function doing? What's the pattern?
// Hint: look at the return value computation.
uint32_t mystery_a(const char* s) {
    uint32_t h = 0x811C9DC5u;
    while (*s) {
        h ^= (uint8_t)*s++;
        h *= 0x01000193u;
    }
    return h;
}

// QUESTION: Is there a branch in the assembly? What optimization happens?
int mystery_b(int x) {
    return (x > 0) ? x : -x;
}

// QUESTION: How many instructions does the loop become in release mode?
//           (hint: loop unrolling / vectorization)
void mystery_c(uint8_t* buf, size_t len, uint8_t key) {
    for (size_t i = 0; i < len; i++)
        buf[i] ^= key;
}

// QUESTION: What kind of call does this generate? Why is that important for RE?
typedef void (*LogFn)(const char*);
void mystery_d(LogFn logger, const char* msg) {
    if (logger) logger(msg);
}

// QUESTION: Describe the stack layout after the prologue.
//           Where does `local` live relative to RBP/RSP?
uint64_t mystery_e(uint64_t input) {
    uint64_t local = input ^ 0xDEADC0DEu;
    local = (local << 13) | (local >> 51);
    local ^= 0xBAADF00Du;
    return local;
}

// QUESTION: This touches the PEB. How? What register holds it in x64?
//           (compile and look for GS: prefix)
#ifdef _WIN32
#include <windows.h>
uintptr_t mystery_f() {
    // returns address of the Process Environment Block
    return (uintptr_t)NtCurrentTeb()->ProcessEnvironmentBlock;
}
#endif

int main() {
    printf("mystery_a(\"hello\") = 0x%08X\n", mystery_a("hello"));
    printf("mystery_b(-42)     = %d\n",       mystery_b(-42));

    uint8_t buf[16];
    memset(buf, 0xAA, sizeof(buf));
    mystery_c(buf, sizeof(buf), 0x42);
    printf("mystery_c result[0]= 0x%02X (expected 0xE8)\n", buf[0]);

    mystery_d(nullptr, "silent");
    mystery_d([](const char* s){ printf("logged: %s\n", s); }, "test");

    printf("mystery_e(1)       = 0x%016llX\n", (unsigned long long)mystery_e(1));

#ifdef _WIN32
    printf("mystery_f (PEB)    = 0x%016llX\n", (unsigned long long)mystery_f());
#endif

    return 0;
}
