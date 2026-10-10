// Exercise 3: Calling Conventions & Stack Frames
// Goal: observe how different calling conventions affect the stack and registers.
//
// TASKS:
//  1. Compile in RELEASE mode and open the binary in x64dbg or view with /Fa in MSVC.
//     Find each function call site and verify register usage matches the theory.
//  2. Implement read_shadow_space() to print the 32-byte shadow home space.
//  3. Write a function with 6+ parameters. Observe where args 5+ land on the stack.
//  4. Add a __declspec(noinline) to each function and compare the generated code
//     vs without it (inlining removes the call).
//
// COMPILE (MSVC release):  cl /O2 /FA /std:c++17 ex03_calling_conventions.cpp
//   /FA generates ex03_calling_conventions.asm alongside — read it!
// COMPILE (GCC):           g++ -O2 -S -masm=intel -std=c++17 ex03_calling_conventions.cpp

#include <cstdio>
#include <cstdint>

// Prevent inlining so calls appear in disasm
#if defined(_MSC_VER)
  #define NOINLINE __declspec(noinline)
#else
  #define NOINLINE __attribute__((noinline))
#endif

// -- 4 args: all in registers (RCX, RDX, R8, R9) --
NOINLINE int add_four(int a, int b, int c, int d) {
    return a + b + c + d;
}

// -- 6 args: first 4 in regs, args 5+6 on stack --
NOINLINE int add_six(int a, int b, int c, int d, int e, int f) {
    return a + b + c + d + e + f;
}

// -- Returns struct (> 8 bytes): hidden pointer in RCX --
struct BigResult {
    uint64_t lo;
    uint64_t hi;
};
NOINLINE BigResult make_big(uint64_t v) {
    return { v, v ^ 0xDEADBEEFDEADBEEFULL };
}

// -- Function pointer (indirect call) --
typedef int (*BinaryOp)(int, int);
NOINLINE int apply(BinaryOp op, int x, int y) {
    return op(x, y);           // generates: call rax (or call [rbp+N])
}
NOINLINE int multiply(int a, int b) { return a * b; }

// -- Shadow space demo --
// On x64 Windows, caller reserves 32 bytes of shadow space BEFORE the call.
// The callee can write its register args there (but doesn't have to).
// This function reads its own shadow space to demonstrate.
NOINLINE void read_shadow_space(int a, int b, int c, int d) {
    // The shadow space for our args (a=RCX,b=RDX,c=R8,d=R9) is at
    // [rsp+8], [rsp+16], [rsp+24], [rsp+32] from caller's perspective.
    // Inside this function, after prologue, they're accessible as locals.
    // TODO: use inline asm (MSVC __asm or GCC __asm__) to read RSP
    //       and print the values at shadow offsets.
    printf("a=%d b=%d c=%d d=%d (shadow space demo — see asm output)\n", a, b, c, d);
}

int main() {
    printf("add_four(1,2,3,4)     = %d\n", add_four(1, 2, 3, 4));
    printf("add_six(1,2,3,4,5,6)  = %d\n", add_six(1, 2, 3, 4, 5, 6));

    BigResult r = make_big(0x1122334455667788ULL);
    printf("make_big lo=0x%016llX hi=0x%016llX\n",
           (unsigned long long)r.lo, (unsigned long long)r.hi);

    BinaryOp op = multiply;
    printf("apply(multiply,7,6)   = %d\n", apply(op, 7, 6));

    read_shadow_space(10, 20, 30, 40);

    return 0;
}
