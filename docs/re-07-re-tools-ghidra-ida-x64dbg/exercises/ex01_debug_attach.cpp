// ex01_debug_attach.cpp — attach to a process as a debugger
// TODO 1: DebugActiveProcess(pid)
// TODO 2: WaitForDebugEvent loop — handle CREATE_PROCESS_DEBUG_EVENT, EXCEPTION_DEBUG_EVENT
// TODO 3: On EXCEPTION_BREAKPOINT, print "BP hit at 0x<addr>", then ContinueDebugEvent
// TODO 4: Single-step 10 instructions using CONTEXT.EFlags |= 0x100 (TF bit) +
//          SetThreadContext, then EXCEPTION_SINGLE_STEP handler
// Compile: g++ -std=c++17 -o ex01.exe ex01_debug_attach.cpp
// Usage: ex01.exe <pid>
#include <windows.h>
#include <stdio.h>
int main(int argc, char* argv[]) {
    if(argc<2){printf("Usage: ex01.exe <pid>\n");return 1;}
    printf("Debug attach exercise — implement TODOs for PID %s\n", argv[1]);
    return 0;
}
