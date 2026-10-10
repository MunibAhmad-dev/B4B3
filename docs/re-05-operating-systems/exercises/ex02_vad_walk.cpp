// ex02_vad_walk.cpp — walk own virtual address space with VirtualQuery
// TODO 1: Loop VirtualQueryEx on current process; print each committed region:
//         Base, Size, Type, Protect, State.
// TODO 2: For each MEM_COMMIT region, read first 2 bytes; flag if == 'MZ'.
// TODO 3: Count total committed, free, and reserved bytes and print a summary.
// Compile: g++ -std=c++17 -o ex02.exe ex02_vad_walk.cpp
#include <windows.h>
#include <stdio.h>
int main() {
    printf("VAD walk exercise — implement TODOs\n");
    return 0;
}
