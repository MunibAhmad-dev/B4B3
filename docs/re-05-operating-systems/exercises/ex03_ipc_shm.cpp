// ex03_ipc_shm.cpp — shared-memory IPC with event synchronization
// Run two instances: ex03.exe producer | ex03.exe consumer
// TODO: Producer writes a message to shared memory, sets event.
//       Consumer waits on event, reads message, clears it.
// Compile: g++ -std=c++17 -o ex03.exe ex03_ipc_shm.cpp
#include <windows.h>
#include <stdio.h>
#include <string>
int main(int argc, char* argv[]) {
    printf("IPC shared-memory exercise — implement TODOs\n  Mode: %s\n",
           argc>1?argv[1]:"(none)");
    return 0;
}
