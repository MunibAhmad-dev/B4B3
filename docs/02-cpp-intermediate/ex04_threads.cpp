/*
  Exercise 04 — Threads and Mutex
  ---------------------------------
  Build a producer/consumer system that simulates a keylogger + exfiltrator.

  Tasks:
  1. Shared state:
       - std::string keyBuffer  (the collected keystrokes)
       - std::mutex  keyMtx     (protects keyBuffer)
       - std::atomic<bool> running (controls both threads)

  2. Thread 1 — "keylogger":
       Runs in a loop while running == true.
       Every 200ms: appends a random letter (A-Z) to keyBuffer (locked).
       Prints "[keylog] appended: X" each time.

  3. Thread 2 — "exfiltrator":
       Runs in a loop while running == true.
       Every 1000ms: locks keyMtx, takes a COPY of keyBuffer, clears keyBuffer,
       unlocks, then prints "[exfil] sending: <copied_data>".

  4. In main():
       Start both threads.
       Sleep for 5 seconds.
       Set running = false.
       Join both threads.
       Print "Done."

  Expected behaviour: keylogger accumulates ~5 chars per second,
  exfiltrator drains it every second.

  Compile: g++ -std=c++17 -Wall -o ex04.exe ex04_threads.cpp -lpthread
  (on Windows with MinGW, -lpthread may not be needed)
*/

#include <iostream>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <string>
#include <cstdlib>

// YOUR CODE HERE

int main() {
    // YOUR CODE HERE
    return 0;
}
