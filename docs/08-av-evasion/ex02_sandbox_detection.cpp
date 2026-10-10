/*
  Exercise 02 — Sandbox Detection Score
  ----------------------------------------
  Build a function that scores the environment and returns a confidence
  value: 0 = likely real machine, 100 = almost certainly a sandbox.

  Tasks:
  1. Write individual check functions, each returning bool (true = sandbox indicator):

       bool checkHal9th()          — computer name is "HAL9TH"
       bool checkLowRam()          — total RAM < 2 GB
       bool checkFewProcesses()    — running process count < 30
       bool checkSmallScreen()     — screen < 1024x768
       bool checkHypervisor()      — CPUID hypervisor bit set
       bool checkSleepSkipped()    — 500ms sleep takes < 250ms (QPC)
       bool checkFewCPUs()         — GetSystemInfo logical processor count < 2
       bool checkSuspiciousUser()  — username is "user", "admin", or "administrator"

  2. Write: int sandboxScore()
     Runs all checks. Each true check adds points (weight them by how reliable
     each check is). Returns total 0-100.
     Suggested weights:
       HAL9TH check:     40 (very reliable, rarely false positive)
       low RAM:          15
       few processes:    15
       small screen:     10
       hypervisor bit:   10 (may false-positive on real VMs)
       sleep skipped:    25
       few CPUs:         10
       suspicious user:  10
     Cap at 100.

  3. In main():
     Print each check result (true/false).
     Print the total score.
     If score >= 50, print "SANDBOX DETECTED — exiting" and call ExitProcess(0).
     Otherwise print "Clean environment — proceeding."

  4. Run this on your real machine — what score do you get?
     Run inside a VM — what score do you get?

  Compile (requires Windows):
    g++ -std=c++17 -Wall -O2 -o ex02.exe ex02_sandbox_detection.cpp -lkernel32 -luser32
*/

#include <windows.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <iostream>
#include <string>
#include <algorithm>

// YOUR CODE HERE

int main() {
    // YOUR CODE HERE
    return 0;
}
