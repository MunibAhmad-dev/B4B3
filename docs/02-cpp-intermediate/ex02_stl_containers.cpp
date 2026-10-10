/*
  Exercise 02 — STL Containers
  --------------------------------
  Simulate a process list like a real RAT would collect.

  Tasks:
  1. Define a struct ProcessEntry { int pid; string name; string path; }.
     Manually create a vector of 6 ProcessEntry objects (made-up process names are fine).

  2. Sort the vector alphabetically by name using std::sort and a lambda comparator.
     Print the sorted list as: PID | NAME | PATH

  3. Build a std::map<int, ProcessEntry> indexed by PID from the same data.
     Look up PID 1234 (or whatever PID you gave "explorer.exe") and print it.
     Attempt to look up PID 9999 — handle the case where it doesn't exist.

  4. Build an std::unordered_map<string, int> of name -> pid.
     Given a list of target process names: {"wireshark.exe","procmon.exe","x64dbg.exe"}
     Check if any of them are in your process map.
     Print "FOUND: <name> (pid <pid>)" or "NOT FOUND: <name>".
     (This is exactly what AntiProcesses() does in Protector.cpp.)

  Compile: g++ -std=c++17 -Wall -o ex02.exe ex02_stl_containers.cpp
*/

#include <iostream>
#include <vector>
#include <map>
#include <unordered_map>
#include <algorithm>
#include <string>

struct ProcessEntry {
    int pid;
    std::string name;
    std::string path;
};

int main() {
    // Task 1
    std::vector<ProcessEntry> processes = {
        // Fill in 6 entries
        // YOUR CODE HERE
    };

    // Task 2
    // YOUR CODE HERE

    // Task 3
    // YOUR CODE HERE

    // Task 4
    std::vector<std::string> targets = {"wireshark.exe", "procmon.exe", "x64dbg.exe"};
    // YOUR CODE HERE

    return 0;
}
