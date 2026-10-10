/*
  Exercise 01 — Classes and OOP
  --------------------------------
  Build a simple RAT command queue system.

  Tasks:
  1. Create an abstract base class Command with:
       - pure virtual: string name()
       - pure virtual: void execute()
       - virtual destructor (always add this to base classes)

  2. Create three derived classes:
       - ListProcessesCmd   — execute() prints "Listing processes..."
       - ScreenshotCmd      — execute() prints "Capturing screenshot..."
       - ShellCmd(string)   — stores a command string, execute() prints "Running: <cmd>"

  3. Create a class CommandQueue with:
       - private: vector<Command*> _queue
       - void enqueue(Command* cmd)
       - void runAll()   — calls execute() on each, then deletes it and removes from queue
       - size_t size()

  4. In main():
       Create a CommandQueue.
       Enqueue: ListProcessesCmd, ScreenshotCmd, ShellCmd("whoami"), ShellCmd("ipconfig").
       Print queue size.
       Call runAll().
       Print queue size again (should be 0).

  Bonus: rewrite using std::unique_ptr<Command> instead of raw pointers.

  Compile: g++ -std=c++17 -Wall -o ex01.exe ex01_classes_oop.cpp
*/

#include <iostream>
#include <vector>
#include <string>

// YOUR CODE HERE

int main() {
    // YOUR CODE HERE
    return 0;
}
