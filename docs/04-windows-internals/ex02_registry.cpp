/*
  Exercise 02 — Registry
  ----------------------
  Build a persistence helper exactly as a real RAT uses it.

  Tasks:
  1. Write: bool SetRunKey(const char* valueName, const char* exePath)
     Writes valueName=exePath under:
       HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
     Use RegOpenKeyExA + RegSetValueExA.
     Return true on success.

  2. Write: bool DeleteRunKey(const char* valueName)
     Deletes the named value from the Run key.
     Return true on success.

  3. Write: bool RunKeyExists(const char* valueName)
     Returns true if the value exists.
     Use RegQueryValueExA to check — if it returns ERROR_SUCCESS, the value exists.

  4. Write: std::string GetRunKeyValue(const char* valueName)
     Returns the current value (the exe path string) or empty string if missing.

  5. In main():
     - Get the path to the current executable with GetModuleFileNameA()
     - Call SetRunKey("TestPersistence", <exe path>)
     - Check RunKeyExists returns true
     - Print GetRunKeyValue
     - Call DeleteRunKey("TestPersistence")
     - Check RunKeyExists returns false

  Verify with regedit: HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  You should see the key appear and disappear.

  Compile:
    g++ -std=c++17 -Wall -o ex02.exe ex02_registry.cpp -ladvapi32
*/

#include <windows.h>
#include <iostream>
#include <string>

// YOUR CODE HERE

int main() {
    // YOUR CODE HERE
    return 0;
}
