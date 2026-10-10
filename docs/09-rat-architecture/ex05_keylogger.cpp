/*
  Exercise 05 — Low-Level Keyboard Hook Keylogger
  --------------------------------------------------
  Tasks:
  1. Write a global:
       std::string     g_keyBuffer;
       std::mutex      g_keyMtx;

  2. Write the hook callback: LRESULT CALLBACK LLKeyProc(int, WPARAM, LPARAM)
     When nCode == HC_ACTION and wParam == WM_KEYDOWN:
       - Get KBDLLHOOKSTRUCT from lParam
       - Convert vkCode to a character:
           Printable ASCII (0x20-0x7E): use MapVirtualKeyA + GetKeyboardState + ToAscii
           Special keys: produce tokens like [ENTER], [BACKSPACE], [TAB], [SPACE],
                         [CTRL], [ALT], [WIN], [DEL], [F1]..[F12], [LEFT][RIGHT]etc.
           Arrow keys / nav: [UP], [DOWN], [LEFT], [RIGHT], [HOME], [END], etc.
       - Lock g_keyMtx and append to g_keyBuffer

  3. Write: void startKeylogger(std::atomic<bool>& running)
     Sets the hook: SetWindowsHookEx(WH_KEYBOARD_LL, LLKeyProc, nullptr, 0)
     Runs the message loop: while(running) { GetMessage(&msg...) + Translate+Dispatch }
     Must run in its own thread (the message loop blocks).

  4. In main():
     Start keylogger in a background thread.
     Sleep 15 seconds (while you type some text).
     Set running=false.
     Join the thread.
     Print "Captured: " + g_keyBuffer.

  5. (Harder) Add window context:
     In the hook callback, also call GetForegroundWindow() + GetWindowTextA()
     to log which window was active when each key was pressed.
     Format: "[Window: Notepad] hello world [Window: Chrome] google search"

  IMPORTANT: Unhook with UnhookWindowsHookEx() when done.
  NOT unhooking causes the system to become sluggish.

  Compile:
    g++ -std=c++17 -Wall -o ex05.exe ex05_keylogger.cpp -lkernel32 -luser32
*/

#include <windows.h>
#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>

// YOUR CODE HERE

int main() {
    std::cout << "Keylogger starting — type something for 15 seconds...\n";
    // YOUR CODE HERE
    return 0;
}
