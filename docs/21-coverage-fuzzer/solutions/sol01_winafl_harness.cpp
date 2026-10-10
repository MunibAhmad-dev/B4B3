/*
  Solution 01 — WinAFL Harness (Complete)
  ----------------------------------------
  Compile as DLL (WinAFL mode):
    cl /LD /std:c++17 /Zi sol01_winafl_harness.cpp /Fe:harness.dll

  Compile as EXE (standalone test):
    cl /std:c++17 /Zi sol01_winafl_harness.cpp /Fe:harness_test.exe
    g++ -std=c++17 -Wall -o harness_test.exe sol01_winafl_harness.cpp

  WinAFL usage (after installing DynamoRIO + WinAFL):
    afl-fuzz.exe -i corpus -o findings -t 5000 --
      drrun.exe -c winafl.dll -target_module harness.dll
      -target_offset <fuzz_RVA> -fuzz_iterations 1000
      -- harness_test.exe @@
*/

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <direct.h>   // _mkdir

// -------- Target struct & parser (provided — do NOT modify) --------
typedef struct {
    char method[16];
    char path[256];
    char host[128];
    char contentType[64];
    int  contentLength;
} HttpRequest;

static bool parseHttpHeader(const char* data, size_t len, HttpRequest* out) {
    if (!data || len == 0 || !out) return false;
    memset(out, 0, sizeof(*out));

    const char* p   = data;
    const char* end = data + len;

    // Parse "METHOD /path HTTP/1.x"
    char* dst = out->method;
    while (p < end && *p != ' ' && (dst - out->method) < 15) *dst++ = *p++;
    while (p < end && *p == ' ')  p++;
    dst = out->path;
    while (p < end && *p != ' ' && (dst - out->path) < 255) *dst++ = *p++;
    while (p < end && *p != '\n') p++;
    if (p < end) p++;   // skip newline

    // Parse header fields
    while (p < end) {
        if (*p == '\r' || *p == '\n') break;
        char line[512] = {};
        int  li = 0;
        while (p < end && *p != '\r' && *p != '\n' && li < 511)
            line[li++] = *p++;
        while (p < end && (*p == '\r' || *p == '\n')) p++;

        if (_strnicmp(line, "Host:", 5) == 0)
            strncpy_s(out->host, sizeof(out->host), line + 6, _TRUNCATE);
        else if (_strnicmp(line, "Content-Type:", 13) == 0)
            strncpy_s(out->contentType, sizeof(out->contentType), line + 14, _TRUNCATE);
        else if (_strnicmp(line, "Content-Length:", 15) == 0)
            out->contentLength = atoi(line + 16);
    }
    return true;
}
// -------- end target --------


// =========================================================
// 1. readFile — read an entire file into a heap buffer
// =========================================================
static char* readFile(const char* filename, size_t* outSize) {
    *outSize = 0;

    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFile(%s) failed: %lu\n", filename, GetLastError());
        return nullptr;
    }

    DWORD hi = 0;
    DWORD lo = GetFileSize(hFile, &hi);
    if (lo == INVALID_FILE_SIZE && GetLastError() != NO_ERROR) {
        CloseHandle(hFile);
        return nullptr;
    }

    size_t size = ((size_t)hi << 32) | lo;
    char*  buf  = (char*)malloc(size + 1);
    if (!buf) { CloseHandle(hFile); return nullptr; }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buf, lo, &bytesRead, nullptr) || bytesRead != lo) {
        free(buf);
        CloseHandle(hFile);
        return nullptr;
    }
    buf[size] = '\0';
    *outSize = size;

    CloseHandle(hFile);
    return buf;
}

// =========================================================
// 2. fuzz() — DLL export consumed by WinAFL
//    Reads the mutated input file and exercises parseHttpHeader.
// =========================================================
extern "C" __declspec(dllexport) int fuzz(const char* filename) {
    size_t size = 0;
    char*  data = readFile(filename, &size);
    if (!data) return 0;

    HttpRequest req;
    parseHttpHeader(data, size, &req);

    free(data);
    return 0;  // always 0 — crashes detected externally by WinAFL
}

// =========================================================
// 3. Persistent-mode variant (WINAFL_PERSISTENT build flag)
//    Avoids process-restart per test case — much faster.
//    Build:  cl /LD /DWINAFL_PERSISTENT /std:c++17 ...
// =========================================================
#ifdef WINAFL_PERSISTENT
extern "C" int __afl_persistent_loop(unsigned int max_cnt);

extern "C" __declspec(dllexport) int fuzz_persistent(const char* filename) {
    while (__afl_persistent_loop(1000)) {
        size_t size = 0;
        char*  data = readFile(filename, &size);
        if (data) {
            HttpRequest req;
            parseHttpHeader(data, size, &req);
            free(data);
        }
    }
    return 0;
}
#endif  // WINAFL_PERSISTENT


// =========================================================
// 4. Seed corpus generator
//    Creates corpus/ directory and writes 5 seed files.
// =========================================================
static void writeFileContents(const char* path, const char* data, size_t len) {
    HANDLE hf = CreateFileA(path, GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot create %s: %lu\n", path, GetLastError());
        return;
    }
    DWORD written = 0;
    WriteFile(hf, data, (DWORD)len, &written, nullptr);
    CloseHandle(hf);
    printf("[+] Created corpus file: %s (%lu bytes)\n", path, written);
}

static void createSeedCorpus() {
    _mkdir("corpus");

    // 01 — valid GET request
    const char* valid =
        "GET /index.html HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 0\r\n"
        "\r\n";
    writeFileContents("corpus/01_valid.txt", valid, strlen(valid));

    // 02 — long header value (8192-byte X-Custom)
    {
        std::string longReq =
            "POST /upload HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "X-Custom: ";
        longReq += std::string(8192, 'A');
        longReq += "\r\nContent-Length: 0\r\n\r\n";
        writeFileContents("corpus/02_long.txt",
                          longReq.c_str(), longReq.size());
    }

    // 03 — missing CRLF terminator
    const char* noCrlf = "GET /path HTTP/1.0\r\nHost: noeol.com";
    writeFileContents("corpus/03_no_crlf.txt", noCrlf, strlen(noCrlf));

    // 04 — binary / random bytes (edge-case coverage)
    {
        unsigned char binary[64];
        for (int i = 0; i < 64; i++) binary[i] = (unsigned char)i;
        binary[0] = 'G'; binary[1] = 'E'; binary[2] = 'T'; binary[3] = ' ';
        writeFileContents("corpus/04_binary.txt",
                          (const char*)binary, sizeof(binary));
    }

    // 05 — UTF-8 multi-byte sequences in header value
    const char* unicode =
        "GET /utf8 HTTP/1.1\r\n"
        "Host: \xC3\xA9xample.com\r\n"   // é in UTF-8
        "X-Lang: \xE4\xB8\xAD\xE6\x96\x87\r\n"  // 中文
        "\r\n";
    writeFileContents("corpus/05_unicode.txt", unicode, strlen(unicode));
}


// =========================================================
// Standalone test entry point
// =========================================================
#ifndef _USRDLL   // only compile main when building as EXE

#include <string>

int main(int argc, char* argv[]) {
    printf("[*] WinAFL Harness — standalone test mode\n");

    // Create seed corpus if it doesn't exist yet
    createSeedCorpus();

    // If a specific file was given, test that
    if (argc > 1) {
        printf("\n[*] Testing with provided file: %s\n", argv[1]);
        int rc = fuzz(argv[1]);
        printf("[*] fuzz() returned %d (0 = OK)\n", rc);
        return rc;
    }

    // Otherwise exercise all 5 corpus seeds
    const char* seeds[] = {
        "corpus/01_valid.txt",
        "corpus/02_long.txt",
        "corpus/03_no_crlf.txt",
        "corpus/04_binary.txt",
        "corpus/05_unicode.txt",
    };

    printf("\n[*] Running all corpus seeds:\n");
    for (const char* seed : seeds) {
        printf("  %-30s  -> ", seed);
        fuzz(seed);
        printf("OK (no crash)\n");
    }

    printf("\n[*] All tests passed — no crashes detected.\n");
    printf("[*] Ready for WinAFL.  Build DLL with: cl /LD /std:c++17 sol01_winafl_harness.cpp\n");
    return 0;
}

#endif  // _USRDLL
