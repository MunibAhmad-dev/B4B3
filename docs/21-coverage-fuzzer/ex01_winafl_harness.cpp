/*
  Exercise 01 — WinAFL Harness
  -----------------------------
  AFL (and WinAFL on Windows) fuzz a target by running a "harness" —
  a function that accepts mutated input and exercises the target code.

  Your target library: a simple HTTP header parser (provided below as
  parseHttpHeader). In real engagements your target would be a DLL from
  a browser, PDF reader, image codec, etc.

  WinAFL requires the harness to be a DLL export named "fuzz" with this
  exact signature:
    __declspec(dllexport) int fuzz(const char* filename)

  The harness:
    1. Reads the file at `filename` into a buffer.
    2. Calls the target function with that buffer.
    3. Returns 0 (always — crashes are detected by WinAFL externally).

  Tasks:
  1. Implement readFile(filename) → returns a heap buffer + size.
  2. Implement the fuzz() DLL export — read the file, call parseHttpHeader.
  3. Write a persistent-mode version using __afl_persistent_loop:
       extern "C" int __afl_persistent_loop(unsigned int max_cnt);
       Use it to avoid process restart on each test case (much faster).
  4. Build a basic seed corpus: write 3-5 files under corpus/ that
     represent valid and edge-case HTTP headers.

  Seed files to create:
    corpus/01_valid.txt    — a valid GET request header
    corpus/02_long.txt     — a header with a 8192-byte value
    corpus/03_no_crlf.txt  — missing \r\n terminator
    corpus/04_binary.txt   — random binary bytes (edge case)
    corpus/05_unicode.txt  — UTF-8 multi-byte sequences in header value

  COMPILE as DLL (WinAFL mode):
    cl /LD /std:c++17 /Zi ex01_winafl_harness.cpp /Fe:harness.dll
  COMPILE as EXE (standalone test):
    cl /std:c++17 /Zi ex01_winafl_harness.cpp /Fe:harness_test.exe

  RUN with WinAFL (after installing DynamoRIO + WinAFL):
    afl-fuzz.exe -i corpus -o findings -t 5000
      -- drrun.exe -c winafl.dll -target_module harness.dll
         -target_offset <fuzz_RVA> -fuzz_iterations 1000
      -- harness_test.exe @@
*/

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

// -------- Target function (provided — do NOT modify) --------
typedef struct {
    char method[16];
    char path[256];
    char host[128];
    char contentType[64];
    int  contentLength;
} HttpHeader;

bool parseHttpHeader(const char* data, size_t len, HttpHeader* out) {
    if (!data || len == 0 || !out) return false;
    memset(out, 0, sizeof(*out));

    // Parse "METHOD /path HTTP/1.x"
    const char* p = data;
    const char* end = data + len;
    char* dst = out->method;
    while (p < end && *p != ' ' && (dst - out->method) < 15) *dst++ = *p++;
    while (p < end && *p == ' ') p++;
    dst = out->path;
    while (p < end && *p != ' ' && (dst - out->path) < 255) *dst++ = *p++;
    while (p < end && *p != '\n') p++;
    if (p < end) p++;

    // Parse headers
    while (p < end) {
        if (*p == '\r' || *p == '\n') break;
        char line[512] = {};
        int li = 0;
        while (p < end && *p != '\r' && *p != '\n' && li < 511) line[li++] = *p++;
        while (p < end && (*p == '\r' || *p == '\n')) p++;

        if (_strnicmp(line, "Host:", 5) == 0) {
            strncpy_s(out->host, sizeof(out->host), line+6, _TRUNCATE);
        } else if (_strnicmp(line, "Content-Type:", 13) == 0) {
            strncpy_s(out->contentType, sizeof(out->contentType), line+14, _TRUNCATE);
        } else if (_strnicmp(line, "Content-Length:", 15) == 0) {
            out->contentLength = atoi(line+16);
        }
    }
    return true;
}
// -------- end target function --------

// ---------- TODO 1: readFile ----------
char* readFile(const char* filename, size_t* outSize) {
    *outSize = 0;
    // YOUR CODE HERE:
    // HANDLE hFile = CreateFileA(filename, GENERIC_READ, ...);
    // DWORD size = GetFileSize(hFile, nullptr);
    // char* buf = (char*)malloc(size + 1);
    // ReadFile(hFile, buf, size, ...);
    // buf[size] = '\0';
    // *outSize = size;
    // CloseHandle(hFile);
    // return buf;
    (void)filename;
    return nullptr; // replace
}

// ---------- TODO 2: fuzz export ----------
extern "C" __declspec(dllexport) int fuzz(const char* filename) {
    size_t size = 0;
    char* data = readFile(filename, &size);
    if (!data) return 0;

    HttpHeader h;
    parseHttpHeader(data, size, &h);

    free(data);
    return 0;
}

// ---------- TODO 3: persistent mode (bonus) ----------
// extern "C" int __afl_persistent_loop(unsigned int max_cnt);
//
// extern "C" __declspec(dllexport) int fuzz_persistent(const char* filename) {
//     while (__afl_persistent_loop(1000)) {
//         size_t size = 0;
//         char* data = readFile(filename, &size);
//         if (data) {
//             HttpHeader h;
//             parseHttpHeader(data, size, &h);
//             free(data);
//         }
//     }
//     return 0;
// }

// Standalone test entry point
int main(int argc, char* argv[]) {
    const char* testFile = argc > 1 ? argv[1] : "corpus/01_valid.txt";
    printf("[*] Testing harness with: %s\n", testFile);
    fuzz(testFile);
    printf("[*] Done (no crash)\n");
    return 0;
}
