/*
  Solution 02 — String Extractor (Complete)
  -------------------------------------------
  Extracts and classifies ASCII + UTF-16LE strings from a binary file.
  Also brute-forces single-byte XOR obfuscation.

  Compile:
    g++ -std=c++17 -Wall -o sol02.exe sol02_string_extractor.cpp
    cl  /std:c++17  sol02_string_extractor.cpp /Fe:sol02.exe

  Usage:
    sol02.exe target.exe
    sol02.exe target.exe --xor
*/

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <cstdio>
#include <fstream>
#include <algorithm>
#include <cctype>

static const int MIN_LEN       = 4;
static const int XOR_THRESHOLD = 20;

enum StringClass {
    URL, IP_ADDR, PATH, REGISTRY, MUTEX, API_NAME, EMAIL, OTHER
};

struct ExtractedString {
    std::string value;
    size_t      offset;
    bool        isWide;
    StringClass cls;
};


// =========================================================
// Helper: is a byte printable ASCII?
// =========================================================
static inline bool isPrintable(BYTE b) {
    return b >= 0x20 && b <= 0x7E;
}


// =========================================================
// 1. extractAscii — collect runs of printable bytes >= MIN_LEN
// =========================================================
std::vector<ExtractedString> extractAscii(const BYTE* buf, size_t size) {
    std::vector<ExtractedString> result;
    size_t runStart = size;   // SIZE_MAX-like sentinel

    for (size_t i = 0; i <= size; i++) {
        bool printable = (i < size && isPrintable(buf[i]));

        if (printable) {
            if (runStart == size) runStart = i;   // start a new run
        } else {
            if (runStart != size) {
                size_t len = i - runStart;
                if ((int)len >= MIN_LEN) {
                    ExtractedString s;
                    s.value  = std::string((const char*)buf + runStart, len);
                    s.offset = runStart;
                    s.isWide = false;
                    s.cls    = OTHER;
                    result.push_back(std::move(s));
                }
                runStart = size;
            }
        }
    }
    return result;
}


// =========================================================
// 2. extractWide — UTF-16LE: high byte == 0, low byte printable
// =========================================================
std::vector<ExtractedString> extractWide(const BYTE* buf, size_t size) {
    std::vector<ExtractedString> result;
    size_t runStart = size;

    // Step by 2 bytes
    for (size_t i = 0; i + 1 < size; i += 2) {
        bool wideChar = (buf[i + 1] == 0x00 && isPrintable(buf[i]));

        if (wideChar) {
            if (runStart == size) runStart = i;
        } else {
            if (runStart != size) {
                size_t chars = (i - runStart) / 2;
                if ((int)chars >= MIN_LEN) {
                    std::string s;
                    s.reserve(chars);
                    for (size_t j = runStart; j < i; j += 2)
                        s += (char)buf[j];

                    ExtractedString es;
                    es.value  = std::move(s);
                    es.offset = runStart;
                    es.isWide = true;
                    es.cls    = OTHER;
                    result.push_back(std::move(es));
                }
                runStart = size;
            }
        }
    }
    return result;
}


// =========================================================
// 3. classify — label each string
// =========================================================
StringClass classify(const std::string& s) {
    // URL
    if (s.find("http://")  != std::string::npos ||
        s.find("https://") != std::string::npos ||
        s.find("ftp://")   != std::string::npos)
        return URL;

    // Registry
    if (s.find("HKEY_")  != std::string::npos ||
        s.find("HKLM\\") != std::string::npos ||
        s.find("HKCU\\") != std::string::npos ||
        s.find("HKCR\\") != std::string::npos ||
        s.find("HKU\\")  != std::string::npos)
        return REGISTRY;

    // Mutex / named objects
    if (s.find("Global\\") != std::string::npos ||
        s.find("Local\\")  != std::string::npos)
        return MUTEX;

    // Email
    if (s.find('@') != std::string::npos &&
        s.find('.') != std::string::npos)
        return EMAIL;

    // Windows path (backslash) or Unix path
    if ((s.size() >= 3 && s[1] == ':' && s[2] == '\\') ||
        s.find("\\\\") != std::string::npos ||
        (s[0] == '/' && s.size() > 1 && (std::isalpha((unsigned char)s[1]) || s[1] == '/')))
        return PATH;

    // IP address heuristic: 3-dot decimal notation, e.g. 192.168.1.1
    {
        int dots = 0;
        bool allDigitsDots = !s.empty();
        for (char c : s) {
            if (c == '.') dots++;
            else if (!std::isdigit((unsigned char)c)) { allDigitsDots = false; break; }
        }
        if (allDigitsDots && dots == 3 && s.size() >= 7)
            return IP_ADDR;
    }

    // Well-known suspicious API names (uppercase + digits, common suffix A/W)
    static const char* apiNames[] = {
        "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory",
        "ReadProcessMemory", "CreateRemoteThread", "NtCreateThreadEx",
        "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState",
        "CryptEncrypt", "CryptDecrypt", "CryptAcquireContext",
        "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
        "WinExec", "ShellExecuteA", "ShellExecuteW",
        "CreateProcessA", "CreateProcessW",
        "InternetOpenA", "HttpSendRequestA", "WinHttpOpen",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        nullptr
    };
    for (int i = 0; apiNames[i]; i++) {
        if (s == apiNames[i] ||
            s == std::string(apiNames[i]) + "A" ||
            s == std::string(apiNames[i]) + "W")
            return API_NAME;
    }

    return OTHER;
}


// =========================================================
// Helper: count printable ASCII runs >= MIN_LEN in a buffer
// =========================================================
static int countPrintableRuns(const BYTE* buf, size_t size) {
    int    runs     = 0;
    int    runLen   = 0;
    bool   inRun    = false;

    for (size_t i = 0; i < size; i++) {
        if (isPrintable(buf[i])) {
            runLen++;
            if (!inRun) inRun = true;
        } else {
            if (inRun && runLen >= MIN_LEN) runs++;
            inRun  = false;
            runLen = 0;
        }
    }
    if (inRun && runLen >= MIN_LEN) runs++;
    return runs;
}


// =========================================================
// 4. xorBruteforce — try keys 1-255, report if > THRESHOLD strings
// =========================================================
void xorBruteforce(const BYTE* buf, size_t size) {
    printf("\n[XOR] Brute-forcing single-byte XOR keys (threshold=%d strings)...\n",
           XOR_THRESHOLD);

    std::vector<BYTE> decoded(size);

    for (int key = 1; key < 256; key++) {
        for (size_t i = 0; i < size; i++)
            decoded[i] = buf[i] ^ (BYTE)key;

        int runs = countPrintableRuns(decoded.data(), size);

        if (runs >= XOR_THRESHOLD) {
            printf("  [KEY 0x%02X]  %d printable strings — possible XOR obfuscation!\n",
                   key, runs);

            // Show a sample of what decoded strings look like
            auto strings = extractAscii(decoded.data(), size);
            int  shown   = 0;
            for (auto& s : strings) {
                if (s.value.size() >= 6) {   // only show non-trivial ones
                    printf("    0x%06zX  %s\n", s.offset, s.value.c_str());
                    if (++shown >= 5) { printf("    ... (more)\n"); break; }
                }
            }
        }
    }
    printf("[XOR] Done.\n");
}


// =========================================================
// main
// =========================================================
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <file.exe> [--xor]\n", argv[0]);
        return 1;
    }
    bool doXor = (argc > 2 && strcmp(argv[2], "--xor") == 0);

    std::ifstream f(argv[1], std::ios::binary);
    if (!f) { printf("[-] Cannot open %s\n", argv[1]); return 1; }

    std::vector<BYTE> buf(
        (std::istreambuf_iterator<char>(f)),
        std::istreambuf_iterator<char>());
    f.close();

    printf("[*] File: %s  (%zu bytes)\n\n", argv[1], buf.size());

    auto ascii = extractAscii(buf.data(), buf.size());
    auto wide  = extractWide (buf.data(), buf.size());

    printf("[*] ASCII strings: %zu\n", ascii.size());
    printf("[*] Wide  strings: %zu\n", wide.size());

    // Classify and print
    static const char* clsName[] = {
        "URL", "IP", "PATH", "REGISTRY", "MUTEX", "API", "EMAIL", "other"
    };

    printf("\n[CLASSIFIED STRINGS]\n");
    printf("%-10s  %-12s  %s\n", "Offset", "Class", "Value");
    printf("%s\n", std::string(80, '-').c_str());

    // Merge and classify all strings
    std::vector<ExtractedString> all;
    all.insert(all.end(), ascii.begin(), ascii.end());
    all.insert(all.end(), wide.begin(),  wide.end());
    std::sort(all.begin(), all.end(),
              [](const ExtractedString& a, const ExtractedString& b){
                  return a.offset < b.offset;
              });

    int interesting = 0;
    std::set<std::string> seen;
    for (auto& s : all) {
        s.cls = classify(s.value);
        if (s.cls == OTHER) continue;
        if (seen.count(s.value)) continue;
        seen.insert(s.value);

        printf("0x%08zX  %-12s  %s%s\n",
               s.offset,
               clsName[s.cls],
               s.value.c_str(),
               s.isWide ? " [W]" : "");
        interesting++;
    }

    printf("\n[*] Total interesting (non-OTHER): %d\n", interesting);

    if (doXor) xorBruteforce(buf.data(), buf.size());

    return 0;
}
