/*
  Exercise 02 — String Extractor
  --------------------------------
  Malware analysts extract strings from binaries to find:
  - C2 URLs and IPs
  - Mutexes (anti-analysis artifacts)
  - Registry keys (persistence paths)
  - API function names (when not in IAT — dynamically resolved)
  - Debug paths (reveals compilation environment)

  Your string extractor should:
  1. Scan a raw file buffer for printable ASCII runs of length >= MIN_LEN.
  2. Scan the same buffer for UTF-16LE runs of length >= MIN_LEN.
  3. Filter out "interesting" strings using a keyword list.
  4. Detect string obfuscation: count how many strings XOR-decode to
     printable ASCII (brute-force single-byte XOR key 0x01-0xFF).

  Tasks:
  1. Implement extractAscii(buf, size) — find all ASCII strings >= MIN_LEN chars.
  2. Implement extractWide(buf, size) — find UTF-16LE strings >= MIN_LEN chars.
  3. Implement classifyStrings(strings) — label each string:
       URL, IP, PATH, REGISTRY, MUTEX, API, EMAIL, OTHER.
  4. Implement xorBruteforce(buf, size) — for each key 0x01-0xFF, XOR the
     buffer, count printable ASCII runs. Report if a key gives > THRESHOLD strings.
  5. Build a summary report: total strings, interesting strings, obfuscation score.

  Compile:
    g++ -std=c++17 -Wall -o ex02.exe ex02_string_extractor.cpp
  Usage:
    ex02.exe target.exe
    ex02.exe target.exe --xor
*/

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <regex>
#include <cstdio>
#include <fstream>
#include <algorithm>

static const int MIN_LEN = 4;
static const int XOR_THRESHOLD = 20;

enum StringClass { URL, IP_ADDR, PATH, REGISTRY, MUTEX, API_NAME, EMAIL, OTHER };

struct ExtractedString {
    std::string  value;
    size_t       offset;
    bool         isWide;
    StringClass  cls;
};

// ---------- TODO 1: extractAscii ----------
std::vector<ExtractedString> extractAscii(const BYTE* buf, size_t size) {
    std::vector<ExtractedString> result;
    // YOUR CODE HERE:
    // Walk buf byte by byte.
    // When you see a printable char (0x20-0x7E), start accumulating.
    // When the run ends (non-printable or end-of-buffer):
    //   if run.size() >= MIN_LEN, add ExtractedString{run, offset, false, OTHER}
    (void)buf; (void)size;
    return result;
}

// ---------- TODO 2: extractWide ----------
std::vector<ExtractedString> extractWide(const BYTE* buf, size_t size) {
    std::vector<ExtractedString> result;
    // YOUR CODE HERE:
    // Each UTF-16LE char is 2 bytes: high byte must be 0x00, low byte printable.
    // Step by 2; when run of wide printable chars is >= MIN_LEN chars, record it.
    (void)buf; (void)size;
    return result;
}

// ---------- TODO 3: classify ----------
StringClass classify(const std::string& s) {
    // YOUR CODE HERE: simple pattern matching
    // URL: starts with http:// or https://
    // IP:  matches \d{1,3}(\.\d{1,3}){3}
    // PATH: contains \\ or /
    // REGISTRY: starts with HKEY_ or HKLM\\ or HKCU\\
    // MUTEX: contains Global\\ or Local\\
    // API: all uppercase letters + digits, ends with A or W
    // EMAIL: contains @
    (void)s;
    return OTHER;
}

// ---------- TODO 4: xorBruteforce ----------
void xorBruteforce(const BYTE* buf, size_t size) {
    printf("[XOR] Brute-forcing single-byte XOR keys...\n");
    for (int key = 1; key < 256; key++) {
        // XOR entire buf with key, count printable ASCII runs >= MIN_LEN
        std::vector<BYTE> decoded(buf, buf + size);
        for (auto& b : decoded) b ^= (BYTE)key;

        // YOUR CODE HERE: count runs of printable chars >= MIN_LEN
        int runs = 0;
        // ... (same logic as extractAscii but on decoded)
        // if (runs >= XOR_THRESHOLD) printf("  Key 0x%02X: %d strings\n", key, runs);
        (void)runs;
    }
}

// ---------- main ----------
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <file.exe> [--xor]\n", argv[0]);
        return 1;
    }
    bool doXor = (argc > 2 && strcmp(argv[2], "--xor") == 0);

    std::ifstream f(argv[1], std::ios::binary);
    if (!f) { printf("[-] Cannot open %s\n", argv[1]); return 1; }
    std::vector<BYTE> buf(std::istreambuf_iterator<char>(f), {});

    auto ascii = extractAscii(buf.data(), buf.size());
    auto wide  = extractWide(buf.data(),  buf.size());

    printf("[*] ASCII strings: %zu\n", ascii.size());
    printf("[*] Wide  strings: %zu\n", wide.size());

    // Classify and print interesting ones
    int interesting = 0;
    for (auto& s : ascii) {
        s.cls = classify(s.value);
        if (s.cls != OTHER) {
            printf("  [0x%08zX]  %-10s  %s\n",
                   s.offset,
                   s.cls == URL       ? "URL"      :
                   s.cls == IP_ADDR   ? "IP"       :
                   s.cls == PATH      ? "PATH"     :
                   s.cls == REGISTRY  ? "REGISTRY" :
                   s.cls == MUTEX     ? "MUTEX"    :
                   s.cls == API_NAME  ? "API"      :
                   s.cls == EMAIL     ? "EMAIL"    : "OTHER",
                   s.value.c_str());
            interesting++;
        }
    }
    printf("[*] Interesting: %d\n", interesting);

    if (doXor) xorBruteforce(buf.data(), buf.size());
    return 0;
}
