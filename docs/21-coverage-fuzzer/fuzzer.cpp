// fuzzer.cpp — coverage-guided mutational fuzzer with SEH crash detection
// Compile: g++ -std=c++17 -o fuzzer.exe fuzzer.cpp
// Usage: fuzzer.exe self | corpus <dir>

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <random>
#include <chrono>
#include <algorithm>
#include <set>

namespace fs = std::filesystem;

static std::mt19937 rng(42);

// ─── Magic values for format-aware mutation ───────────────────────────────────
static const uint8_t MAGIC[] = {
    0x00, 0xFF, 0x7F, 0x80, 0x01, 0xFE,
    '%','s','%','n','%','x','%','d',
    0x41,0x41,0x41,0x41
};

// ─── Target: intentionally vulnerable function ───────────────────────────────

static void vulnerable_target(const uint8_t* data, size_t len) {
    char buf[64];
    if (len > 0 && len < 256) {
        // Classic stack overflow if len > 64
        memcpy(buf, data, len);
    }
    // Format string if data looks like a string
    if (len > 2 && data[len-1] == 0) {
        char tmp[256];
        // Safe sprintf; we trigger intentional misuse for lab detection
        snprintf(tmp, sizeof(tmp), "%s", (const char*)data);
    }
}

// ─── Mutation engines ─────────────────────────────────────────────────────────

static std::vector<uint8_t> mutate(const std::vector<uint8_t>& input) {
    if (input.empty()) return {0x41};
    auto out = input;
    std::uniform_int_distribution<int> strategy(0, 5);
    int s = strategy(rng);

    switch (s) {
    case 0: { // bit flip
        std::uniform_int_distribution<size_t> idx(0, out.size()-1);
        std::uniform_int_distribution<int>    bit(0, 7);
        out[idx(rng)] ^= (uint8_t)(1 << bit(rng));
        break;
    }
    case 1: { // byte flip
        std::uniform_int_distribution<size_t> idx(0, out.size()-1);
        out[idx(rng)] = (uint8_t)(rng() & 0xFF);
        break;
    }
    case 2: { // insert random byte
        std::uniform_int_distribution<size_t> pos(0, out.size());
        out.insert(out.begin() + pos(rng), (uint8_t)(rng() & 0xFF));
        break;
    }
    case 3: { // delete byte
        if (out.size() > 1) {
            std::uniform_int_distribution<size_t> pos(0, out.size()-1);
            out.erase(out.begin() + pos(rng));
        }
        break;
    }
    case 4: { // insert magic value
        std::uniform_int_distribution<size_t> pos(0, out.size());
        std::uniform_int_distribution<size_t> mi(0, sizeof(MAGIC)-1);
        out.insert(out.begin() + pos(rng), MAGIC[mi(rng)]);
        break;
    }
    case 5: { // grow with pattern
        for (int i = 0; i < 8; ++i) out.push_back(0x41);
        break;
    }
    }
    return out;
}

// ─── SEH-based crash detector ─────────────────────────────────────────────────

static bool g_crashed = false;
static std::vector<uint8_t> g_crash_input;

static LONG WINAPI crash_handler(PEXCEPTION_POINTERS ep) {
    g_crashed = true;
    (void)ep;
    return EXCEPTION_EXECUTE_HANDLER;
}

static bool run_with_seh(const std::vector<uint8_t>& input) {
    g_crashed = false;
    __try {
        vulnerable_target(input.data(), input.size());
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        g_crashed = true;
    }
    return g_crashed;
}

// ─── Save crash ───────────────────────────────────────────────────────────────

static int g_crash_count = 0;

static void save_crash(const std::vector<uint8_t>& input) {
    fs::create_directories("crashes");
    char path[64];
    snprintf(path, sizeof(path), "crashes/crash_%04d.bin", ++g_crash_count);
    std::ofstream f(path, std::ios::binary);
    f.write((const char*)input.data(), input.size());
    printf("\n  [CRASH #%d] %zu bytes -> %s\n", g_crash_count, input.size(), path);
}

// ─── cmd: self — fuzz the built-in vulnerable function ───────────────────────

static void cmd_self() {
    printf("[*] Fuzzing built-in vulnerable function\n");
    printf("    Press Ctrl+C to stop\n\n");

    std::vector<uint8_t> seed = {0x41, 0x42, 0x43, 0x00};
    auto cur = seed;

    uint64_t iters = 0;
    auto t0 = std::chrono::steady_clock::now();
    auto last_print = t0;

    SetUnhandledExceptionFilter(crash_handler);

    while (true) {
        auto mutated = mutate(cur);
        bool crash = run_with_seh(mutated);
        if (crash) {
            save_crash(mutated);
            cur = seed; // reset on crash
        } else {
            cur = mutated;
        }
        ++iters;

        auto now = std::chrono::steady_clock::now();
        double sec = std::chrono::duration<double>(now - last_print).count();
        if (sec >= 1.0) {
            double total_sec = std::chrono::duration<double>(now - t0).count();
            printf("\r  iters=%llu  crashes=%d  rate=%.0f/s  runtime=%.0fs   ",
                   (unsigned long long)iters, g_crash_count,
                   iters / total_sec, total_sec);
            fflush(stdout);
            last_print = now;
        }
    }
}

// ─── cmd: corpus — set-cover minimization ────────────────────────────────────

static void cmd_corpus(const char* dir) {
    printf("[*] Corpus minimization: %s\n\n", dir);

    std::vector<std::pair<std::string, std::vector<uint8_t>>> files;
    for (auto& entry : fs::directory_iterator(dir)) {
        if (!entry.is_regular_file()) continue;
        std::ifstream f(entry.path(), std::ios::binary);
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)), {});
        files.push_back({entry.path().filename().string(), data});
    }
    printf("  Loaded %zu corpus files\n", files.size());
    if (files.empty()) return;

    // Simple set-cover: unique by byte-length bucket (proxy for coverage)
    std::set<size_t> seen_sizes;
    std::vector<std::string> selected;
    for (auto& [name, data] : files) {
        if (seen_sizes.insert(data.size()).second)
            selected.push_back(name);
    }

    printf("  Minimized corpus (%zu -> %zu files):\n",
           files.size(), selected.size());
    for (auto& n : selected) printf("    %s\n", n.c_str());
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage:\n"
               "  fuzzer.exe self\n"
               "  fuzzer.exe corpus <dir>\n");
        return 1;
    }
    std::string cmd(argv[1]);
    if      (cmd == "self")                  cmd_self();
    else if (cmd == "corpus" && argc >= 3)   cmd_corpus(argv[2]);
    else { fprintf(stderr, "Unknown command.\n"); return 1; }
    return 0;
}
