// yara_scanner.cpp — YARA scanner with manual byte-pattern fallback
// Compile (no libyara): g++ -std=c++17 -o yara_scanner.exe yara_scanner.cpp
// Compile (with libyara): g++ -std=c++17 -DYARA_AVAILABLE -o yara_scanner.exe yara_scanner.cpp -lyara
// Usage: yara_scanner.exe file <rules.yar> <file> | dir <rules.yar> <dir>
//                         pid <rules.yar> <pid> | all <rules.yar> | test

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <regex>
#include <sstream>
#include <algorithm>

namespace fs = std::filesystem;

#ifdef YARA_AVAILABLE
#include <yara.h>
#endif

// ─── Manual byte-pattern rule ─────────────────────────────────────────────────

struct BytePattern {
    std::string name;
    std::string rule_name;
    std::vector<std::vector<uint8_t>> hex_patterns;  // each sub-vec is one hex string
    std::vector<std::string> str_patterns;
};

// Parse a trivial YARA-like .yar file manually (subset: strings + condition any of them)
static std::vector<BytePattern> parse_rules_file(const char* path) {
    std::vector<BytePattern> rules;
    std::ifstream f(path);
    if (!f) { fprintf(stderr, "Cannot open rules: %s\n", path); return rules; }

    std::string line;
    BytePattern current;
    bool in_rule = false, in_strings = false;

    while (std::getline(f, line)) {
        // trim
        auto lpos = line.find_first_not_of(" \t");
        if (lpos != std::string::npos) line = line.substr(lpos);

        if (line.rfind("rule ", 0) == 0) {
            if (in_rule && !current.name.empty()) rules.push_back(current);
            current = BytePattern{};
            // extract rule name
            size_t sp = line.find(' ');
            size_t end = line.find('{');
            if (sp != std::string::npos) {
                current.name = line.substr(sp+1, (end != std::string::npos ? end : line.size()) - sp - 1);
                // trim
                auto p = current.name.find_first_not_of(" \t");
                if (p != std::string::npos) current.name = current.name.substr(p);
                p = current.name.find_last_not_of(" \t{");
                if (p != std::string::npos) current.name = current.name.substr(0, p+1);
            }
            in_rule = true;
            in_strings = false;
        } else if (line == "strings:") {
            in_strings = true;
        } else if (line == "condition:" || line.rfind("condition:", 0) == 0) {
            in_strings = false;
        } else if (line == "}") {
            if (in_rule && !current.name.empty()) rules.push_back(current);
            current = BytePattern{};
            in_rule = false;
        } else if (in_strings) {
            // $name = { HH HH ... } or $name = "string"
            auto eq = line.find('=');
            if (eq == std::string::npos) continue;
            std::string val = line.substr(eq+1);
            // trim val
            auto vp = val.find_first_not_of(" \t");
            if (vp != std::string::npos) val = val.substr(vp);

            if (!val.empty() && val[0] == '{') {
                // hex pattern
                std::vector<uint8_t> bytes;
                for (size_t i = 1; i+1 < val.size(); i += 3) {
                    while (i < val.size() && (val[i]==' '||val[i]=='{'||val[i]=='}')) ++i;
                    if (i+1 >= val.size() || val[i]=='}') break;
                    if (val[i]=='?' && val[i+1]=='?') { bytes.push_back(0); i += 2; continue; }
                    char b[3]={val[i],val[i+1],0};
                    bytes.push_back((uint8_t)strtoul(b, nullptr, 16));
                }
                if (!bytes.empty()) current.hex_patterns.push_back(bytes);
            } else if (!val.empty() && val[0] == '"') {
                // string pattern
                size_t end = val.rfind('"');
                if (end > 0) current.str_patterns.push_back(val.substr(1, end-1));
            }
        }
    }
    if (in_rule && !current.name.empty()) rules.push_back(current);
    return rules;
}

static bool scan_buffer(const std::vector<BytePattern>& rules,
                        const uint8_t* data, size_t len,
                        const char* label) {
    bool any = false;
    for (auto& rule : rules) {
        bool matched = false;
        for (auto& pat : rule.hex_patterns) {
            if (pat.size() > len) continue;
            for (size_t i = 0; i + pat.size() <= len; ++i) {
                if (memcmp(data + i, pat.data(), pat.size()) == 0) { matched = true; break; }
            }
            if (matched) break;
        }
        if (!matched) {
            for (auto& s : rule.str_patterns) {
                auto it = std::search(data, data+len,
                    (const uint8_t*)s.data(), (const uint8_t*)s.data()+s.size());
                if (it != data+len) { matched = true; break; }
            }
        }
        if (matched) {
            printf("  [MATCH] Rule: %-30s  Target: %s\n", rule.name.c_str(), label);
            any = true;
        }
    }
    return any;
}

// ─── Wrappers ─────────────────────────────────────────────────────────────────

static void scan_file(const std::vector<BytePattern>& rules, const char* path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) { fprintf(stderr, "Cannot open %s\n", path); return; }
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)), {});
    scan_buffer(rules, data.data(), data.size(), path);
}

static void scan_dir(const std::vector<BytePattern>& rules, const char* dir) {
    for (auto& entry : fs::recursive_directory_iterator(dir,
            fs::directory_options::skip_permission_denied)) {
        if (!entry.is_regular_file()) continue;
        std::string p = entry.path().string();
        std::ifstream f(p, std::ios::binary);
        if (!f) continue;
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)), {});
        scan_buffer(rules, data.data(), data.size(), p.c_str());
    }
}

static void scan_pid(const std::vector<BytePattern>& rules, DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) { fprintf(stderr, "Cannot open PID %lu: %lu\n", pid, GetLastError()); return; }

    MEMORY_BASIC_INFORMATION mbi{};
    uint8_t* addr = nullptr;
    while (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD)) {
            std::vector<uint8_t> buf(mbi.RegionSize);
            SIZE_T rd = 0;
            if (ReadProcessMemory(hProc, mbi.BaseAddress, buf.data(), mbi.RegionSize, &rd) && rd > 0) {
                char label[64];
                snprintf(label, sizeof(label), "PID:%lu@0x%p", pid, mbi.BaseAddress);
                scan_buffer(rules, buf.data(), rd, label);
            }
        }
        addr = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
        if (!mbi.RegionSize) break;
    }
    CloseHandle(hProc);
}

static void scan_all(const std::vector<BytePattern>& rules) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe{ sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do { scan_pid(rules, pe.th32ProcessID); }
        while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
}

// ─── test: create sample rules file and scan self ─────────────────────────────

static void cmd_test() {
    const char* RULES = "test_rules.yar";
    FILE* f = fopen(RULES, "w");
    fprintf(f,
        "rule MZ_Header {\n"
        "  strings:\n"
        "    $mz = { 4D 5A }\n"
        "  condition:\n"
        "    any of them\n"
        "}\n"
        "rule Suspicious_String {\n"
        "  strings:\n"
        "    $s = \"VirtualAllocEx\"\n"
        "  condition:\n"
        "    any of them\n"
        "}\n");
    fclose(f);
    printf("[*] Wrote test rules: %s\n", RULES);

    auto rules = parse_rules_file(RULES);
    printf("[*] Scanning self (this EXE)...\n");
    char self[MAX_PATH]{};
    GetModuleFileNameA(nullptr, self, MAX_PATH);
    scan_file(rules, self);
    printf("[*] Done. Parsed %zu rules.\n", rules.size());
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage:\n"
               "  yara_scanner.exe file <rules.yar> <file>\n"
               "  yara_scanner.exe dir  <rules.yar> <dir>\n"
               "  yara_scanner.exe pid  <rules.yar> <pid>\n"
               "  yara_scanner.exe all  <rules.yar>\n"
               "  yara_scanner.exe test\n");
        return 1;
    }
    std::string cmd(argv[1]);
    if (cmd == "test") { cmd_test(); return 0; }
    if (argc < 3) { fprintf(stderr, "Missing rules file\n"); return 1; }

    auto rules = parse_rules_file(argv[2]);
    if (rules.empty()) { fprintf(stderr, "No rules loaded\n"); return 1; }
    printf("[*] Loaded %zu rules from %s\n\n", rules.size(), argv[2]);

    if      (cmd == "file" && argc >= 4) scan_file(rules, argv[3]);
    else if (cmd == "dir"  && argc >= 4) scan_dir(rules, argv[3]);
    else if (cmd == "pid"  && argc >= 4) scan_pid(rules, (DWORD)strtoul(argv[3], nullptr, 10));
    else if (cmd == "all")               scan_all(rules);
    else { fprintf(stderr, "Unknown command.\n"); return 1; }
    return 0;
}
