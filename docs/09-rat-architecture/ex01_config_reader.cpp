/*
  Exercise 01 — Config Reader
  ----------------------------
  The B4B3 stub reads its config from bytes appended to its own binary.
  This exercise teaches you how that works.

  Tasks:
  1. Write a function: void appendConfig(const char* stubPath, const char* outPath)
     - Reads stubPath into a buffer
     - Builds a fake 651-byte payload:
         * bytes 0-642: XOR-encode a config struct with a key derived from the first 1024 bytes
         * bytes 643-650: magic marker { 0xB4, 0x4B, 0xD4, 0x3E, 0x7A, 0x91, 0xC3, 0xF8 }
     - Appends it to the stub bytes and writes to outPath
     Config struct (simplified for this exercise):
       struct Config {
           char c2host[64];    // null-terminated
           uint16_t c2port;    // little-endian
           char authkey[32];   // null-terminated
           char botname[32];   // null-terminated
           // ... (pad to 643 bytes)
       };
     For this exercise use: host="127.0.0.1", port=4444, key="test123", name="bot001"

  2. Write: bool readConfig(Config* out)
     Reads own binary (GetModuleFileNameA), seeks to the last 651 bytes.
     Verifies the magic marker.
     Derives XOR key from first 1024 bytes of the file.
     XOR-decodes the 643-byte config.
     Fills out the Config struct.
     Returns true on success.

  3. In main():
     - Call appendConfig() on argv[0] to create "test_stub.exe"
       (or use a test binary you create)
     - Run "test_stub.exe" which calls readConfig() and prints the config.

  Compile:
    g++ -std=c++17 -Wall -o ex01.exe ex01_config_reader.cpp

  Note: to test readConfig(), you'll need to run a binary that has the config
  appended. The easiest way: compile this, call appendConfig on the resulting
  ex01.exe to create test.exe, then run test.exe.
*/

#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>

struct Config {
    char     c2host[64];
    uint16_t c2port;
    char     authkey[32];
    char     botname[32];
    char     _pad[513];   // pad to 643 bytes total
};
static_assert(sizeof(Config) == 643, "Config size must be 643");

static const uint8_t MAGIC[8] = {0xB4,0x4B,0xD4,0x3E,0x7A,0x91,0xC3,0xF8};

// YOUR CODE HERE

int main(int argc, char* argv[]) {
    // If run without args: try to read own config
    Config cfg = {};
    if (readConfig(&cfg)) {
        std::cout << "Config found!\n";
        std::cout << "  host:    " << cfg.c2host  << "\n";
        std::cout << "  port:    " << cfg.c2port  << "\n";
        std::cout << "  authkey: " << cfg.authkey << "\n";
        std::cout << "  botname: " << cfg.botname << "\n";
    } else {
        std::cout << "No config found in this binary.\n";

        // Create a test binary with config appended
        char selfPath[MAX_PATH];
        GetModuleFileNameA(nullptr, selfPath, MAX_PATH);
        appendConfig(selfPath, "test_with_config.exe");
        std::cout << "Created test_with_config.exe — run it to test readConfig.\n";
    }
    return 0;
}
