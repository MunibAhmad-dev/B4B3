/*
  Exercise 03 — Safe Ransomware Simulation
  ------------------------------------------
  Implement a COMPANY-APPROVED ransomware simulation that:
  1. Operates ONLY on C:\RansomwareSimTest\
  2. Requires C:\RansomwareSimTest\SIM_APPROVED.flag to exist before starting
  3. Generates a random per-session AES-256 key
  4. Encrypts each matching file to <filename>.enc (keeps original for safety)
  5. Writes a simulated ransom note: C:\RansomwareSimTest\README_DECRYPT.txt
  6. Logs every action to sim_log.txt
  7. Provides instant recovery: --recover flag decrypts .enc files

  Usage:
    ex03.exe              → runs simulation (requires SIM_APPROVED.flag)
    ex03.exe --recover    → decrypts all .enc files using saved key

  The key is saved to sim_key.bin (32 bytes, raw) for the recovery path.
  In a real assessment the key would be sent to the C2 instead.

  Tasks:
  1. Implement generateSessionKey() — BCryptGenRandom 32 bytes.
  2. Implement encryptSimFile() — read file, encrypt with AES-256-CBC, write .enc.
     Prepend the 16-byte IV to the output file.
  3. Implement recoverSimFiles() — enumerate .enc files, decrypt, write original.
  4. Implement the main simulation loop with safety checks.

  BONUS:
  - Add a --dry-run flag that logs without encrypting.
  - Add a ransom note that includes the machine name and date.
  - Simulate shadow copy deletion by logging the vssadmin command (DON'T run it).

  Compile:
    g++ -std=c++17 -Wall -o ex03.exe ex03_ransomware_sim.cpp -lbcrypt -lkernel32
*/

#include <windows.h>
#include <bcrypt.h>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <ctime>
#include <iomanip>
#include <sstream>

#pragma comment(lib, "bcrypt.lib")
namespace fs = std::filesystem;

static const char* TEST_DIR   = "C:\\RansomwareSimTest";
static const char* FLAG_FILE  = "C:\\RansomwareSimTest\\SIM_APPROVED.flag";
static const char* KEY_FILE   = "sim_key.bin";
static const char* LOG_FILE   = "sim_log.txt";
static const char* NOTE_FILE  = "C:\\RansomwareSimTest\\README_DECRYPT.txt";

static const std::vector<std::string> TARGET_EXTS = {
    ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".txt",
    ".jpg", ".jpeg", ".png", ".csv"
};

static std::ofstream g_log;

void log(const std::string& msg) {
    auto t = std::time(nullptr); char ts[32];
    std::strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", std::localtime(&t));
    std::string line = std::string("[") + ts + "] " + msg;
    printf("%s\n", line.c_str());
    if (g_log.is_open()) g_log << line << "\n";
}

// TODO: Generate a random 32-byte AES key using BCryptGenRandom.
// Save it to KEY_FILE and return the key bytes.
std::vector<BYTE> generateSessionKey() {
    // YOUR CODE HERE
    return {};
}

// TODO: Load the key from KEY_FILE.
std::vector<BYTE> loadSessionKey() {
    // YOUR CODE HERE
    return {};
}

// TODO: Encrypt src file → dst file using AES-256-CBC.
// File format: [16 bytes IV][ciphertext with PKCS7 padding]
bool encryptSimFile(const std::string& src, const std::string& dst,
                    const std::vector<BYTE>& key) {
    // YOUR CODE HERE
    return false;
}

// TODO: Decrypt a .enc file → original file using AES-256-CBC.
// Read IV from first 16 bytes, decrypt the rest.
bool decryptSimFile(const std::string& src, const std::string& dst,
                    const std::vector<BYTE>& key) {
    // YOUR CODE HERE
    return false;
}

bool isSafeTarget(const fs::path& p) {
    std::string ext = p.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    for (const auto& e : TARGET_EXTS)
        if (e == ext) return true;
    return false;
}

void dropRansomNote() {
    char hostname[256] = "UNKNOWN"; GetComputerNameA(hostname, nullptr);
    char ts[32]; auto t = std::time(nullptr);
    std::strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", std::localtime(&t));

    std::ofstream note(NOTE_FILE);
    note << "*** RANSOMWARE SIMULATION — COMPANY AUTHORISED TEST ***\n\n";
    note << "Machine: " << hostname << "\n";
    note << "Date:    " << ts << "\n\n";
    note << "Your files in this test directory have been encrypted as part of\n";
    note << "a scheduled security drill. THIS IS NOT A REAL ATTACK.\n\n";
    note << "Contact IT Security to recover your test files.\n";
    note << "Recovery key file: sim_key.bin\n\n";
    note << "What would happen in a REAL attack:\n";
    note << "  - All user documents and photos would be encrypted\n";
    note << "  - Shadow copies would be deleted (vssadmin delete shadows /all)\n";
    note << "  - A ransom demand would be displayed\n";
    note << "  - Data would be exfiltrated before encryption\n";
    log("Ransom note dropped: " + std::string(NOTE_FILE));
}

void runSimulation(bool dryRun) {
    log(std::string("=== Ransomware Simulation Starting ") +
        (dryRun ? "(DRY RUN)" : "") + " ===");

    // Safety check
    if (!fs::exists(FLAG_FILE)) {
        log("SAFETY CHECK FAILED — SIM_APPROVED.flag not found. Aborting.");
        return;
    }
    log("Safety check passed — SIM_APPROVED.flag present");

    // TODO: Generate session key
    auto key = generateSessionKey();
    if (key.empty()) { log("Failed to generate session key"); return; }
    log("Session key generated and saved to " + std::string(KEY_FILE));

    int encrypted = 0, skipped = 0;

    for (const auto& entry : fs::recursive_directory_iterator(TEST_DIR)) {
        if (!entry.is_regular_file()) continue;
        if (!isSafeTarget(entry.path())) continue;

        std::string src = entry.path().string();
        std::string dst = src + ".enc";

        if (dryRun) {
            log("DRY-RUN: would encrypt " + src);
            encrypted++;
            continue;
        }

        // TODO: Call encryptSimFile() here
        log("ENCRYPTED: " + src + " → " + dst);
        encrypted++;
    }

    if (!dryRun) dropRansomNote();

    log("Simulation complete. Files encrypted: " + std::to_string(encrypted) +
        ", skipped: " + std::to_string(skipped));
}

void runRecovery() {
    log("=== Recovery Starting ===");

    auto key = loadSessionKey();
    if (key.empty()) { log("Could not load session key from " + std::string(KEY_FILE)); return; }
    log("Session key loaded");

    int recovered = 0, failed = 0;

    for (const auto& entry : fs::recursive_directory_iterator(TEST_DIR)) {
        if (!entry.is_regular_file()) continue;
        if (entry.path().extension() != ".enc") continue;

        std::string src = entry.path().string();
        std::string dst = src.substr(0, src.size() - 4);

        // TODO: Call decryptSimFile() and log result
        log("RECOVERED: " + src + " → " + dst);
        recovered++;
    }

    log("Recovery complete. Recovered: " + std::to_string(recovered) +
        ", failed: " + std::to_string(failed));
}

int main(int argc, char* argv[]) {
    g_log.open(LOG_FILE, std::ios::app);

    bool recover = false, dryRun = false;
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "--recover") recover = true;
        if (std::string(argv[i]) == "--dry-run") dryRun  = true;
    }

    if (!fs::exists(TEST_DIR)) {
        printf("[-] Test directory not found: %s\n", TEST_DIR);
        printf("    mkdir C:\\RansomwareSimTest\n");
        printf("    echo approved > C:\\RansomwareSimTest\\SIM_APPROVED.flag\n");
        printf("    (then add some test files)\n");
        return 1;
    }

    if (recover) runRecovery();
    else         runSimulation(dryRun);

    return 0;
}
