// Solution 02 — Compile-time String Obfuscation

#include <iostream>
#include <string>

static constexpr char OBF_KEY = 0x5A;

constexpr char xorChar(char c, char key) {
    return static_cast<char>(c ^ key);
}

template <size_t N>
struct ObfStr {
    char data[N];

    constexpr ObfStr(const char (&s)[N]) : data{} {
        for (size_t i = 0; i < N; i++)
            data[i] = xorChar(s[i], OBF_KEY);
    }

    std::string decode() const {
        std::string out(data, N - 1);  // exclude null terminator
        for (char& c : out) c ^= OBF_KEY;
        return out;
    }
};

// These are encrypted at compile time — plaintext never appears in .rdata
constexpr ObfStr s1("cmd.exe");
constexpr ObfStr s2("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
constexpr ObfStr s3("hal9th");
constexpr ObfStr s4("explorer.exe");
constexpr ObfStr s5("powershell.exe");

int main() {
    std::cout << s1.decode() << "\n";
    std::cout << s2.decode() << "\n";
    std::cout << s3.decode() << "\n";
    std::cout << s4.decode() << "\n";
    std::cout << s5.decode() << "\n";

    // Task 5 bonus — key derived from string content
    // (More advanced: each string's key is XOR of all its characters)
    // This is left as exploration.

    return 0;
}

/*
  Key insight: because data[] is filled in a constexpr constructor, the compiler
  evaluates the XOR loop at compile time. The binary's .rdata section will contain
  only the encrypted bytes, not the plaintext strings.

  Verify with:
    objdump -s --section=.rdata ex02.exe | grep -A2 "cmd"
    (should find nothing)
*/
