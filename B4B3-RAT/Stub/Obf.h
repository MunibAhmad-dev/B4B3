#pragma once
#include <string>

// Compile-time XOR string obfuscation.
// S("literal") returns std::string, decrypted at runtime.
// With -O2, the plaintext is consumed only at compile time and does not appear in the binary.
// Each char i is XOR'd with key(i) = 0x4B ^ ((i*23 + 63) & 0xFF).

template<size_t N>
struct _Xs {
    char e[N];
    constexpr _Xs(const char (&s)[N]) : e{} {
        for (size_t i = 0; i < N; ++i)
            e[i] = char(int(s[i]) ^ (int(0x4B) ^ int(static_cast<unsigned char>((i * 23u + 63u) & 0xFFu))));
    }
    std::string d() const {
        std::string r(N > 0 ? N - 1 : 0, '\0');
        for (size_t i = 0; i + 1 < N; ++i)
            r[i] = char(int(e[i]) ^ (int(0x4B) ^ int(static_cast<unsigned char>((i * 23u + 63u) & 0xFFu))));
        return r;
    }
};

#define S(s) ([]() -> std::string { constexpr _Xs<sizeof(s)> _x(s); return _x.d(); }())
