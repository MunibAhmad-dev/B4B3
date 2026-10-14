#pragma once
#include <string>

// Compile-time XOR string obfuscation.
// S("literal")  → std::string   (narrow, char*)
// SW(L"literal") → std::wstring  (wide, wchar_t*) — covers all W-variant API strings
// With -O2, the plaintext is consumed only at compile time and does not appear in the binary.
// Each char i is XOR'd with key(i) = 0xD3 ^ ((i*41 + 97) & 0xFF).

template<size_t N>
struct _Xs {
    char e[N];
    constexpr _Xs(const char (&s)[N]) : e{} {
        for (size_t i = 0; i < N; ++i)
            e[i] = char(int(s[i]) ^ (int(0xD3) ^ int(static_cast<unsigned char>((i * 41u + 97u) & 0xFFu))));
    }
    std::string d() const {
        std::string r(N > 0 ? N - 1 : 0, '\0');
        for (size_t i = 0; i + 1 < N; ++i)
            r[i] = char(int(e[i]) ^ (int(0xD3) ^ int(static_cast<unsigned char>((i * 41u + 97u) & 0xFFu))));
        return r;
    }
};

// Wide-string variant: key is applied per wchar_t index, low-byte only (wide chars ≤ 0x7F here).
template<size_t N>
struct _XsW {
    wchar_t e[N];
    constexpr _XsW(const wchar_t (&s)[N]) : e{} {
        for (size_t i = 0; i < N; ++i) {
            unsigned char k = static_cast<unsigned char>((int(0xD3) ^ int(static_cast<unsigned char>((i * 41u + 97u) & 0xFFu))));
            e[i] = wchar_t(int(s[i]) ^ int(k));
        }
    }
    std::wstring d() const {
        std::wstring r(N > 0 ? N - 1 : 0, L'\0');
        for (size_t i = 0; i + 1 < N; ++i) {
            unsigned char k = static_cast<unsigned char>((int(0xD3) ^ int(static_cast<unsigned char>((i * 41u + 97u) & 0xFFu))));
            r[i] = wchar_t(int(e[i]) ^ int(k));
        }
        return r;
    }
};

#define S(s)  ([]() -> std::string  { constexpr _Xs<sizeof(s)>                  _x(s); return _x.d(); }())
#define SW(s) ([]() -> std::wstring { constexpr _XsW<sizeof(s)/sizeof(wchar_t)> _x(s); return _x.d(); }())
