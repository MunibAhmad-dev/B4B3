// Solution 01 — Variables, types, sizeof

#include <iostream>
#include <iomanip>

typedef unsigned char BYTE;

int main() {
    // Task 1
    int         a = 42;
    long long   b = 9876543210LL;
    double      d = 3.14159;
    char        c = 'Z';
    bool        ok = true;

    std::cout << "int:       " << a  << "\n";
    std::cout << "long long: " << b  << "\n";
    std::cout << "double:    " << d  << "\n";
    std::cout << "char:      " << c  << "\n";
    std::cout << "bool:      " << ok << "\n\n";

    // Task 2
    std::cout << "sizeof(int)       = " << sizeof(int)       << "\n";
    std::cout << "sizeof(long long) = " << sizeof(long long) << "\n";
    std::cout << "sizeof(double)    = " << sizeof(double)    << "\n";
    std::cout << "sizeof(char)      = " << sizeof(char)      << "\n";
    std::cout << "sizeof(bool)      = " << sizeof(bool)      << "\n\n";

    // Task 3
    unsigned int u = 4294967295u;
    std::cout << "u = " << u << "\n";
    u += 1;
    std::cout << "u + 1 = " << u << "\n";
    // u wraps around to 0 — this is unsigned integer overflow / wrap-around.
    // It is defined behaviour for unsigned types. For signed int it would be UB.
    std::cout << "\n";

    // Task 4
    int x = 0b0011;  // 3
    int y = 0b0101;  // 5
    std::cout << "x | y = " << (x | y) << "\n";  // 7

    BYTE flags = 0;
    flags |= (1 << 3);  // set bit 3
    if ((flags & (1 << 3)) != 0)
        std::cout << "bit 3 is set\n";
    else
        std::cout << "bit 3 is clear\n";

    return 0;
}
