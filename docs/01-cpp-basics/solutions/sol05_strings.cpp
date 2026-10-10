// Solution 05 — Strings

#include <iostream>
#include <string>
#include <cstring>
#include <iomanip>

std::string xorStr(const std::string& s, char key) {
    std::string out = s;
    for (char& c : out) c ^= key;
    return out;
}

int main() {
    // Task 1
    char buf[64] = "OneDriveHelper";
    std::cout << "length: " << strlen(buf) << "\n";
    char buf2[64];
    strncpy(buf2, buf, sizeof(buf2) - 1);
    buf2[sizeof(buf2) - 1] = '\0';
    strncat(buf2, ".exe", sizeof(buf2) - strlen(buf2) - 1);
    std::cout << "final: " << buf2 << "\n\n";

    // Task 2
    std::string s = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    std::cout << "length: " << s.length() << "\n";
    size_t pos = s.find("Run");
    std::cout << "Run at pos: " << pos << "\n";
    std::cout << "substr: " << s.substr(pos) << "\n";
    // Replace HKEY_CURRENT_USER with HKCU
    size_t hPos = s.find("HKEY_CURRENT_USER");
    s.replace(hPos, strlen("HKEY_CURRENT_USER"), "HKCU");
    std::cout << "modified: " << s << "\n\n";

    // Task 3
    std::string portStr = "Port: " + std::to_string(4444);
    std::cout << portStr << "\n";
    int ip_part = std::stoi("192");
    std::cout << ip_part * 256 << "\n\n";

    // Task 4
    std::string enc = xorStr("cmd.exe", 0x42);
    std::cout << "encrypted: ";
    for (unsigned char c : enc)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c << " ";
    std::cout << "\n";
    std::cout << "decrypted: " << xorStr(enc, 0x42) << "\n";

    return 0;
}
