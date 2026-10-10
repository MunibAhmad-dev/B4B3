// sol01_keygen.cpp — keygen for ex01_crackme_target
// Reversing the check: DJB2 hash of name → 8-char serial from hex nibbles
// Compile: g++ -std=c++17 -o sol01.exe sol01_keygen.cpp
// Usage: sol01.exe <name>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
int main(int argc, char* argv[]) {
    if(argc<2){printf("Usage: sol01.exe <name>\n");return 1;}
    const char* name=argv[1];
    uint32_t key=0;
    for(int i=0;name[i];++i) key=((key<<5)+key)^(unsigned char)name[i];
    char serial[9]{};
    for(int i=0;i<8;++i) serial[i]='A'+(((key>>(i*4))&0xF)%26);
    serial[8]=0;
    printf("Name:   %s\nSerial: %s\n",name,serial);
    return 0;
}
