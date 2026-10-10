// ex01_crackme_target.cpp — CRACKME TARGET (reverse this to find the serial)
// Build and run: ex01.exe <name> <serial>
// Goal: find a serial that passes the check for your chosen name.
// Compile: g++ -std=c++17 -O1 -o ex01.exe ex01_crackme_target.cpp
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static int check(const char* name, const char* serial) {
    if (!name || !serial || strlen(name)<3 || strlen(serial)!=8) return 0;
    uint32_t key=0;
    for(int i=0;name[i];++i) key = ((key<<5)+key) ^ (unsigned char)name[i]; // DJB2-like
    char expected[9]{};
    for(int i=0;i<8;++i) expected[i]='A'+(((key>>(i*4))&0xF)%26);
    expected[8]=0;
    return strcmp(serial,expected)==0;
}
int main(int argc, char* argv[]) {
    if (argc<3){printf("Usage: ex01.exe <name> <serial>\n");return 1;}
    if (check(argv[1],argv[2])) printf("[+] CORRECT — serial accepted!\n");
    else                        printf("[-] Wrong serial.\n");
    return 0;
}
