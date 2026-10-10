/*
  User-mode client for ex02_ioctl_channel.c
  -------------------------------------------
  Talks to the kernel driver via DeviceIoControl.
  Run AFTER sc start MyDriver.

  Compile:
    g++ -std=c++17 -Wall -o ex02_client.exe ex02_ioctl_usermode.cpp -lkernel32
*/
#include <windows.h>
#include <iostream>

#define IOCTL_MYDRIVER_PING \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

int main() {
    HANDLE h = CreateFileA("\\\\.\\MyDriver",
                            GENERIC_READ | GENERIC_WRITE,
                            0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        printf("[-] Can't open driver device. Is sc start MyDriver running? Error: %lu\n",
               GetLastError());
        return 1;
    }
    printf("[+] Opened driver device\n");

    char response[64] = {};
    DWORD returned = 0;
    BOOL ok = DeviceIoControl(h, IOCTL_MYDRIVER_PING,
                               nullptr, 0,
                               response, sizeof(response),
                               &returned, nullptr);
    if (ok)
        printf("[+] Kernel says: %s (%lu bytes)\n", response, returned);
    else
        printf("[-] DeviceIoControl failed: %lu\n", GetLastError());

    CloseHandle(h);
    return 0;
}
