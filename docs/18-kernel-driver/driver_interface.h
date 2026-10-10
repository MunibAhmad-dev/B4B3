// driver_interface.h — shared IOCTL definitions for MyDriver
// Include in both driver (kernel) and client (usermode) code

#pragma once

#include <ntioapi.h>  // kernel side; usermode includes winioctl.h instead

#ifndef CTL_CODE
#include <winioctl.h>
#endif

#define MYDRIVER_DEVICE_TYPE  FILE_DEVICE_UNKNOWN
#define MYDRIVER_DEVICE_NAME  L"\\\\.\\MyDriver"
#define MYDRIVER_SYMLINK      L"\\DosDevices\\MyDriver"

// IOCTL: ping — usermode sends 0, driver echoes "PONG"
#define IOCTL_MYDRIVER_PING   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

// IOCTL: get PID of a process by name
// Input:  null-terminated process name (wchar_t[])
// Output: DWORD pid
#define IOCTL_MYDRIVER_GETPID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Common response for PING
#define MYDRIVER_PONG_MSG  "PONG"
