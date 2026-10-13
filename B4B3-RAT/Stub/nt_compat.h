#pragma once
// MinGW NT-internals compatibility shim. Include via common.h.
// Provides types from winternl.h / ntstatus.h that MinGW misses.
// MUST be included AFTER <Windows.h>.

// ── Status codes ──────────────────────────────────────────────────────────────
#ifndef NT_SUCCESS
#  define NT_SUCCESS(s)    (((NTSTATUS)(s)) >= 0)
#endif
#ifndef STATUS_SUCCESS
#  define STATUS_SUCCESS   ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_NOT_FOUND
#  define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L)
#endif

// ── UNICODE_STRING / OBJECT_ATTRIBUTES ────────────────────────────────────────
// Windows.h / winnt.h usually provides UNICODE_STRING; guard anyway.
#ifndef _UNICODE_STRING_DEFINED
#  define _UNICODE_STRING_DEFINED
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
#endif

#ifndef _OBJECT_ATTRIBUTES_DEFINED
#  define _OBJECT_ATTRIBUTES_DEFINED
typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
#endif

// ── PEB / Loader ───────────────────────────────────────────────────────────────
#ifndef _PEB_LDR_DATA_DEFINED
#  define _PEB_LDR_DATA_DEFINED
typedef struct _PEB_LDR_DATA {
    ULONG      Length;
    BOOL       Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
#endif

#ifndef _PEB_DEFINED
#  define _PEB_DEFINED
typedef struct _PEB {
    BYTE           InheritedAddressSpace;
    BYTE           ReadImageFileExecOptions;
    BYTE           BeingDebugged;
    BYTE           BitField;
    PVOID          Mutant;
    PVOID          ImageBaseAddress;
    PPEB_LDR_DATA  Ldr;
    PVOID          ProcessParameters;
    PVOID          SubSystemData;
    PVOID          ProcessHeap;
    // Remaining fields not needed; do not add — size-sensitive casts rely on
    // accessing only the fields above by name, not by struct size.
} PEB, *PPEB;
#endif

#ifndef _LDR_DATA_TABLE_ENTRY_DEFINED
#  define _LDR_DATA_TABLE_ENTRY_DEFINED
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG          Flags;
    USHORT         LoadCount;
    USHORT         TlsIndex;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
#endif

// ── Process information ────────────────────────────────────────────────────────
#ifndef _PROCESSINFOCLASS_DEFINED
#  define _PROCESSINFOCLASS_DEFINED
typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation    = 0,
    ProcessDebugPort           = 7,
    ProcessWow64Information    = 26,
    ProcessImageFileName       = 27,
    ProcessBreakOnTermination  = 29,
    ProcessDebugObjectHandle   = 30,
    ProcessDebugFlags          = 31,
} PROCESSINFOCLASS;
#endif

#ifndef _PROCESS_BASIC_INFORMATION_DEFINED
#  define _PROCESS_BASIC_INFORMATION_DEFINED
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID     Reserved1;
    PVOID     PebBaseAddress;
    PVOID     Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID     Reserved3;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;
#endif
