#pragma once
// MinGW NT-internals compatibility shim. Include via common.h.
// Pull in <winternl.h> first so its include-guard blocks any later direct
// includes (e.g. Protector.cpp), then patch the gaps.

#include <winternl.h>   // PEB/PPEB, LDR_DATA_TABLE_ENTRY/PLDR_DATA_TABLE_ENTRY,
                        // OBJECT_ATTRIBUTES/POBJECT_ATTRIBUTES, UNICODE_STRING,
                        // PROCESSINFOCLASS, PROCESS_BASIC_INFORMATION, NTSTATUS

// ntsecapi.h typedef's UNICODE_STRING as LSA_UNICODE_STRING (different struct
// tag) which conflicts with winternl.h's definition.  Set the guard ntsecapi.h
// checks so it skips its own redefinition.
#ifndef __UNICODE_STRING_DEFINED
#  define __UNICODE_STRING_DEFINED
#endif

// NT status helpers not provided by winternl.h.
#ifndef NT_SUCCESS
#  define NT_SUCCESS(s)    (((NTSTATUS)(s)) >= 0)
#endif
#ifndef STATUS_SUCCESS
#  define STATUS_SUCCESS   ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_NOT_FOUND
#  define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L)
#endif

// MinGW's PEB hides ProcessHeap behind Reserved4[].
// On both x86 and x64, Reserved4[1] maps to ProcessHeap.
#define PEB_PROCESS_HEAP(p) ((p)->Reserved4[1])
