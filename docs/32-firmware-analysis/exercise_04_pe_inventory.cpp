// exercise_04_pe_inventory.cpp
// Module 32 — Firmware Analysis, Exercise 4
//
// Goal: Scan a directory of .efi files extracted from firmware.
//       For each file, print: filename, machine type, subsystem, entry point RVA,
//       and the first few DLL names from the import table.
//
// Compile: g++ -std=c++17 -Wall -o ex04.exe exercise_04_pe_inventory.cpp
// Run:     ex04.exe <directory_of_efi_files>
//
// Note: UEFI PE images usually have NO import table (they use UEFI protocols
//       instead of DLL imports). Some shell applications do import from the shell.
//
// Windows-specific: uses FindFirstFile/FindNextFile for directory listing
//                   and CreateFileMapping/MapViewOfFile for file mapping.

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <windows.h>

// PE header constants
#define IMAGE_DOS_SIGNATURE   0x5A4D      // "MZ"
#define IMAGE_NT_SIGNATURE    0x00004550  // "PE\0\0"

// Machine types
#define IMAGE_FILE_MACHINE_I386   0x014C
#define IMAGE_FILE_MACHINE_AMD64  0x8664
#define IMAGE_FILE_MACHINE_ARM64  0xAA64
#define IMAGE_FILE_MACHINE_EBC    0x0EBC  // EFI Byte Code

// Subsystem values for UEFI
#define IMAGE_SUBSYSTEM_EFI_APPLICATION         10
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER 11
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER      12
#define IMAGE_SUBSYSTEM_EFI_ROM                 13

// -------------------------------------------------------------------
// TODO: Implement machineName(machine)
//
// Return a descriptive string for IMAGE_FILE_MACHINE_* values:
//   0x014C  -> "I386"
//   0x8664  -> "AMD64"
//   0xAA64  -> "ARM64 (AArch64)"
//   0x0EBC  -> "EFI Byte Code"
//   default -> "Unknown(0x%04X)"
// -------------------------------------------------------------------
static std::string machineName(uint16_t machine) {
    // TODO: implement
    (void)machine;
    return "TODO";
}

// -------------------------------------------------------------------
// TODO: Implement subsystemName(sub)
//
// Return a string for EFI subsystem values:
//   10 -> "EFI_APPLICATION"
//   11 -> "EFI_BOOT_SERVICE_DRIVER"
//   12 -> "EFI_RUNTIME_DRIVER"
//   13 -> "EFI_ROM"
//   default -> "Other(%u)"
// -------------------------------------------------------------------
static std::string subsystemName(uint16_t sub) {
    // TODO: implement
    (void)sub;
    return "TODO";
}

// -------------------------------------------------------------------
// TODO: Implement scanPE(filePath)
//
// Algorithm:
//   1. CreateFile + CreateFileMapping + MapViewOfFile to get a read-only view
//   2. Check IMAGE_DOS_HEADER::e_magic == IMAGE_DOS_SIGNATURE ("MZ")
//   3. Get NT headers: IMAGE_NT_HEADERS* nth = base + dosHdr->e_lfanew
//   4. Check nth->Signature == IMAGE_NT_SIGNATURE ("PE\0\0")
//   5. Determine 32-bit vs 64-bit from OptionalHeader.Magic:
//        0x10B = PE32 (IMAGE_NT_OPTIONAL_HDR32_MAGIC)
//        0x20B = PE32+ (IMAGE_NT_OPTIONAL_HDR64_MAGIC)
//   6. Print:
//        "  Machine    : <machineName>\n"
//        "  Subsystem  : <subsystemName>\n"
//        "  EntryPoint : 0x%08X (RVA)\n"
//        "  Sections   : %u\n"
//   7. Walk the import directory (DataDirectory[1]):
//        a. Get VirtualAddress of import table
//        b. Convert RVA to file offset: find which section the RVA falls in,
//           offset = RVA - section.VirtualAddress + section.PointerToRawData
//        c. For each IMAGE_IMPORT_DESCRIPTOR until Name==0:
//             - Convert Name RVA to pointer, print the DLL name
//             - Print first 3 imported function names (OriginalFirstThunk)
//        d. If no import table: print "  Imports    : (none — uses UEFI protocols)\n"
//   8. Unmap and close handles
// -------------------------------------------------------------------
static void scanPE(const std::string& filePath) {
    printf("File: %s\n", filePath.c_str());
    // TODO: implement
    printf("  TODO: implement scanPE\n\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <directory>\n", argv[0]);
        return 1;
    }

    std::string dir = argv[1];
    std::string pattern = dir + "\\*.efi";

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "No .efi files found in: %s\n", dir.c_str());
        return 1;
    }

    int count = 0;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            std::string fullPath = dir + "\\" + fd.cFileName;
            scanPE(fullPath);
            count++;
        }
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);

    printf("Total: %d .efi files scanned\n", count);
    return 0;
}
