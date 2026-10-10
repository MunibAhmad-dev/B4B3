# RE-06: PE and ELF File Formats

## PE Format (Portable Executable)

Used by Windows: .exe, .dll, .sys, .ocx

### Structure

```
[DOS Header]       MZ magic; e_lfanew → NT Headers
[DOS Stub]         "This program cannot be run in DOS mode"
[NT Headers]       PE signature + File Header + Optional Header
[Section Headers]  Array of IMAGE_SECTION_HEADER (NumberOfSections entries)
[Sections]         .text  .data  .rdata  .rsrc  .reloc  …
```

### IMAGE_FILE_HEADER

- `Machine`: 0x8664=AMD64, 0x14C=i386, 0xAA64=ARM64
- `NumberOfSections`
- `TimeDateStamp`: compile time (often zeroed/forged)
- `Characteristics`: IMAGE_FILE_DLL, IMAGE_FILE_EXECUTABLE_IMAGE, …

### IMAGE_OPTIONAL_HEADER

- `AddressOfEntryPoint`: RVA; malware often changes this for injected code
- `ImageBase`: preferred load address (ASLR randomises this)
- `SectionAlignment` / `FileAlignment`
- `DataDirectory[16]`: RVA+Size for Import, Export, Resource, Reloc, TLS, …

### Sections

| Name     | Contents                        | Typical Protect |
|----------|---------------------------------|-----------------|
| .text    | Executable code                 | RX              |
| .data    | Initialised writable data       | RW              |
| .rdata   | Read-only data (strings, vtables)| R              |
| .rsrc    | Resources (icons, manifests)    | R               |
| .reloc   | Base-relocation table           | R               |
| .tls     | Thread-local storage            | RW              |
| UPX0/1   | Packed section (empty → high-entropy) | RWX        |

### Import Table (IAT)

`DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]` → array of `IMAGE_IMPORT_DESCRIPTOR`.
Each entry: DLL name RVA, OriginalFirstThunk (INT), FirstThunk (IAT).
At load time the loader overwrites IAT with actual addresses.

### Export Table

`DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]` → `IMAGE_EXPORT_DIRECTORY`.
Contains: Name, Base, NumberOfNames, AddressOfNames, AddressOfFunctions, AddressOfNameOrdinals.

### Relocations

`.reloc` section: base-relocation blocks. Each block covers a 4KB page.
Each entry type: HIGHLOW (32-bit) or DIR64 (64-bit) delta from preferred ImageBase.

### TLS Callbacks

`DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]` → `IMAGE_TLS_DIRECTORY`.
TLS callbacks run **before** the entry point — used by packers/malware as
a hidden execution entry point. Anti-debug: check inside TLS callback.

---

## ELF Format (Linux/UNIX)

- `e_ident[4]`: 0x7F 'E' 'L' 'F'
- `e_type`: ET_EXEC, ET_DYN (shared object / PIE), ET_CORE
- Program headers (PT_LOAD, PT_DYNAMIC, PT_INTERP)
- Section headers (.text, .data, .got, .plt, .dynsym, .rela.plt)
- `.plt` / `.got.plt`: equivalent of IAT; lazy binding via `_dl_runtime_resolve`

---

## Exercises

1. `ex01_parse_headers.cpp`  — Parse PE32/PE32+ and print all headers + data directories
2. `ex02_tls_callback.cpp`   — Add a TLS callback to a program; verify it runs before main()
3. `ex03_rebuild_iat.cpp`    — Walk IAT, log all imports, manually resolve one API via export walk

## Key References

- *PE Format* — docs.microsoft.com/en-us/windows/win32/debug/pe-format
- *An In-Depth Look into the Win32 Portable Executable File Format* — Matt Pietrek (MSDN)
- `pefile` (Python), CFF Explorer, PE-bear for interactive exploration
