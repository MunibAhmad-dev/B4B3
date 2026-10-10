# Module 35 — DLL / COM Development

## 1. DLL Anatomy

### 1.1 What Is a DLL?

A Dynamic-Link Library (DLL) is a PE file with characteristics bit `IMAGE_FILE_DLL` (0x2000) set in the COFF header. The operating system maps it into a process's virtual address space and resolves imports from it at load time or, for delay-loaded DLLs, on first call. Unlike an EXE, a DLL has no entry point in the traditional sense — instead, it has an optional `DllMain` notification callback.

### 1.2 DllMain and Notification Reasons

```cpp
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:  // DLL loaded into a process
        case DLL_PROCESS_DETACH:  // DLL unloaded (lpvReserved != NULL means process is terminating)
        case DLL_THREAD_ATTACH:   // New thread created in the process
        case DLL_THREAD_DETACH:   // Thread exits cleanly
    }
    return TRUE; // FALSE on DLL_PROCESS_ATTACH aborts the load
}
```

**Critical rules for DllMain:**
- DllMain runs under the loader lock. You must not call `LoadLibrary`, `FreeLibrary`, `CoInitialize`, or any function that acquires another lock.
- Allocating memory with `HeapAlloc`/`malloc` is safe; calling into the CRT's init routines may deadlock.
- Creating threads is allowed but they may not call any function that requires the loader lock.
- `DisableThreadLibraryCalls(hinstDLL)` in `DLL_PROCESS_ATTACH` suppresses `DLL_THREAD_ATTACH`/`DLL_THREAD_DETACH` notifications, which is a common optimization.

### 1.3 __declspec(dllexport) and __declspec(dllimport)

```cpp
// In the DLL (exporting)
__declspec(dllexport) int Add(int a, int b) { return a + b; }

// In the client (importing)
__declspec(dllimport) int Add(int a, int b);
```

The compiler decorates C++ names (name mangling). To suppress mangling and export a plain C symbol:

```cpp
extern "C" __declspec(dllexport) int Add(int a, int b) { return a + b; }
```

### 1.4 Module Definition (.def) Files

A `.def` file gives the linker explicit control over exports, including ordinal assignment:

```
LIBRARY   myDll
EXPORTS
    Add         @1          ; exported by name and ordinal 1
    Sub         @2 NONAME   ; exported by ordinal only, no name in EAT
    GetVersion  @3
    _InternalHelper @4 PRIVATE ; not exported to the outside world
```

**Why ordinals matter for security:** malware frequently imports functions by ordinal to bypass naive import-table scanning. A DLL whose EAT maps ordinal 5 to a shellcode loader is harder to detect than one with a named `ExecuteShellcode` export.

### 1.5 Ordinal Exports

Every exported function has both an ordinal and, optionally, a name. The Export Address Table (EAT) in the PE data directory stores RVAs indexed by ordinal. `GetProcAddress(hDll, (LPCSTR)5)` loads by ordinal. `GetProcAddress(hDll, "Add")` performs a binary search in the Export Name Table.

### 1.6 Delay-Load DLLs

With `/DELAYLOAD:foo.dll` (MSVC) or `--delayed=foo.dll` (lld-link), the linker generates a stub that calls `__delayLoadHelper2` on the first invocation of any function in that DLL. The DLL is not loaded until then, reducing startup time and allowing graceful degradation when the DLL is absent.

```cpp
#include <delayimp.h>
#pragma comment(lib, "delayimp")
#pragma comment(linker, "/DELAYLOAD:version.dll")
```

Delay-loaded imports are a common technique in implant development because they defer resolution and can complicate static analysis.

---

## 2. COM Fundamentals

### 2.1 What Is COM?

The Component Object Model (COM) is a binary interface standard that allows objects implemented in different languages and processes to communicate. A COM object is any object that implements `IUnknown`. The runtime (`ole32.dll`) manages object creation, lifetime via reference counting, and interface negotiation.

### 2.2 IUnknown: The Root Interface

Every COM interface inherits from `IUnknown`, which declares three methods:

```cpp
HRESULT QueryInterface(REFIID riid, void** ppvObject);
ULONG   AddRef();
ULONG   Release();
```

**QueryInterface:** given an interface ID (IID), the object either returns a pointer to a valid implementation of that interface (and increments the reference count) or returns `E_NOINTERFACE`.

**AddRef / Release:** COM uses reference counting for lifetime management. When the reference count reaches zero, the object deletes itself. Callers must `AddRef` when copying a pointer and `Release` when done.

### 2.3 HRESULT

`HRESULT` is a 32-bit value: bit 31 = severity (0 = success, 1 = failure), bits 16–30 = facility code, bits 0–15 = status code. Common values:

| Constant | Value | Meaning |
|----------|-------|---------|
| `S_OK` | 0x00000000 | Success |
| `S_FALSE` | 0x00000001 | Success, alternate result |
| `E_NOINTERFACE` | 0x80004002 | Interface not supported |
| `E_POINTER` | 0x80004003 | NULL pointer |
| `E_OUTOFMEMORY` | 0x8007000E | Out of memory |
| `CLASS_E_NOAGGREGATION` | 0x80040110 | Aggregation not supported |
| `REGDB_E_CLASSNOTREG` | 0x80040154 | CLSID not registered |

Use `SUCCEEDED(hr)` / `FAILED(hr)` macros instead of comparing to `S_OK` directly — many COM methods return non-zero success codes.

### 2.4 GUIDs, CLSIDs, and IIDs

A Globally Unique Identifier (GUID) is a 128-bit value guaranteed to be universally unique. COM uses two specialisations:

- **CLSID** — identifies a coclass (a concrete implementation). Stored in HKCR\CLSID\{...}.
- **IID** — identifies an interface. Stored in HKCR\Interface\{...} for proxy/stub lookup.

Define a GUID in code:

```cpp
// {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
static const GUID CLSID_MyObject = {
    0xa1b2c3d4, 0xe5f6, 0x7890,
    { 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90 }
};
```

Or with the helper macro (requires `<initguid.h>` in exactly one translation unit):

```cpp
// myinterface.h
DEFINE_GUID(CLSID_MyObject, 0xa1b2c3d4, 0xe5f6, 0x7890,
            0xab,0xcd,0xef,0x12,0x34,0x56,0x78,0x90);
```

### 2.5 In-Process Server Lifecycle

An in-process COM server is a DLL. The lifecycle is:

```
Client calls CoCreateInstance(CLSID_X, ...)
    → ole32 looks up HKCR\CLSID\{CLSID_X}\InprocServer32 → path to DLL
    → LoadLibrary(path)
    → GetProcAddress(hDll, "DllGetClassObject")
    → DllGetClassObject(CLSID_X, IID_IClassFactory, &pFactory)
    → pFactory->CreateInstance(NULL, IID_X, &pObj)
    → pFactory->Release()
    → returns pObj to caller
```

The DLL must export these four functions:

| Export | Purpose |
|--------|---------|
| `DllGetClassObject` | Returns an `IClassFactory` for a given CLSID |
| `DllCanUnloadNow` | Returns `S_OK` if the DLL has no outstanding objects |
| `DllRegisterServer` | Writes registry entries for all CLSIDs (called by `regsvr32`) |
| `DllUnregisterServer` | Removes those entries |

### 2.6 IClassFactory

```cpp
interface IClassFactory : IUnknown {
    HRESULT CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppvObject);
    HRESULT LockServer(BOOL fLock);
};
```

`pUnkOuter` is non-NULL only when aggregation is requested. Most simple servers return `CLASS_E_NOAGGREGATION` for non-NULL `pUnkOuter`.

### 2.7 CLSID / ProgID Registration

`regsvr32` calls `DllRegisterServer` which must write:

```
HKCR\CLSID\{CLSID_X}\
    (Default) = "Human-readable name"
    InprocServer32\
        (Default) = "C:\path\to\server.dll"
        ThreadingModel = "Apartment"   (or "Free", "Both", "Neutral")
HKCR\MyApp.MyObject.1\
    (Default) = "Human-readable name"
    CLSID\
        (Default) = "{CLSID_X}"
HKCR\MyApp.MyObject\
    (Default) = "Human-readable name"
    CurVer\
        (Default) = "MyApp.MyObject.1"
```

ProgIDs (e.g. `Excel.Application`) are human-readable aliases for CLSIDs. `CLSIDFromProgID(L"Excel.Application", &clsid)` resolves a ProgID to a CLSID.

---

## 3. COM Threading Models

### 3.1 Apartments

COM uses "apartments" to enforce threading rules:

| Model | Description | `CoInitialize[Ex]` flag |
|-------|-------------|------------------------|
| Single-Threaded Apartment (STA) | One thread per apartment. COM serializes calls using a hidden message loop. | `COINIT_APARTMENTTHREADED` |
| Multi-Threaded Apartment (MTA) | All MTA threads share one apartment. No serialization; caller must synchronize. | `COINIT_MULTITHREADED` |
| Neutral Apartment (NA) | Thread-neutral; introduced in COM+. | `COINIT_DISABLE_OLE1DDE` |

`CoInitialize(NULL)` initializes the current thread in an STA (equivalent to `CoInitializeEx(NULL, COINIT_APARTMENTTHREADED)`).

### 3.2 ThreadingModel Registry Value

The `ThreadingModel` value under `InprocServer32` tells COM which apartments can call the object directly (without marshaling):

- `Apartment` — only STA threads. If created from an MTA, COM marshals all calls.
- `Free` — only MTA. STA callers get a proxy.
- `Both` — STA or MTA, no marshaling needed.
- `Neutral` — any apartment.

A mismatch causes COM to inject a proxy/stub, adding marshal overhead. Security tools watch for objects registered as `Free` or `Both` that do unsafe operations, as this bypasses the STA serialization fence.

### 3.3 Marshal-by-Reference vs Marshal-by-Value

For cross-apartment calls, COM needs a proxy (in-process stub that packages arguments) and a stub (in the server's apartment that unpacks them). This is "marshal by reference." The proxy/stub DLL is registered under `HKCR\Interface\{IID}\ProxyStubClsid32`.

For interfaces defined with a typelib (IDispatch-based), the standard type library marshaler (`oleaut32.dll`) can marshal automatically without a custom proxy/stub.

---

## 4. IDispatch for Scripting and VBA Automation

### 4.1 Late Binding

`IDispatch` enables scripting languages (VBScript, JavaScript) and Office VBA to call COM objects without compile-time knowledge of interfaces:

```cpp
interface IDispatch : IUnknown {
    HRESULT GetTypeInfoCount(UINT* pctinfo);
    HRESULT GetTypeInfo(UINT iTInfo, LCID lcid, ITypeInfo** ppTInfo);
    HRESULT GetIDsOfNames(REFIID riid, LPOLESTR* rgszNames, UINT cNames,
                          LCID lcid, DISPID* rgDispId);
    HRESULT Invoke(DISPID dispIdMember, REFIID riid, LCID lcid,
                   WORD wFlags, DISPPARAMS* pDispParams,
                   VARIANT* pVarResult, EXCEPINFO* pExcepInfo, UINT* puArgErr);
};
```

`GetIDsOfNames` maps a method name like `"CreateObject"` to a numeric `DISPID`. `Invoke` dispatches a call by DISPID with variant-typed arguments.

### 4.2 Security Relevance

Macro-based malware (Office macros, VBScript WSH) uses `IDispatch`-based COM objects: `WScript.Shell`, `Shell.Application`, `Scripting.FileSystemObject`. These are all IDispatch servers. A blue team analyst must be able to trace VBA `CreateObject("WScript.Shell")` calls to `CoCreateInstance` → CLSID lookup → DLL load.

### 4.3 VARIANT and SAFEARRAY

`VARIANT` is the universal container type for Automation:

```cpp
VARIANT v;
VariantInit(&v);
v.vt = VT_BSTR;
v.bstrVal = SysAllocString(L"hello");
// ... use v ...
VariantClear(&v); // frees memory
```

`SAFEARRAY` is a bounds-safe array used to pass collections across COM calls:

```cpp
SAFEARRAY* psa = SafeArrayCreateVector(VT_BSTR, 0, count);
// SafeArrayPutElement / SafeArrayGetElement to fill/read
SafeArrayDestroy(psa);
```

---

## 5. COM Hijacking for Persistence

### 5.1 How COM Hijacking Works

Windows looks up CLSIDs in this order:

1. `HKCU\SOFTWARE\Classes\CLSID\{...}` (per-user, no elevation needed)
2. `HKCR\CLSID\{...}` (machine-wide, requires admin)

An attacker with standard user privileges can write to HKCU. If a CLSID registered in HKLM is **not** present in HKCU, the attacker can insert a record there pointing to a malicious DLL. The next time any process calls `CoCreateInstance` for that CLSID, COM will load the attacker's DLL instead of the legitimate one.

### 5.2 Identifying Hijackable CLSIDs

The attack surface consists of CLSIDs that:
- Are invoked by regularly-running processes (Explorer, scheduled tasks, auto-start components)
- Are registered in HKLM only
- Have no HKCU entry

Tools like `COMHijackToolkit` and Process Monitor (filter: `RegQueryValue`, path contains `CLSID`, result `NAME NOT FOUND`) identify candidate CLSIDs.

### 5.3 Registry Keys

```
HKCU\SOFTWARE\Classes\CLSID\{Target-CLSID}\
    InprocServer32\
        (Default) = "C:\Users\attacker\evil.dll"
        ThreadingModel = "Apartment"
```

This key is writable by any standard user without UAC prompts.

### 5.4 Blue Team Detection

| Signal | Detection Method |
|--------|-----------------|
| New HKCU CLSID write | Sysmon Event ID 13 (RegistryValueSet) with path `HKCU\...\CLSID` |
| Unsigned DLL loaded from user-writable path | Sysmon Event ID 7 (ImageLoad), check `Signed` field |
| DLL loaded from `%APPDATA%`, `%TEMP%`, or home directory | EDR file-load telemetry |
| Process loads DLL not in its normal baseline | Behavioral ML in EDR |
| `DllHost.exe` with unexpected module | Process-creation + module-load correlation |

### 5.5 Defenses

- HKCU CLSID writes should trigger alerts in enterprise environments.
- Application Control (AppLocker / WDAC) can block DLLs from user-writable paths.
- The `DisableRegistryTools` policy and Protected Users group do not prevent HKCU CLSID writes but reduce the blast radius.
- Auditing all `HKCU\SOFTWARE\Classes\CLSID` subkey creations in your SIEM provides high-fidelity alerting with low false-positive rates in non-developer environments.

---

## 6. Proxy/Stub DLLs vs. Typelib Registration

### 6.1 Custom Proxy/Stub DLL

For custom interfaces (vtable-based, not IDispatch), COM needs a proxy/stub DLL to marshal calls across apartment or process boundaries. The MIDL compiler generates the marshaling code from an IDL file:

```
midl myinterface.idl /out generated\
cl /LD generated\myinterface_p.c generated\dlldata.c /link /DEF:generated\myinterface.def
regsvr32 myinterface_ps.dll
```

The proxy/stub CLSID is registered under `HKCR\Interface\{IID}\ProxyStubClsid32`.

### 6.2 Typelib (Free-Threaded Marshaler via oleaut32)

If you define your interface with `dual` or `oleautomation` in IDL, `oleaut32.dll`'s universal marshaler can handle marshaling using the type library. You register the typelib with `RegisterTypeLib` and set `HKCR\Interface\{IID}\TypeLib` to the typelib GUID. This is simpler but has overhead and limitations compared to a custom proxy.

### 6.3 Security Implication

Registering a proxy/stub DLL associates a CLSID with a COM server. Attackers register malicious proxy/stub DLLs to gain execution when COM tries to marshal a legitimate interface. The CLSID for the proxy/stub is often overlooked during forensic investigations.

---

## 7. How Security Software Detects DLL Injection vs. COM Loading

### 7.1 DLL Injection Indicators

| Technique | Detection Signal |
|-----------|-----------------|
| `CreateRemoteThread` + `LoadLibrary` | Suspicious cross-process thread creation (Sysmon Event 8); `LoadLibrary` pointer as thread start address |
| `SetWindowsHookEx` | `NtSetWindowsHookEx` hook installation with a remote process module |
| Reflective DLL injection | No `LoadLibrary` call; PE mapped via `VirtualAllocEx`+`WriteProcessMemory`; MZ/PE magic in remote memory |
| Process hollowing | `NtUnmapViewOfSection` on legitimate image followed by `VirtualAllocEx` at same base |
| `AppInit_DLLs` | Registry key `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` |
| Manual mapping | Direct syscall to `NtMapViewOfSection`; no image load event in ETW |

### 7.2 COM Loading Indicators (Legitimate Path)

Normal COM in-proc loading follows this syscall pattern:
1. `NtOpenKey` → HKCR\CLSID\{...}
2. `NtQueryValueKey` → InprocServer32
3. `LdrLoadDll` (via `LoadLibrary` inside `ole32.dll`)
4. `GetProcAddress("DllGetClassObject")`

EDR products baseline this pattern and flag deviations: wrong DLL path, unsigned DLL, DLL in writable location, or a DLL that does not export `DllGetClassObject`.

### 7.3 COM Hijack vs. Normal Load

The HKCU-override path looks identical to normal COM loading at the API level, but:
- The DLL path resolves to a user-writable directory.
- The DLL may be unsigned or unsigned by an unexpected signer.
- The HKCU key was created recently (check registry MRU timestamps).
- The DLL exports `DllGetClassObject` but may not export `DllRegisterServer` or `DllCanUnloadNow`.

---

## 8. ATL vs. WRL vs. Raw IUnknown

### 8.1 Raw IUnknown

Writing COM by hand (raw `IUnknown`) is the most instructive approach and the one used in the exercises:

```cpp
class CMyObject : public IMyInterface {
    volatile LONG m_refCount = 0;
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override { ... }
    ULONG   STDMETHODCALLTYPE AddRef()  override { return InterlockedIncrement(&m_refCount); }
    ULONG   STDMETHODCALLTYPE Release() override {
        ULONG n = InterlockedDecrement(&m_refCount);
        if (n == 0) delete this;
        return n;
    }
};
```

### 8.2 ATL (Active Template Library)

ATL provides `CComObjectRootEx`, `CComCoClass`, and `CComObject<T>` template classes that generate the boilerplate. Used in classic Win32 COM server development.

```cpp
class ATL_NO_VTABLE CMyObject :
    public CComObjectRootEx<CComSingleThreadModel>,
    public CComCoClass<CMyObject, &CLSID_MyObject>,
    public IMyInterface
{
    BEGIN_COM_MAP(CMyObject)
        COM_INTERFACE_ENTRY(IMyInterface)
        COM_INTERFACE_ENTRY(IUnknown)
    END_COM_MAP()
};
```

### 8.3 WRL (Windows Runtime C++ Template Library)

WRL targets WinRT/COM+ hybrid models, used heavily in Universal Windows Platform (UWP). Similar template patterns to ATL but targets the Windows Runtime ABI.

### 8.4 Choosing for Security Research

Raw IUnknown is preferable for implant or payload development:
- No ATL/WRL dependency (smaller, fewer imports to enumerate).
- Full control over QueryInterface logic (can implement interface spoofing).
- No CRT static initializers unless you add them.
- Easier to compile with MinGW or Clang cross-toolchain.

---

## 9. Summary: Key Concepts Checklist

- DllMain notification reasons and loader-lock restrictions
- Export by name vs. export by ordinal; .def file syntax
- Delay-load DLL mechanism and its use in obfuscating imports
- IUnknown: QueryInterface contract, AddRef/Release symmetry
- HRESULT structure; `SUCCEEDED`/`FAILED` macros
- GUID/CLSID/IID distinction and GUID literal syntax
- In-proc COM server lifecycle (4 required exports)
- CLSID registry layout (InprocServer32, ThreadingModel)
- STA vs MTA: when marshaling is required
- IDispatch late binding; VBA/script attack surface
- COM hijacking: HKCU override, detection via Sysmon Event 13
- Proxy/stub DLL registration under `HKCR\Interface`
- DLL injection detection signals vs. normal COM load pattern
- Raw IUnknown vs. ATL/WRL: trade-offs for security research
