# Module 02 — C++ Intermediate

## 1. Classes and Objects

A **class** is a blueprint. An **object** is an instance of that blueprint.

```cpp
class BotConfig {
public:                      // public = accessible from outside
    std::string host;
    int         port;
    bool        tlsEnabled;

    // Constructor — runs when an object is created
    BotConfig(const std::string& h, int p, bool tls)
        : host(h), port(p), tlsEnabled(tls) {}

    // Method
    std::string toString() const {
        return host + ":" + std::to_string(port);
    }
};

// Usage:
BotConfig cfg("192.168.1.1", 4444, true);
std::cout << cfg.toString();
```

**Access modifiers:**
- `public`    — anyone can access
- `private`   — only the class itself can access (default)
- `protected` — class and derived classes

```cpp
class Bot {
private:
    std::string _id;    // internal state — nobody should set this directly

public:
    Bot() { _id = generateId(); }
    std::string getId() const { return _id; }
};
```

---

## 2. Inheritance

```cpp
class Command {
public:
    virtual std::string name() const = 0;  // pure virtual = must override
    virtual void execute() = 0;
};

class ScreenshotCmd : public Command {
public:
    std::string name() const override { return "screenshot"; }
    void execute() override { /* capture screen */ }
};

class ShellCmd : public Command {
    std::string _cmdline;
public:
    ShellCmd(const std::string& cmd) : _cmdline(cmd) {}
    std::string name() const override { return "shell"; }
    void execute() override { /* run command */ }
};
```

**Polymorphism:** you can store different command types in the same container:

```cpp
std::vector<Command*> queue;
queue.push_back(new ScreenshotCmd());
queue.push_back(new ShellCmd("whoami"));

for (auto* cmd : queue) {
    cmd->execute();   // calls the right version automatically
    delete cmd;
}
```

---

## 3. STL Containers

The Standard Template Library gives you ready-made data structures.

### std::vector — resizable array

```cpp
#include <vector>
std::vector<int> v = {1, 2, 3};
v.push_back(4);             // add to end
v.erase(v.begin() + 1);    // remove index 1
int third = v[2];           // access by index (no bounds check)
int safe  = v.at(2);        // access with bounds check (throws if out of range)
size_t sz = v.size();

// Iterate
for (int x : v) std::cout << x << "\n";
for (size_t i = 0; i < v.size(); i++) std::cout << v[i] << "\n";
```

### std::map — key-value pairs (sorted)

```cpp
#include <map>
std::map<std::string, std::string> env;
env["OS"]   = "Windows";
env["ARCH"] = "x64";

// Lookup
if (env.count("OS")) std::cout << env["OS"];

// Iterate
for (const auto& [key, val] : env)
    std::cout << key << " = " << val << "\n";
```

### std::unordered_map — same but faster (O(1) lookup)

```cpp
#include <unordered_map>
std::unordered_map<int, std::string> commands;
commands[1] = "LIST_PROC";
commands[2] = "SCREENSHOT";
```

---

## 4. File I/O

```cpp
#include <fstream>

// Write a file
std::ofstream out("log.txt");
if (out.is_open()) {
    out << "keystroke: A\n";
    out.close();
}

// Append to file
std::ofstream app("log.txt", std::ios::app);
app << "keystroke: B\n";

// Read entire file into string
std::ifstream in("log.txt");
std::string content((std::istreambuf_iterator<char>(in)),
                     std::istreambuf_iterator<char>());

// Read line by line
std::ifstream in2("log.txt");
std::string line;
while (std::getline(in2, line)) {
    std::cout << line << "\n";
}

// Binary file I/O (for reading PE files, parsing binaries)
std::ifstream bin("Stub.exe", std::ios::binary);
std::vector<char> bytes((std::istreambuf_iterator<char>(bin)),
                         std::istreambuf_iterator<char>());
```

---

## 5. Exception Handling

```cpp
try {
    std::vector<int> v = {1, 2, 3};
    int x = v.at(10);       // throws std::out_of_range
} catch (const std::out_of_range& e) {
    std::cerr << "Out of range: " << e.what() << "\n";
} catch (const std::exception& e) {
    std::cerr << "Exception: " << e.what() << "\n";
} catch (...) {
    std::cerr << "Unknown exception\n";
}
```

**In security code**, exceptions are often avoided in favour of error codes
because:
- Exceptions add code to the binary (exception tables).
- Win32 API does not use exceptions — it returns error codes.
- You want predictable control flow in an implant.

---

## 6. Smart Pointers (RAII)

Raw `new`/`delete` is error-prone — you can forget to `delete`, or `delete`
twice. Smart pointers automate this.

```cpp
#include <memory>

// unique_ptr — single owner, auto-deleted when out of scope
std::unique_ptr<int> p = std::make_unique<int>(42);
std::cout << *p;
// No delete needed — freed automatically when p goes out of scope.

// shared_ptr — reference-counted, freed when last owner is gone
std::shared_ptr<BotConfig> cfg = std::make_shared<BotConfig>("10.0.0.1", 4444, true);
std::shared_ptr<BotConfig> cfg2 = cfg;  // both point to same object
// freed when both cfg and cfg2 go out of scope
```

Use `unique_ptr` by default. Use `shared_ptr` only when you genuinely need
shared ownership.

---

## 7. Lambda Functions

A lambda is an anonymous function defined inline.

```cpp
// Basic lambda
auto add = [](int a, int b) { return a + b; };
std::cout << add(3, 4);  // 7

// Capture by reference
int base = 100;
auto addBase = [&base](int x) { return base + x; };
std::cout << addBase(5);  // 105
base = 200;
std::cout << addBase(5);  // 205 — captured by reference, sees new value

// Capture by value
auto snapshot = [base](int x) { return base + x; };
// 'base' is copied at the point the lambda is created
```

Lambdas appear constantly in:
- `std::sort` custom comparators
- Thread functions (you pass a lambda to `std::thread`)
- Callback-style code

---

## 8. std::thread — Multi-threading

A RAT runs multiple things at once: main C2 loop, keylogger, screenshot timer,
persistence watchdog. Each runs on its own thread.

```cpp
#include <thread>
#include <mutex>
#include <atomic>

std::mutex mtx;
std::atomic<bool> running{true};

void keylogLoop() {
    while (running.load()) {
        // poll keys...
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

void c2Loop() {
    while (running.load()) {
        // send beacon, receive commands...
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

int main() {
    std::thread t1(keylogLoop);
    std::thread t2(c2Loop);

    // Let threads run for 30 seconds then stop
    std::this_thread::sleep_for(std::chrono::seconds(30));
    running.store(false);

    t1.join();   // wait for thread to finish before main() exits
    t2.join();
    return 0;
}
```

**`std::mutex`** protects shared data from simultaneous access:

```cpp
std::string keyBuffer;
std::mutex  keyMtx;

// Writer thread:
{
    std::lock_guard<std::mutex> lock(keyMtx);  // auto-unlocks when lock goes out of scope
    keyBuffer += 'A';
}

// Reader thread:
{
    std::lock_guard<std::mutex> lock(keyMtx);
    std::string snapshot = keyBuffer;
    keyBuffer.clear();
    // process snapshot
}
```

**`std::atomic<bool>`** for a simple flag that threads can read/write safely
without a mutex.

---

## 9. The Compilation Model in Detail

Understanding this is critical for understanding how AV scans your binary.

```
Source file (.cpp)
    ↓ Preprocessor — #include expands headers, #define substituted
    ↓ Compiler     — produces object file (.o) per .cpp
    ↓ Linker       — combines .o files + library archives (.a) + import libs
    → Executable (.exe)
```

**What ends up in the binary:**
- All code from all `.cpp` files that were linked
- Static library code that was referenced
- Import table entries for DLL functions (e.g. `CreateProcess` → `kernel32.dll`)
- String literals — EVERY string literal you write is embedded verbatim
  in the `.rdata` section. This is how AV detects you: it scans for known
  strings like "SOFTWARE\\...\\Run" or "cmd.exe".
- Debug info (stripped with `-s` flag)

**Compiler flags that matter:**
```
-O2              optimise — changes code layout, harder to reverse
-s               strip debug symbols
-fno-ident       remove GCC version comment from binary
-mwindows        GUI subsystem — no console window
-static-libgcc   embed libgcc statically — no libgcc_s_seh-1.dll needed
-static-libstdc++ embed libstdc++ statically
```

---

## Exercises

- `ex01_classes_oop.cpp` — build a command queue with classes
- `ex02_stl_containers.cpp` — process list stored in map, sorted
- `ex03_file_io.cpp` — keylog writer / reader
- `ex04_threads.cpp` — two threads sharing data safely with a mutex
