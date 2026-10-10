// Solution 01 — Classes and OOP

#include <iostream>
#include <vector>
#include <string>
#include <memory>

class Command {
public:
    virtual std::string name() const = 0;
    virtual void execute() = 0;
    virtual ~Command() {}
};

class ListProcessesCmd : public Command {
public:
    std::string name() const override { return "list_processes"; }
    void execute() override { std::cout << "[*] Listing processes...\n"; }
};

class ScreenshotCmd : public Command {
public:
    std::string name() const override { return "screenshot"; }
    void execute() override { std::cout << "[*] Capturing screenshot...\n"; }
};

class ShellCmd : public Command {
    std::string _cmdline;
public:
    ShellCmd(const std::string& cmd) : _cmdline(cmd) {}
    std::string name() const override { return "shell"; }
    void execute() override { std::cout << "[*] Running: " << _cmdline << "\n"; }
};

class CommandQueue {
    std::vector<std::unique_ptr<Command>> _queue;
public:
    void enqueue(std::unique_ptr<Command> cmd) {
        std::cout << "[+] Queued: " << cmd->name() << "\n";
        _queue.push_back(std::move(cmd));
    }
    void runAll() {
        for (auto& cmd : _queue) cmd->execute();
        _queue.clear();  // unique_ptr auto-deletes on erase
    }
    size_t size() const { return _queue.size(); }
};

int main() {
    CommandQueue q;
    q.enqueue(std::make_unique<ListProcessesCmd>());
    q.enqueue(std::make_unique<ScreenshotCmd>());
    q.enqueue(std::make_unique<ShellCmd>("whoami"));
    q.enqueue(std::make_unique<ShellCmd>("ipconfig"));

    std::cout << "Queue size: " << q.size() << "\n\n";
    q.runAll();
    std::cout << "\nQueue size after runAll: " << q.size() << "\n";
    return 0;
}
