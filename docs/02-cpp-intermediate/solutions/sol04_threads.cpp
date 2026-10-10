// Solution 04 — Threads and Mutex

#include <iostream>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <string>
#include <cstdlib>
#include <ctime>

std::string            keyBuffer;
std::mutex             keyMtx;
std::atomic<bool>      running{true};

void keyloggerThread() {
    while (running.load()) {
        char key = 'A' + (std::rand() % 26);
        {
            std::lock_guard<std::mutex> lock(keyMtx);
            keyBuffer += key;
        }
        std::cout << "[keylog] appended: " << key << "\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    std::cout << "[keylog] thread exiting\n";
}

void exfilThread() {
    while (running.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        std::string chunk;
        {
            std::lock_guard<std::mutex> lock(keyMtx);
            chunk = keyBuffer;
            keyBuffer.clear();
        }
        if (!chunk.empty())
            std::cout << "[exfil] sending: " << chunk << "\n";
    }
    std::cout << "[exfil] thread exiting\n";
}

int main() {
    std::srand((unsigned)std::time(nullptr));

    std::thread t1(keyloggerThread);
    std::thread t2(exfilThread);

    std::this_thread::sleep_for(std::chrono::seconds(5));
    running.store(false);

    t1.join();
    t2.join();
    std::cout << "Done.\n";
    return 0;
}
