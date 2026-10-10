// Solution 02 — Control flow

#include <iostream>

int main() {
    // Task 1: FizzBuzz
    for (int i = 1; i <= 20; i++) {
        if (i % 15 == 0)      std::cout << "FizzBuzz\n";
        else if (i % 3 == 0)  std::cout << "Fizz\n";
        else if (i % 5 == 0)  std::cout << "Buzz\n";
        else                  std::cout << i << "\n";
    }
    std::cout << "\n";

    // Task 2: bit shift loop
    unsigned int x = 256;
    int iterations = 0;
    while (x != 0) {
        x >>= 1;
        iterations++;
        std::cout << x << "\n";
    }
    // x = 256 = 2^8, so we need 8 right-shifts to reach 0.
    // Each right-shift divides by 2 (discards the lowest bit).
    std::cout << "Iterations: " << iterations << "\n\n";

    // Task 3: command dispatcher
    int cmd = 3;
    switch (cmd) {
        case 1:  std::cout << "LIST_PROCESSES\n";  break;
        case 2:  std::cout << "SCREENSHOT\n";      break;
        case 3:  std::cout << "KEYLOG_START\n";    break;
        case 4:  std::cout << "SHELL_EXEC\n";      break;
        default: std::cout << "UNKNOWN_COMMAND\n"; break;
    }

    return 0;
}
