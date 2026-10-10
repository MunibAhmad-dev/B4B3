// Solution 04 — Pointers

#include <iostream>

void swap(int* a, int* b) {
    *a ^= *b;
    *b ^= *a;
    *a ^= *b;
}

int main() {
    // Task 1
    int x = 100;
    int* p = &x;
    *p = 999;
    std::cout << "x = " << x << "  *p = " << *p << "\n";
    std::cout << "address: " << p << "\n\n";

    // Task 2
    int arr[5] = {10, 20, 30, 40, 50};
    int* ap = arr;
    for (int i = 0; i < 5; i++) {
        std::cout << *(ap + i) << " ";
    }
    std::cout << "\n";
    int sum = 0;
    for (int i = 0; i < 5; i++) sum += *(ap + i);
    std::cout << "sum = " << sum << "\n\n";

    // Task 3
    int a = 10, b = 20;
    swap(&a, &b);
    std::cout << "after swap: a=" << a << " b=" << b << "\n\n";

    // Task 4
    int* heap = new int[8];
    for (int i = 0; i < 8; i++) heap[i] = i * 0x10;
    for (int i = 0; i < 8; i++) std::cout << heap[i] << " ";
    std::cout << "\n";
    delete[] heap;
    heap = nullptr;

    // Task 5
    int y = 7;
    int* q = &y;
    int** qq = &q;
    **qq = 42;
    std::cout << "\ny = " << y << "\n";

    return 0;
}
