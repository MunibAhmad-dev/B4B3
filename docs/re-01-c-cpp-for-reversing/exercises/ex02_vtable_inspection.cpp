// Exercise 2: vtable Inspection
// Goal: understand how C++ virtual dispatch works at the memory level.
//
// TASKS:
//  1. Run the program and observe the vtable pointer at offset 0 of each object.
//  2. Manually call a virtual function by reading the vtable and casting — complete
//     the TODO in manual_virtual_call().
//  3. Verify that Dog's vtable != Cat's vtable but two Dog instances share a vtable.
//  4. Add a second virtual function `void describe()` to Animal and update subclasses.
//     What offset does it appear at in the vtable? Print it.
//
// COMPILE (MSVC):  cl /W4 /std:c++17 ex02_vtable_inspection.cpp
// COMPILE (GCC):   g++ -Wall -std=c++17 ex02_vtable_inspection.cpp -o ex02

#include <cstdio>
#include <cstdint>

// -- Class hierarchy --

class Animal {
public:
    int age;
    explicit Animal(int a) : age(a) {}
    virtual void speak()      = 0;
    virtual const char* name() = 0;
    virtual ~Animal() {}
};

class Dog : public Animal {
public:
    explicit Dog(int a) : Animal(a) {}
    void speak()             override { printf("Woof!\n"); }
    const char* name()       override { return "Dog"; }
};

class Cat : public Animal {
public:
    explicit Cat(int a) : Animal(a) {}
    void speak()             override { printf("Meow!\n"); }
    const char* name()       override { return "Cat"; }
};

// -- Helpers --

// Object in memory: [ vptr (8 bytes) | int age (4 bytes) | padding ]
// vptr points to the vtable: [ dtor, speak, name, ... ]

void print_vtable_info(Animal* obj, const char* label) {
    uintptr_t* raw    = reinterpret_cast<uintptr_t*>(obj);
    uintptr_t  vptr   = raw[0];
    uintptr_t* vtable = reinterpret_cast<uintptr_t*>(vptr);

    printf("\n[%s]\n", label);
    printf("  object  addr = %p\n", (void*)obj);
    printf("  vptr         = 0x%016llX\n", (unsigned long long)vptr);
    printf("  vtable[0] dtor  = 0x%016llX\n", (unsigned long long)vtable[0]);
    printf("  vtable[1] speak = 0x%016llX\n", (unsigned long long)vtable[1]);
    printf("  vtable[2] name  = 0x%016llX\n", (unsigned long long)vtable[2]);
}

// Task 2: call speak() without using virtual dispatch — go through vtable manually
void manual_virtual_call(Animal* obj) {
    // TODO:
    //  1. Get the vptr from obj
    //  2. Index into the vtable to get the speak() function pointer (index 1)
    //  3. Cast it to the right function pointer type
    //  4. Call it with obj as 'this'
    printf("[manual_virtual_call] TODO: implement this\n");
    (void)obj;
}

int main() {
    Dog d1(3), d2(5);
    Cat c1(2);

    print_vtable_info(&d1, "Dog d1");
    print_vtable_info(&d2, "Dog d2");
    print_vtable_info(&c1, "Cat c1");

    printf("\n--- Shared vtable? (d1 vptr == d2 vptr): %s ---\n",
        (*reinterpret_cast<uintptr_t*>(&d1) == *reinterpret_cast<uintptr_t*>(&d2))
        ? "YES" : "NO");

    printf("\n--- Normal dispatch ---\n");
    Animal* animals[] = { &d1, &c1 };
    for (auto* a : animals) {
        printf("%s says: ", a->name());
        a->speak();
    }

    printf("\n--- Manual vtable call ---\n");
    manual_virtual_call(&d1);
    manual_virtual_call(&c1);

    return 0;
}
