// Solution 2: vtable Inspection (complete)

#include <cstdio>
#include <cstdint>

class Animal {
public:
    int age;
    explicit Animal(int a) : age(a) {}
    virtual void speak()           = 0;
    virtual const char* name()     = 0;
    virtual void describe()              // Task 4: added second virtual
        { printf("I am an animal, age %d\n", age); }
    virtual ~Animal() {}
};

class Dog : public Animal {
public:
    explicit Dog(int a) : Animal(a) {}
    void speak()         override { printf("Woof!\n"); }
    const char* name()   override { return "Dog"; }
    void describe()      override { printf("I am a Dog, age %d\n", age); }
};

class Cat : public Animal {
public:
    explicit Cat(int a) : Animal(a) {}
    void speak()         override { printf("Meow!\n"); }
    const char* name()   override { return "Cat"; }
    void describe()      override { printf("I am a Cat, age %d\n", age); }
};

// vtable layout (MSVC, typical):
// vtable[0] = destructor (scalar)
// vtable[1] = speak
// vtable[2] = name
// vtable[3] = describe   (after adding task 4)
// vtable[4] = destructor (vector, MSVC specific) or varies

// Function pointer type matching speak() and describe()
typedef void (*VoidFn)(void*);
typedef const char* (*NameFn)(void*);

void print_vtable_info(Animal* obj, const char* label) {
    uintptr_t* raw    = reinterpret_cast<uintptr_t*>(obj);
    uintptr_t  vptr   = raw[0];
    uintptr_t* vtable = reinterpret_cast<uintptr_t*>(vptr);

    printf("\n[%s]\n", label);
    printf("  object  addr = %p\n", (void*)obj);
    printf("  vptr         = 0x%016llX\n", (unsigned long long)vptr);
    for (int i = 0; i < 5; i++)
        printf("  vtable[%d]    = 0x%016llX\n", i, (unsigned long long)vtable[i]);
}

// Task 2: call speak() manually through vtable
// vtable[1] = speak (after dtor at [0])
void manual_virtual_call(Animal* obj) {
    uintptr_t* raw    = reinterpret_cast<uintptr_t*>(obj);
    uintptr_t  vptr   = raw[0];
    uintptr_t* vtable = reinterpret_cast<uintptr_t*>(vptr);

    // speak is at vtable[1]
    VoidFn speak_fn = reinterpret_cast<VoidFn>(vtable[1]);
    printf("[manual vtable] calling speak(): ");
    speak_fn(obj);   // pass 'this' manually

    // name is at vtable[2]
    NameFn name_fn = reinterpret_cast<NameFn>(vtable[2]);
    printf("[manual vtable] name() = %s\n", name_fn(obj));
}

int main() {
    Dog d1(3), d2(5);
    Cat c1(2);

    print_vtable_info(&d1, "Dog d1");
    print_vtable_info(&d2, "Dog d2");
    print_vtable_info(&c1, "Cat c1");

    uintptr_t d1_vptr = *reinterpret_cast<uintptr_t*>(&d1);
    uintptr_t d2_vptr = *reinterpret_cast<uintptr_t*>(&d2);
    uintptr_t c1_vptr = *reinterpret_cast<uintptr_t*>(&c1);

    printf("\n--- d1 vptr == d2 vptr (shared vtable):  %s ---\n",
           d1_vptr == d2_vptr ? "YES" : "NO");
    printf("--- d1 vptr == c1 vptr (different types): %s ---\n",
           d1_vptr == c1_vptr ? "YES" : "NO");

    printf("\n--- Normal dispatch ---\n");
    Animal* animals[] = { &d1, &c1 };
    for (auto* a : animals) {
        printf("%s: ", a->name()); a->speak();
        a->describe();
    }

    printf("\n--- Manual vtable call ---\n");
    manual_virtual_call(&d1);
    manual_virtual_call(&c1);

    return 0;
}
