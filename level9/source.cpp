#include <string.h>
#include <stdlib.h>

// Class N structure (108 bytes total)
class N {
private:
    // Offset 0x00: vtable pointer (4 bytes) - automatically managed by C++
    // Offset 0x04: annotation buffer (100 bytes) - for user data
    // Offset 0x68: int member (4 bytes)
    
public:
    int value;  // At offset 0x68 (104 bytes from start)
    
    // Constructor
    N(int param_1);
    
    // Methods
    void setAnnotation(char *param_1);
    int operator+(N &param_1);
    int operator-(N &param_1);
};

/* N::N(int) - Constructor */

void N::N(int param_1)
{
    // Vtable pointer is set automatically by C++ compiler
    // Points to vtable at 0x08048848
    this->value = param_1;  // Store at offset 0x68
    return;
}

/* N::setAnnotation(char*) - VULNERABILITY HERE! */

void N::setAnnotation(char *param_1)
{
    size_t __n;
    
    __n = strlen(param_1);
    // Copies to this + 4 (annotation buffer starts 4 bytes after vtable)
    // NO BOUNDS CHECK! Can overflow if param_1 is longer than 100 bytes!
    memcpy((char *)this + 4, param_1, __n);
    return;
}

/* N::operator+(N&) */

int N::operator+(N &param_1)
{
    return this->value + param_1.value;
}

/* N::operator-(N&) */

int N::operator-(N &param_1)
{
    return this->value - param_1.value;
}

/* Main function */

void main(int argc, char **argv)
{
    N *obj1;
    N *obj2;
    
    if (argc < 2) {
        _exit(1);
    }
    
    // Allocate two N objects on the heap
    obj1 = new N(5);      // operator.new(0x6c) = 108 bytes
    obj2 = new N(6);      // operator.new(0x6c) = 108 bytes
    
    // Vulnerable call - can overflow obj1 into obj2!
    obj1->setAnnotation(argv[1]);
    
    // Call virtual function through obj2's vtable
    // Normally calls obj2->operator+(obj1)
    // If vtable was overwritten, can redirect execution!
    (*obj2) + (*obj1);
    
    return;
}

/*
 * Vtable Layout (at 0x08048848):
 * ─────────────────────────────────
 * 0x08048848: 0x0804873a  → N::operator+
 * 0x0804884c: 0x0804874e  → N::operator-
 *
 * Memory Layout of Class N:
 * ─────────────────────────────────
 * Offset 0x00 (0):    [vtable pointer]       ← 4 bytes
 * Offset 0x04 (4):    [annotation buffer]    ← 100 bytes (setAnnotation writes here)
 * Offset 0x68 (104):  [int value]            ← 4 bytes
 * Total: 0x6c (108 bytes)
 *
 * Heap Layout (from ltrace):
 * ─────────────────────────────────
 * obj1: 0x804a008 (first allocation)
 * obj2: 0x804a078 (second allocation, 112 bytes after obj1)
 *
 * Vulnerability:
 * ─────────────────────────────────
 * setAnnotation() uses strlen() then memcpy() with no bounds check.
 * If argv[1] is longer than 100 bytes, it overflows from obj1 into obj2,
 * allowing us to overwrite obj2's vtable pointer at 0x804a078.
 *
 * Exploit Strategy:
 * ─────────────────────────────────
 * 1. Fill obj1's annotation buffer with NOPs + shellcode
 * 2. Overflow into obj2 to overwrite its vtable pointer
 * 3. Point vtable to a fake vtable in our controlled memory
 * 4. Fake vtable points back to our shellcode
 * 5. When operator+ is called via obj2, it executes our shellcode!
 *
 * Challenge:
 * ─────────────────────────────────
 * strlen() stops at null bytes, so we need:
 * - Null-byte-free shellcode
 * - Addresses without null bytes in payload
 */
