#include <string.h>
#include <stdlib.h>

class N {
public:
    char annotation[100];  // Buffer at offset +4 (after vtable pointer)
    int value;             // Integer value
    
    N(int n);
    void setAnnotation(char *str);
    int operator+(N &other);
    int operator-(N &other);
};

N::N(int n)
{
    value = n;
}

void N::setAnnotation(char *str)
{
    memcpy(annotation, str, strlen(str));  // ⚠️ No bounds checking - overflow!
}

int N::operator+(N &other)
{
    return value + other.value;
}

int N::operator-(N &other)
{
    return value - other.value;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        _exit(1);
    }
    
    N *obj1 = new N(5);  // Allocated on heap at ~0x804a008
    N *obj2 = new N(6);  // Allocated on heap at ~0x804a078 (108 bytes after)
    
    obj1->setAnnotation(argv[1]);  // ⚠️ Overflow can reach obj2's vtable!
    
    obj2->operator+(*obj1);  // ⚠️ Calls via vtable - uses corrupted pointer!
    
    return 0;
}
