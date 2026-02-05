#include <string.h>
#include <stdlib.h>

class N {
public:
    int value;
    
    N(int param_1);
    void setAnnotation(char *param_1);
    int operator+(N &param_1);
    int operator-(N &param_1);
};

/* N::N(int) */

void N::N(int param_1)
{
    this->value = param_1;
    return;
}

/* N::setAnnotation(char*) */

void N::setAnnotation(char *param_1)
{
    size_t __n;
    
    __n = strlen(param_1);
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

/* main */

void main(int argc, char **argv)
{
    N *obj1;
    N *obj2;
    
    if (argc < 2) {
        _exit(1);
    }
    
    obj1 = new N(5);
    obj2 = new N(6);
    
    obj1->setAnnotation(argv[1]);
    
    (*obj2) + (*obj1);
    
    return;
}
