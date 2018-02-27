#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include "sizetags.h"

DEBUG_MODULE_NAME("test_simple");

int main(int argc, char **argv)
{
    char *a = malloc(1);

    printf("a: %p\n", a);
    printf("a raw: %p, size %zu %2$zx\n", leak_ptr(a), ptr_get_size(a));
    assert(ptr_get_size(a) == 1);

    return 0;
}
