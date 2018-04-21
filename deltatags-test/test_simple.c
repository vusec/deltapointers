#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include "deltatags.h"

DEBUG_MODULE_NAME("test_simple");

int main(int argc, char **argv)
{
    char *a = malloc(1);

    printf("a: %p\n", a);
    size_t size = ptr_get_size(a);
    printf("a raw: %p, size %zu %zx\n", (char*)leak_ptr(a), size, size);
    assert(ptr_get_size(a) == 1);

    return 0;
}
