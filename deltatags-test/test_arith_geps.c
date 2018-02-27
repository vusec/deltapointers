#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include "sizetags.h"

DEBUG_MODULE_NAME("test_arith_geps");

struct a {
    int a1, a2;
    void *a3, *a4;
};

struct b {
    int b1;
    struct a b2[16];
};

int main(int argc, char **argv)
{
    struct b s[8];

    memset(s, 'A', sizeof(s));

    void **indexed = &s[2].b2[5].a3;
    printf("s: %p size: %zu\n", s, sizeof(s));
    printf("&s[2].b2[5].a3: %p: %p\n", indexed, *indexed);
    printf("Supposed size: %zu, metadata size: %zu\n",
            sizeof(s) - ((char*)indexed - (char*)s), ptr_get_size(indexed));
    assert(sizeof(s) - ((char*)indexed - (char*)s) == ptr_get_size(indexed));


    void **indexed2 = &s[2].b2[argc].a3;
    printf("Using argc now: %d\n", argc);
    printf("&s[2].b2[%d].a3: %p: %p\n", argc, indexed2, *indexed2);
    printf("Supposed size: %zu, metadata size: %zu\n",
            sizeof(s) - ((char*)indexed2 - (char*)s), ptr_get_size(indexed2));
    assert(sizeof(s) - ((char*)indexed2 - (char*)s) == ptr_get_size(indexed2));

    return 0;
}
