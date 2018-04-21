#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include "deltatags.h"

DEBUG_MODULE_NAME("test_arith_neg");

int main(int argc, char **argv)
{
    int foo[16];
    memset(foo, 'A', sizeof(foo));

    int *midway = (int*)leak_ptr(&foo[8]);

    printf("   foo: %p metasize: %zu\n", foo, ptr_get_size(foo));
    printf("midway: %p metasize: %zu\n", midway, ptr_get_size(midway));
    printf("foo[8]: %x midway[0]: %x\n", foo[8], midway[0]);
    assert(&foo[8] == &midway[0]);
    assert(ptr_get_size(midway) == sizeof(foo) / 2);

    int *sub = &midway[-7];
    printf("&foo[1]: %p, &sub[0]: %p\n", &foo[1], &sub[0]);
    printf("correct size: %zu, sub metasize: %zu\n", ptr_get_size(&foo[1]), ptr_get_size(sub));
    assert(&foo[1] == sub);
    assert(ptr_get_size(&foo[1]) == ptr_get_size(sub));

    return 0;
}
