#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#include "sizetags.h"

DEBUG_MODULE_NAME("test_libptr_copyfromarg");

int main(void)
{
    char buf[512];

    char *str = getcwd(buf, sizeof(buf));
    printf("getcwd: '%s'\n", str);
    printf("real size: %zu, input metasize: %zu, output metasize: %zu\n", sizeof(buf), ptr_get_size(buf), ptr_get_size(str));
    assert(sizeof(buf) == ptr_get_size(buf));
    assert(sizeof(buf) == ptr_get_size(str));

    return 0;
}
