#include <iostream>
#include <fstream>
#include <cstdio>
#include <stdint.h>

#include "deltatags.h"

DEBUG_MODULE_NAME("test_libptr_copyfromarg_cpp");

int main(void)
{
    std::ofstream file;
    file.open("/dev/null", std::ios::binary);
    std::ostream *t = &(file << 1);

    printf("file: %p, t: %p\n", &file, t);
    printf("real size: %zu, input metasize: %zu, output metasize: %zu\n", sizeof(file), ptr_get_size(&file), ptr_get_size(t));
    assert(sizeof(file) == ptr_get_size(&file));
    assert(sizeof(file) == ptr_get_size(t));

    return 0;
}
