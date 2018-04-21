#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>

#include "deltatags.h"

DEBUG_MODULE_NAME("test_libptr_retsize");

int main(void)
{
    const unsigned short **table = __ctype_b_loc();
    printf("__ctype_b_loc: supposed size: %zu, output metasize: %zu\n",
            sizeof(*table), ptr_get_size(table));
    assert(sizeof(*table) == ptr_get_size(table));

    time_t rawtime;
    time(&rawtime);
    struct tm *tm = gmtime(&rawtime);

    printf("gmtime: supposed size: %zu, output metasize: %zu\n",
            sizeof(*tm), ptr_get_size(tm));
    assert(sizeof(*tm) == ptr_get_size(tm));

    FILE *f = fopen("/etc/passwd", "r");
    printf("fopen: supposed size: %zu, output metasize: %zu\n",
            sizeof(*f), ptr_get_size(f));
    assert(sizeof(*f) == ptr_get_size(f));

    return 0;
}
