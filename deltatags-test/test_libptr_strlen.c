#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "sizetags.h"

DEBUG_MODULE_NAME("test_libptr_strlen");

int main(void)
{
    time_t rawtime;
    time(&rawtime);

    char *str = ctime(&rawtime);
    printf("ctime: '%s'\n", str);
    printf("ctime size: %zu, metadata size: %zu\n", strlen(str) + 1, ptr_get_size(str));
    assert(strlen(str) + 1 == ptr_get_size(str));

    unsetenv("ENVVAR_THAT_DOES_NOT_EXIST");
    char *env = getenv("ENVVAR_THAT_DOES_NOT_EXIST");
    printf("getenv: %p\n", env);
    printf("getenv metadata size: %zu\n", ptr_get_size(env));
    assert(env == NULL);
    assert(ptr_get_size(env) == 0);

    return 0;
}
