#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include "deltatags.h"

DEBUG_MODULE_NAME("test_libptr_ptrdiff");

int main(void)
{
    char haystack[] = "this is a test sentence";
    char needle_str[] = "test";
    char needle_str_not[] = "foobar";


    char *strstr_ret = strstr(haystack, needle_str);
    printf("strstr: '%s' @ %p\n supposed size: %zu, output metasize: %zu\n",
            strstr_ret, strstr_ret, sizeof(haystack) - (strstr_ret - haystack),
            ptr_get_size(strstr_ret));
    assert(sizeof(haystack) - (strstr_ret - haystack) == ptr_get_size(strstr_ret));

    char *strstr_ret_not = strstr(haystack, needle_str_not);
    printf("strstr notfound: %p\n output metasize: %zu\n",
            strstr_ret_not, ptr_get_size(strstr_ret_not));
    assert(strstr_ret_not == NULL);

    char *memchr_ret = memchr(haystack, 'a', sizeof(haystack));
    printf("memchr: '%s' @ %p\n supposed size: %zu, output metasize: %zu\n",
            memchr_ret, memchr_ret, sizeof(haystack) - (memchr_ret - haystack),
            ptr_get_size(memchr_ret));
    assert(sizeof(haystack) - (memchr_ret - haystack) == ptr_get_size(memchr_ret));

    return 0;
}
