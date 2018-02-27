#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include "sizetags.h"

DEBUG_MODULE_NAME("test_libptr_strtok");

#define check_tok(tok, correct_str, base)                                      \
    do {                                                                       \
        printf("strtok: '%s' @ %p, supposed size: %zu, output metasize: %zu\n",\
                tok, tok, sizeof(base) - (tok - base), ptr_get_size(tok));     \
        assert(!strcmp(tok, correct_str));                                     \
        assert(sizeof(base) - (tok - base) == ptr_get_size(tok));              \
    } while (0)

int main(void)
{
    char haystack[] = "this is a test";
    char haystack2[] = "second haystack";
    char *tok;

    tok = strtok(haystack, " ");
    check_tok(tok, "this", haystack);
    tok = strtok(NULL, " ");
    check_tok(tok, "is", haystack);
    tok = strtok(NULL, " ");
    check_tok(tok, "a", haystack);
    tok = strtok(NULL, " ");
    check_tok(tok, "test", haystack);

    tok = strtok(haystack2, " ");
    check_tok(tok, "second", haystack2);
    tok = strtok(NULL, " ");
    check_tok(tok, "haystack", haystack2);

    return 0;
}
