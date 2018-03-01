#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "noinstrument.h"
#include "addrspace.h"

/* Special version of strlen that determines size of buffer, i.e. strlen + 1 or
 * 0 if given buffer is NULL. */
size_t NOINSTRUMENT(strsize_nullsafe)(char *str) {
    return str ? strlen(str) + 1 : 0;
}

char *NOINSTRUMENT(strtok)(char *str, const char *delim) {
    static uintptr_t base_ptr;
    static size_t base_size;
    char *maskedptr = (char*)((uintptr_t)str & PRESERVE_MASK);
    char *maskeddelim = (char*)((uintptr_t)delim & PRESERVE_MASK);

    if (maskedptr) {
        base_ptr = (uintptr_t)maskedptr;
        base_size = (uintptr_t)str >> ADDRSPACE_BITS;
    }

    uintptr_t strtok_ret = (uintptr_t)strtok(maskedptr, maskeddelim);
    if (!strtok_ret)
        return NULL;

    /* If the base pointer had no metadata, don't add it not to break stuff */
    if (!base_size)
        return (char*)strtok_ret;

    uintptr_t newsize = (base_size + (strtok_ret - base_ptr)) << ADDRSPACE_BITS;
    return (char*)(strtok_ret | newsize);
}

char *NOINSTRUMENT(strtok_ubound)(char *str, const char *delim) {
    static uintptr_t endptr;
    char *maskedptr = (char*)((uintptr_t)str & ADDRSPACE_MASK);
    char *maskeddelim = (char*)((uintptr_t)delim & ADDRSPACE_MASK);

    if (maskedptr)
        endptr = (uintptr_t)str & BOUND_MASK_HIGH;

    uintptr_t strtok_ret = (uintptr_t)strtok(maskedptr, maskeddelim);
    if (!strtok_ret)
        return endptr; // instrumented NULL pointer

    return (char*)(strtok_ret | endptr);
}
