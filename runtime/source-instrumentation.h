#ifndef _SOURCE_INSTRUMENTATION_H
#define _SOURCE_INSTRUMENTATION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "addrspace.h"
#include "noinstrument.h"

#define _tag_pointer  NOINSTRUMENT(_inline_tag_pointer)
#define _mask_pointer NOINSTRUMENT(_inline_mask_pointer)
#define _tag_of       NOINSTRUMENT(_inline_tag_of)
#define _copy_tag     NOINSTRUMENT(_inline_take_tag)
#define _ptr_arith    NOINSTRUMENT(_inline_ptr_arith)
#define _leak_pointer NOINSTRUMENT(_inline_leak_pointer)
#define _delta_tag    NOINSTRUMENT(_inline_delta_tag)

#define MASK_POINTER_TYPED(ty, p) ((ty*)_mask_pointer((void*)(p)))

/*
 * Implementations for these are in mask-wrappers.c
 */

void *_tag_pointer(const void *ptr, uintptr_t tag);
void *_mask_pointer(const void *ptr);
uintptr_t _tag_of(const void *ptr);
void *_copy_tag(const void *ptr, const void *tagptr);
void *_ptr_arith(const void *ptr, int64_t delta);
uintptr_t _leak_pointer(const void *ptr);
uintptr_t _delta_tag(unsigned long long size);

#ifdef DELTATAGS_UBOUND_BRANCH
# define UNSAFE_ARITH(ptr, delta) ({                                 \
        uintptr_t _tag = _tag_of(ptr);                               \
        _tag_pointer((char*)ptr + delta, _tag ? _tag + delta : 0UL); \
    })
#elif defined(DELTATAGS)
# define UNSAFE_ARITH _ptr_arith
#endif

#ifdef __cplusplus
}
#endif

#endif /* _SOURCE_INSTRUMENTATION_H */
