#include <stdbool.h>
#include <stdint.h>

#include "noinstrument.h"
#include "addrspace.h"

#define UNUSED __attribute__((unused))
#define ALWAYS_INLINE __attribute__((always_inline))

#ifdef __x86_64__

#include "x86intrin.h"

#ifdef OVERFLOW_BIT

ALWAYS_INLINE uintptr_t NOINSTRUMENT(mask_pointer_pext_reg)(uintptr_t ptr, bool preserve UNUSED) {
    return _pext_u64(ptr, PRESERVE_MASK);
}

volatile uint64_t NOINSTRUMENT(pext_mask) = PRESERVE_MASK;

ALWAYS_INLINE uintptr_t NOINSTRUMENT(mask_pointer_pext_glob)(uintptr_t ptr, bool preserve UNUSED) {
    return _pext_u64(ptr, NOINSTRUMENT(pext_mask));
}

#else /* OVERFLOW_BIT */

ALWAYS_INLINE uintptr_t NOINSTRUMENT(mask_pointer_bzhi)(uintptr_t ptr, bool preserve UNUSED) {
    return _bzhi_u64(ptr, ADDRSPACE_BITS);
}

#endif /* !OVERFLOW_BIT */

#endif /* __x86_64__ */




/* Alternative implementations of masking to test their performance. */
#if 0
ALWAYS_INLINE uintptr_t NOINSTRUMENT(mask_pointer)(uintptr_t ptr, bool preserve) {
    return ptr & (preserve ? PRESERVE_MASK : ADDRSPACE_MASK);
}

uintptr_t NOINSTRUMENT(mask_pointer)(uintptr_t ptr, bool preserve) {
    if (preserve) {
        asm ("rol %0" : "+a"(ptr) ::);
        ptr &= ADDRSPACE_MASK;
        asm ("ror %0" : "+a"(ptr) ::);
        return ptr;
    }
    return ptr & ADDRSPACE_MASK;
}

static inline uintptr_t rot(uintptr_t input, unsigned bits) {
     return (input >> bits) | (input << ((sizeof (input) << 3) - bits));
}

uintptr_t NOINSTRUMENT(mask_pointer)(uintptr_t ptr, bool preserve) {
    if (preserve)
        return rot(rot(ptr, 63) & ADDRSPACE_MASK, 1);
    return ptr & ADDRSPACE_MASK;
}

uintptr_t NOINSTRUMENT(mask_pointer)(uintptr_t ptr, bool preserve) {
    if (preserve) {
        asm ("test %%rax, %%rax\n\t"
             "cmovs %[zero], %%eax"
            : "+a"(ptr)
            : [zero] "r"(0)
            : "cc");
        return ptr;
    }
    return ptr & ADDRSPACE_MASK;
}

uintptr_t NOINSTRUMENT(mask_pointer)(uintptr_t ptr, bool preserve) {
    if (preserve) {
        register uintptr_t tmp;
        asm ("movabs $0x80000000ffffffff, %[tmp]\n\t"
             "and %[tmp], %[ptr]"
            : [ptr] "+r"(ptr), [tmp] "=r"(tmp)
            :
            : "cc");
        return ptr;
    }
    return ptr & ADDRSPACE_MASK;
}

uintptr_t NOINSTRUMENT(mask_pointer)(uintptr_t ptr, bool preserve) {
    if (preserve) {
        asm ("test %[ptr], %[ptr]\n\t"
             "js ."
            :
            : [ptr] "r"(ptr)
            : "cc");
        return ptr;
    }
    return ptr & ADDRSPACE_MASK;
}
#endif
