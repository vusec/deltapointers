#ifndef _SIZETAGS_H
#define _SIZETAGS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "noinstrument.h" // from $PATHROOT/lib

// Uncommente if testing ubound-branch pass
//#define TESTING_UBOUND_BRANCH

#define ADDRSPACE_BITS 32
#define ADDRSPACE_MASK ((1ULL << ADDRSPACE_BITS) - 1)

/* For DumpIR pass output. */
/* XXX could also use __FILE__? */
#ifdef __cplusplus
#define DEBUG_MODULE_NAME(n) \
    extern "C" { \
        __attribute__((used)) \
        static const char NOINSTRUMENT(DEBUG_MODULE_NAME)[] = (n); \
    }
#else
#define DEBUG_MODULE_NAME(n) \
    __attribute__((used)) \
    static const char NOINSTRUMENT(DEBUG_MODULE_NAME)[] = (n);
#endif

/* assert doesn't work properly with shrinkaddrspace (has ptr to old stack in
 * __assert_fail_base()).
 *
 * Use inline asm to exit with error, so optimizer cannot catch
 * on to the fact that, if the condition does not hold, we do a no-return exit()
 * call, causing the optimizer to assume all statements in the assert as true,
 * and throwing away a bunch of code because of it (e.g., &a == &b causes the
 * entire remainder of function to use that alias).
 */
#define assert(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "Assertion failed: " #cond "\n"); \
            asm volatile ("mov $231, %rax\n\t" /* sys_exit_group */ \
                          "mov $134, %rdi\n\t" /* error code */ \
                          "syscall\n\t"); \
        } \
    } while (0)

#define leak_ptr(x) NOINSTRUMENT(leak_ptr)(x)
#define ptr_get_size(x) NOINSTRUMENT(ptr_get_size)(x)

__attribute__((noinline)) static uintptr_t NOINSTRUMENT(leak_ptr)(void *p) {
    uintptr_t tmp;
    asm volatile ("mov %1, %0\n\t" : "=r"(tmp) : "r"(p));
    return tmp;
}

__attribute__((noinline)) static size_t NOINSTRUMENT(ptr_get_size)(void *p) {
    uintptr_t raw = leak_ptr(p);
#ifdef TESTING_UBOUND_BRANCH
    return (raw >> ADDRSPACE_BITS) - (raw & ADDRSPACE_MASK);
#else
    uintptr_t meta = (uintptr_t)(raw >> ADDRSPACE_BITS);
    return (size_t)(meta ? (-meta << (ADDRSPACE_BITS + 1) >> (ADDRSPACE_BITS + 1)) : 0);
#endif
}


#ifdef __cplusplus
}
#endif

#endif /* _SIZETAGS_H */
