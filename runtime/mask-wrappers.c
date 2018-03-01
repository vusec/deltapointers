#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "noinstrument.h"
#include "addrspace.h"
#include "source-instrumentation.h"

#define NOINLINE          __attribute__((noinline))
#define ALWAYS_INLINE     __attribute__((always_inline))
#define MASKWITH(p, mask) ((typeof(p)) ((unsigned long long)(p) & mask))
#define MASK(p)           MASKWITH(p, PRESERVE_MASK)
#define MASK_EXEC_ARRAY(p) \
    ((typeof(p)) NOINSTRUMENT(mask_exec_array)((char**)p))
#define unlikely(x)       __builtin_expect(!!(x), 0)

static char **NOINSTRUMENT(mask_exec_array)(char *arr[]) {
    arr = MASK(arr);

    int len = 0;
    while (MASKWITH(arr[len++], ADDRSPACE_MASK) != NULL);

    char **buf = (char**)malloc(len * sizeof (char*));

    int i = 0;
    do {
        buf[i] = MASK(arr[i]);
    } while (buf[i++] != NULL);

    return buf;
}

static const struct iovec *NOINSTRUMENT(mask_iovec)(const struct iovec *iov,
        int iovcnt) {
    const struct iovec *iov_old = MASK(iov);
    struct iovec *iov_new = calloc(iovcnt, sizeof(struct iovec));
    int i;
    for (i = 0; i < iovcnt; i++) {
        iov_new[i].iov_len = iov_old[i].iov_len;
        iov_new[i].iov_base = MASK(iov_old[i].iov_base);
    }
    return iov_new;
}

NOINLINE int NOINSTRUMENT(execv_mask)(const char *path, char *const argv[]) {
    return execv(MASK(path), MASK_EXEC_ARRAY(argv));
}

NOINLINE int NOINSTRUMENT(execvp_mask)(const char *file, char *const argv[]) {
    return execvp(MASK(file), MASK_EXEC_ARRAY(argv));
}

NOINLINE int NOINSTRUMENT(execvpe_mask)(const char *file, char *const argv[],
        char *const envp[]) {
    return execvpe(MASK(file), MASK_EXEC_ARRAY(argv), MASK_EXEC_ARRAY(envp));
}

NOINLINE int NOINSTRUMENT(execve_mask)(const char *filename, char *const argv[],
        char *const envp[]) {
    return execve(MASK(filename), MASK_EXEC_ARRAY(argv), MASK_EXEC_ARRAY(envp));
}

NOINLINE int NOINSTRUMENT(writev_mask)(int fd, const struct iovec *iov,
        int iovcnt) {
    const struct iovec *iov_masked = NOINSTRUMENT(mask_iovec)(iov, iovcnt);
    return writev(fd, iov_masked, iovcnt);
}

ALWAYS_INLINE bool NOINSTRUMENT(is_oob)(const void *ptr, uint64_t size) {
    uintptr_t ptrint = (uintptr_t)ptr & ADDRSPACE_MASK;
    uintptr_t ubnd = (uintptr_t)ptr >> ADDRSPACE_BITS;
    return ubnd != 0 && ptrint + size > ubnd;
}

/*
 * Source instrumentation implementations. These are NOINLINE to avoid inlining
 * by LTO, which would get rif of the noinstrument function names. Instead the
 * names start with "_inline_" (see definitions in source-instrumentation.h)
 * which is recognized by our custom inlining pass.
 */

NOINLINE void *_tag_pointer(const void *ptr, uintptr_t tag) {
    uintptr_t ptrint = (uintptr_t)ptr & ADDRSPACE_MASK;
    return (void*)(ptrint | ((tag & BOUND_MASK_LOW) << BOUND_SHIFT));
}

NOINLINE void *_mask_pointer(const void *ptr) {
    return (void*)((uintptr_t)ptr & ADDRSPACE_MASK);
}

NOINLINE uintptr_t _tag_of(const void *ptr) {
    return (uintptr_t)ptr >> BOUND_SHIFT;
}

NOINLINE void *_copy_tag(const void *ptr, const void *tagptr) {
    uintptr_t addr = (uintptr_t)ptr & ADDRSPACE_MASK;
    uintptr_t tag = (uintptr_t)tagptr & BOUND_MASK_HIGH;
    return (void*)(addr | tag);
}

NOINLINE void *_ptr_arith(const void *ptr, int64_t delta) {
    //return _copy_tag((char*)ptr + delta, ptr);
    return (void*)((char*)ptr + delta);
}

NOINLINE uintptr_t _leak_pointer(const void *ptr) {
    return (uintptr_t)ptr;
}

NOINLINE uintptr_t _delta_tag(unsigned long long size) {
    return (1ULL << BOUND_BITS) - size;
}
