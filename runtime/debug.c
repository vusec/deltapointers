#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

#include "noinstrument.h"

#ifdef DEBUG

#define LOGPATH_ENVVAR "DEBUGNEGARITH_PATH"
#define DEFAULT_LOGPATH "debugnegarith.out"

int NOINSTRUMENT(outfile) = 2;

void NOINSTRUMENT(check_neg_arith)(uint64_t gep_num, void *ptr, long offset, int is_constant_gep) {
    uintptr_t upper;
    if (offset >= 0)
        return;
    upper = (uintptr_t)ptr >> 32;
    if (upper < -1 * offset)
        dprintf(NOINSTRUMENT(outfile), "UNSAFE GEP %llu: %p + %ld (%d)\n", gep_num, ptr, offset, is_constant_gep);

    /* This is interesting but *a lot* */
#if 0
    else if (offset < 0 && !is_constant_gep)
        dprintf(NOINSTRUMENT(outfile), "DYN NEG SAFE GEP %llu: %p + %ld\n", gep_num, ptr, offset, is_constant_gep);
#endif
}

#if 1
__attribute__((constructor(1000)))
void NOINSTRUMENT(init_debugnegarith)() {
    char *logpath = getenv(LOGPATH_ENVVAR);
    if (logpath == NULL)
        logpath = DEFAULT_LOGPATH;
    NOINSTRUMENT(outfile) = open(logpath, O_WRONLY | O_TRUNC | O_CREAT, 0644);
}

__attribute__((destructor))
void NOINSTRUMENT(finalize_debugnegarith)() {
    close(NOINSTRUMENT(outfile));
}
#endif

#endif /* DEBUG */
