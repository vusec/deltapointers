#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include "noinstrument.h"

#ifdef RUNTIME_STATS

#define OUTFILE_BASE_ENVVAR "RTS_OUTFILE_BASE"
#define OUTFILE_BASE_DEFAULT "rts_"

unsigned long NOINSTRUMENT(stat_gep_total);
unsigned long NOINSTRUMENT(stat_gep_dyn);
unsigned long NOINSTRUMENT(stat_gep_dyn_neg);
unsigned long NOINSTRUMENT(stat_gep_const_neg);
unsigned long NOINSTRUMENT(stat_gep_nometa);

unsigned long NOINSTRUMENT(stat_loads_total);
unsigned long NOINSTRUMENT(stat_loads_nometa);
unsigned long NOINSTRUMENT(stat_stores_total);
unsigned long NOINSTRUMENT(stat_stores_nometa);


__attribute__((constructor(1000)))
void NOINSTRUMENT(init_rts)() {
    NOINSTRUMENT(stat_gep_total) = 0;
    NOINSTRUMENT(stat_gep_dyn) = 0;
    NOINSTRUMENT(stat_gep_dyn_neg) = 0;
    NOINSTRUMENT(stat_gep_const_neg) = 0;
    NOINSTRUMENT(stat_loads_total) = 0;
    NOINSTRUMENT(stat_loads_nometa) = 0;
    NOINSTRUMENT(stat_stores_total) = 0;
    NOINSTRUMENT(stat_stores_nometa) = 0;
}

__attribute__((destructor))
void NOINSTRUMENT(finalize_rts)() {
    char *outfile_base = getenv(OUTFILE_BASE_ENVVAR);
    if (outfile_base == NULL)
        outfile_base = OUTFILE_BASE_DEFAULT;

    /* Determine unused filename, as SPEC has multiple runs/inputsets. */
    char outfile[255];
    unsigned num = 0;
    do {
        snprintf(outfile, sizeof(outfile), "%s%d", outfile_base, num);
        num++;
    } while (access(outfile, F_OK) != -1);


    FILE *f = fopen(outfile, "w");
    fprintf(f, "gep_total: %lu\n", NOINSTRUMENT(stat_gep_total));
    fprintf(f, "gep_dyn: %lu\n", NOINSTRUMENT(stat_gep_dyn));
    fprintf(f, "gep_dyn_neg: %lu\n", NOINSTRUMENT(stat_gep_dyn_neg));
    fprintf(f, "gep_const_neg: %lu\n", NOINSTRUMENT(stat_gep_const_neg));
    fprintf(f, "gep_nometa: %lu\n", NOINSTRUMENT(stat_gep_nometa));

    fprintf(f, "loads_total: %lu\n", NOINSTRUMENT(stat_loads_total));
    fprintf(f, "loads_nometa: %lu\n", NOINSTRUMENT(stat_loads_nometa));
    fprintf(f, "stores_total: %lu\n", NOINSTRUMENT(stat_stores_total));
    fprintf(f, "stores_nometa: %lu\n", NOINSTRUMENT(stat_stores_nometa));
    fclose(f);
}

void NOINSTRUMENT(rts_gep)(void *ptr, int64_t off, int is_constant) {
    NOINSTRUMENT(stat_gep_total)++;
    if (!is_constant)
        NOINSTRUMENT(stat_gep_dyn)++;
    if (!is_constant && off < 0)
        NOINSTRUMENT(stat_gep_dyn_neg)++;
    if (is_constant && off < 0)
        NOINSTRUMENT(stat_gep_const_neg)++;

    if (((uintptr_t)ptr & (0xffffffffULL << 32)) == 0)
        NOINSTRUMENT(stat_gep_nometa)++;
}

void NOINSTRUMENT(rts_load)(void *ptr) {
    NOINSTRUMENT(stat_loads_total)++;

    if (((uintptr_t)ptr & (0xffffffffULL << 32)) == 0)
        NOINSTRUMENT(stat_loads_nometa)++;
}

void NOINSTRUMENT(rts_store)(void *ptr) {
    NOINSTRUMENT(stat_stores_total)++;

    if (((uintptr_t)ptr & (0xffffffffULL << 32)) == 0)
        NOINSTRUMENT(stat_stores_nometa)++;
}

#endif /* RUNTIME_STATS */
