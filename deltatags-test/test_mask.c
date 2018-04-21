#include <stdio.h>
#include <sys/time.h>

#include "deltatags.h"

DEBUG_MODULE_NAME("test_mask");

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s N\n", argv[0]);
        return 0;  // so that the testcase succeeds
    }

    long long i, n = atoi(argv[1]);

    if (n > 0x7fffffff) {
        fprintf(stderr, "max N is %lld\n", 0x7fffffffLL);
        return 1;
    }

    volatile char *a = malloc(n * sizeof (char));
    if (!a) {
        perror("malloc");
        return 1;
    }

    struct timeval tv_start, tv_end;
    if (gettimeofday(&tv_start, NULL) < 0) {
        perror("gettimeofday");
        return 1;
    }

    for (i = 0; i < n; i++) {
        a[i] = (char)(argc * i);
    }

    if (gettimeofday(&tv_end, NULL) < 0) {
        perror("gettimeofday");
        return 1;
    }
    double diff = (double)(tv_end.tv_sec - tv_start.tv_sec) +
        (double)(tv_end.tv_usec - tv_start.tv_usec) / 1e6;
    printf("%lld iterations took %g seconds\n", n, diff);

    free((void*)a);

    return 0;
}
