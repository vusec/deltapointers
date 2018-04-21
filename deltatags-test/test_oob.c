#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <setjmp.h>

#include "deltatags.h"

DEBUG_MODULE_NAME("test_oob");

int expect_fault = 0;
jmp_buf chkp;

void test_sig_handler(int sig, siginfo_t *si, void *ptr);

void install_sig_handler(void)
{
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = test_sig_handler;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
}

void test_sig_handler(int sig, siginfo_t *si, void *ptr)
{
    if (!expect_fault)
        exit(1);

    expect_fault = 0;
    install_sig_handler();
    siglongjmp(chkp, 1);
}

#define checkpoint(x) \
    do { \
        expect_fault = 1; \
        if (sigsetjmp(chkp, 1))  \
            goto x; \
    } while (0)


int main(int argc, char **argv)
{
    install_sig_handler();

#define USE(var) dprintf(null, "var " #var ": %lx\n", (unsigned long)var)
    int null = open("/dev/null", O_WRONLY);

    volatile char *a = malloc(10);

    printf("a[9] = 1; (OK)\n");
    a[9] = 1;

    printf("read a[9]; (OK)\n");
    USE(a[9]);

    printf("a[10] = 1; (should fail)\n");
    checkpoint(cont1);
    a[10] = 1;
    assert(!"err 1");

cont1:
    printf("read a[10] (should fail)\n");
    checkpoint(cont2);
    USE(a[10]);
    assert(!"err 2");

cont2:
    return 0;
}
