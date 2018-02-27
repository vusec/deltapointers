#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <setjmp.h>

#include "sizetags.h"

DEBUG_MODULE_NAME("test_memintrinsics");

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

    char *a = malloc(10);
    char *b = malloc(1000);
    char *c = malloc(1001);
    int ret;

    /************
     *  memcpy  *
     ************/

    printf("memcpy(a, argv, 10) (OK)\n");
    memcpy(a, argv, 10);
    USE(a);

    printf("memcpy(a, argv, 11) (small, should fault on dest!)\n");
    checkpoint(cont1);
    memcpy(a, argv, 11);
    assert(!"err 1");
    USE(a);

cont1:
    printf("memcpy(b, c, 1001) (should fault on dest!)\n");
    checkpoint(cont2);
    memcpy(b, c, 1001);
    assert(!"err 2");

cont2:
    printf("memcpy(c, b, 1001) (should fault on src!)\n");
    checkpoint(cont3);
    memcpy(c, b, 1001);
    assert(!"err 3");

cont3:
    /************
     *  memset  *
     ************/

    printf("memset(c, 2, 1001) (OK)\n");
    memset(c, 2, 1001);

    printf("memset(b, 4, 1001) (should fault)\n");
    checkpoint(cont4);
    memset(b, 4, 1001);
    assert(!"err 4");

cont4:
    /*************
     *  memmove  *
     *************/

    printf("memmove(b, c, 1000) (OK)\n");
    memmove(b, c, 1000);

    printf("memmove(b, c, 1001) (fault dest)\n");
    checkpoint(cont5);
    memmove(b, c, 1001);
    assert(!"err 5");

cont5:
    printf("memmove(c, b, 1001) (fault src)\n");
    checkpoint(cont6);
    memmove(c, b, 1001);
    assert(!"err 6");

cont6:
    /************
     *  memcmp  *
     ************/

    printf("memcmp(b, c, 1000) (OK) %p %p\n", b, c);
    ret = memcmp(b, c, 1000);
    USE(ret);

    printf("memcmp(b, c, 1001) (fault arg1)\n");
    checkpoint(cont7);
    ret = memcmp(b, c, 1001);
    assert(!"err 7");
    USE(ret);
cont7:
    printf("memcmp(c, b, 1001) (fault arg2)\n");
    checkpoint(cont8);
    ret = memcmp(c, b, 1001);
    assert(!"err 8");
    USE(ret);


cont8:
    printf("Succes!\n");
    /* Our stack is actually kinda broken here, return 0 does odd stuff. */
    exit(0);
}
