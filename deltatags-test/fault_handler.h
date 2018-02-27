#ifndef _FAULT_HANDLER_H
#define _FAULT_HANDLER_H

#define _GNU_SOURCE
#include <signal.h>
#include <fcntl.h>
#include <setjmp.h>

static int expect_fault = 0;
static jmp_buf chkp;

static void test_sig_handler(int sig, siginfo_t *si, void *ptr);

__attribute__((noinline))
static void install_sig_handler(void)
{
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = test_sig_handler;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
}

static void test_sig_handler(int sig, siginfo_t *si, void *ptr)
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

#endif /* _FAULT_HANDLER_H */
