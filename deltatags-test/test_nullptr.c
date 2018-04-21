#include <stdio.h>

#include "deltatags.h"
#include "fault_handler.h"

DEBUG_MODULE_NAME("test_nullptr");

static unsigned int glob = 0xdeadbeef;

int main(int argc, char **argv)
{
    install_sig_handler();

    char *exploitable = NULL;
    unsigned int *ptr = &glob;

    printf("NULL[offset] dereference, should fault\n");
    checkpoint(end);
    unsigned int leaked_glob = *(unsigned int*)&exploitable[(unsigned long long)ptr];
    assert(leaked_glob == 0xdeadbeef);
    assert(!"value of glob was leaked");

end:
    return 0;
}
