#include <stdio.h>
#include <unistd.h>

#include "deltatags.h"

DEBUG_MODULE_NAME("test_exec");

int main(int argc, char **argv, char **envp)
{
    if (argc == 2) {
        printf("%s child reporting in\n", argv[0]);
        return 0;
    }
    char *newargv[] = {argv[0], "dummy", NULL};
    execve(argv[0], newargv, envp);
    perror("execve");
    return -1;
}
