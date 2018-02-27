#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#include "sizetags.h"

DEBUG_MODULE_NAME("test_fork");

int main(void) {
    int pid;

    pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(1);
    } else if (pid == 0) {
        /* Child */
        printf("Print from child\n");
    } else {
        /* Parent */
        int status, retpid;
        printf("Print from parent, child pid: %d\n", pid);
        retpid = waitpid(pid, &status, 0);
        printf("Waitpid: pid: %d, exited: %d, exitstatus: %d\n", retpid, WIFEXITED(status), WEXITSTATUS(status));
        assert(retpid == pid);
        assert(WIFEXITED(status));
        assert(WEXITSTATUS(status) == 0);
    }

    return 0;
}
