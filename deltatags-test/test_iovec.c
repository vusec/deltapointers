#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/uio.h>

#include "deltatags.h"

DEBUG_MODULE_NAME("test_iovec");

int main(int argc, char **argv)
{
    struct iovec iov[3];

    int fd = open("/dev/null", O_WRONLY);
    if (fd == -1) {
        perror("open");
        return 1;
    }

    iov[0].iov_base = "Hello, ";
    iov[0].iov_len = strlen(iov[0].iov_base);
    iov[1].iov_base = "World";
    iov[1].iov_len = strlen(iov[1].iov_base);
    iov[2].iov_base = "!\n";
    iov[2].iov_len = strlen(iov[2].iov_base);
    size_t expected_size = strlen("Hello, World!\n");

    ssize_t ret = writev(fd, iov, 3);
    printf("writev: %zd\n", ret);

    if (ret == -1) {
        perror("writev");
        return 2;
    } else if (ret != expected_size) {
        fprintf(stderr, "writev returned %zd, expected %zu\n", ret, expected_size);
        return 3;
    }

    return 0;
}
