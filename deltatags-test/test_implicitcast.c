#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "sizetags.h"

DEBUG_MODULE_NAME("test_implicitcast");

/* We intentionally don't include header files for open and read, so that they
 * are declared as i32 @open(...) and then casted to the correct type when used.
 */

int main(int argc, char **argv)
{
    char *a = malloc(10);
    int fd = open("/dev/zero", 0); /* O_RDONLY */
    printf("fd = %d\n", fd);
    assert(fd > 0);
    size_t r = read(fd, a, 10);
    printf("reading 10 bytes, got %zu\n ", r);
    assert(r == 10);

    return 0;
}
