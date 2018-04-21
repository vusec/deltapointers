#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "deltatags.h"

DEBUG_MODULE_NAME("test_old");

/* Make compiler play nice for simple code. */
#define USED(x) \
    __asm__ __volatile__("" :: "r"(x))
#define CLOBBER(x) \
    __asm__ __volatile__(\
            "mov %1, %0\n\t" \
            :"=r"(x) \
            : "r"(x))

struct mystruct_t {
    const char *format;
    union {
        int ival;
        double dval;
    } value;
};

extern char **environ;

char glob[100] = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque bibendum leo eu purus pretium amet.";

static int zero[100] = {0};

__attribute__ ((noinline)) void *foo_do(size_t size)
{
    char *tmp = malloc(size);
    memset(tmp, 0, size);
    return tmp;
}

__attribute__((noinline)) void takes_struct_by_val(struct mystruct_t s)
{
    printf(s.format, s.value.ival);
    memcpy((char*)&s, zero, sizeof (struct mystruct_t));
}

__attribute__((noinline)) void takes_struct_by_ref(struct mystruct_t *s)
{
    printf(s->format, s->value.dval);
    memcpy((char*)s, zero, sizeof (struct mystruct_t));
}

int main(int argc, char **argv)
{
    int *a = malloc(1000 * sizeof(int));
    char *b = calloc(1000, 1);
    char *c = foo_do(1000);
    char *d = malloc(argc + sizeof(struct mystruct_t));
    char *e = foo_do(argc);
    char *f = calloc(argc, 8);
    int *g;
    int h[1000];

    struct mystruct_t struct_a = {"I haz int: %d\n", 1};
    struct mystruct_t struct_b = {"I haz int too: %d\n", 2};

    USED(c);
    USED(d);
    USED(e);
    USED(f);
    b[0] = 'A';
    b[1] = 'B';
    printf("b: %p %s\n", b, b);
    printf("array spans %p - %p (inclusive)\n", &a[0], &a[999]);
    a[999] = 42;
    //a[1000] = 43; /* crash */
    *a = 1;
    a++;
    *a = 2;
    g = a;
    a += 100;
    *a = 3;
    CLOBBER(a);
    printf("%p %d %d %d\n", a, *a, *g, a[-100]);
    a += 1000;
    CLOBBER(a);
    printf("%p\n", a);
    a -= 102; /* a[999] */
    printf("%p %d\n", a, *a);
    CLOBBER(a);
    a = (int*)((char*)a + 3);
    printf("%p %d\n", a, *a);
    //CLOBBER(h); // FIXME
    h[50] = 50;
    //CLOBBER(h); // FIXME
    printf("%p %d\n", &h[50], h[50]);

    takes_struct_by_val(struct_a);
    takes_struct_by_val(struct_b);
    takes_struct_by_ref(&struct_a);
    takes_struct_by_ref(&struct_b);
    takes_struct_by_ref((struct mystruct_t*)d);

    printf("environ[0]: %s\n", environ[0]);
    printf("glob: %s\n", glob);

    return 0;
}
