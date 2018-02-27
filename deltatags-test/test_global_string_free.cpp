#include <iostream>

#include "sizetags.h"

DEBUG_MODULE_NAME("test_global_string_free");

std::string s;

int main(void)
{
    printf("s @ %p\n", &s);
    s = "foo";
    return 0;
}
