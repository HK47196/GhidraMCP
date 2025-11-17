#include <stdio.h>
#include <string.h>

struct TestStruct {
    int field1;
    char field2;
    long field3;
};

int add(int a, int b) {
    return a + b;
}

int multiply(int a, int b) {
    return a * b;
}

int helper_function(int x) {
    return x * 2;
}

void string_function(char *dest, const char *src) {
    strcpy(dest, src);
}

int main(int argc, char **argv) {
    int result = add(5, 3);
    printf("Result: %d\n", result);

    int doubled = helper_function(result);
    printf("Doubled: %d\n", doubled);

    struct TestStruct test = {10, 'A', 100L};

    return multiply(result, 2);
}
