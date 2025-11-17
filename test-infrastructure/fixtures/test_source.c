#include <stdio.h>
#include <string.h>

struct TestStruct {
    int field1;
    char field2;
    long field3;
};

// Level 3 functions (leaf nodes)
int level3_add_one(int x) {
    return x + 1;
}

int level3_multiply_two(int x) {
    return x * 2;
}

int level3_square(int x) {
    return x * x;
}

// Level 2 functions (call level 3)
int level2_compute_a(int x) {
    int tmp = level3_add_one(x);
    return level3_multiply_two(tmp);
}

int level2_compute_b(int x) {
    return level3_square(x);
}

int level2_compute_c(int x, int y) {
    int a = level3_add_one(x);
    int b = level3_multiply_two(y);
    return a + b;
}

// Level 1 functions (call level 2)
int level1_complex_calc(int x) {
    int a = level2_compute_a(x);
    int b = level2_compute_b(x);
    return a + b;
}

int level1_simple_calc(int x, int y) {
    return level2_compute_c(x, y);
}

// Original simple functions
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

// Thunk-like wrapper functions
int thunk_add(int a, int b) {
    return add(a, b);
}

int thunk_multiply(int a, int b) {
    return multiply(a, b);
}

// Function with multiple direct calls
int multi_call_function(int x, int y) {
    int a = add(x, y);
    int b = multiply(x, y);
    int c = helper_function(x);
    return a + b + c;
}

int main(int argc, char **argv) {
    // Original calls
    int result = add(5, 3);
    printf("Result: %d\n", result);

    int doubled = helper_function(result);
    printf("Doubled: %d\n", doubled);

    struct TestStruct test = {10, 'A', 100L};

    // Test thunks
    int thunk_result = thunk_add(10, 20);
    printf("Thunk result: %d\n", thunk_result);

    // Test multi-level calls
    int complex = level1_complex_calc(5);
    printf("Complex: %d\n", complex);

    int simple = level1_simple_calc(3, 4);
    printf("Simple: %d\n", simple);

    // Test multi-call function
    int multi = multi_call_function(2, 3);
    printf("Multi: %d\n", multi);

    return multiply(result, 2);
}
