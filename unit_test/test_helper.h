#ifndef TEST_HELPER_H
#define TEST_HELPER_H

#include <stdarg.h>

#define MODULE_INIT(fn) \
static void __attribute__((constructor)) do_md_ ## fn(void) \
{ \
    int ret; \
    if ((ret = fn()) < 0) { \
        fprintf(stderr, "Module initialization failed: %s returned %d\n", #fn, ret); \
        exit(EXIT_FAILURE); \
    } \
}

static inline void _test_assert_impl(int *test_count_p, int *pass_count_p, 
    int condition, const char *test_name, const char *fmt, ...)
{
    (*test_count_p)++;
    if (condition) {
        printf("  ✓ PASS: %s\n", test_name);
        (*pass_count_p)++;
        return;
    }

    printf("  ✗ FAIL: %s\n", test_name);
    if (fmt) {
        printf("    Error: ");
        va_list ap;
        va_start(ap, fmt);
        vprintf(fmt, ap);
        va_end(ap);
        printf("\n");
    }
    assert(condition);
}

// TEST_ASSERT(condition, test_name [, fmt, ...]) - pass addresses of counters so the
// inline function doesn't require those globals to be declared before including this header.
#define TEST_ASSERT(condition, test_name, ...) _test_assert_impl(&test_count, &pass_count, (condition), (test_name), ##__VA_ARGS__)

#endif // TEST_HELPER_H
