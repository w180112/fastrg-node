#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <common.h>

#include "../src/utils.h"
#include "../src/fastrg.h"
#include "test_helper.h"

// Global test counters
static int test_count = 0;
static int pass_count = 0;

void test_make_eal_args_string()
{
    printf("\nTesting make_eal_args_string function:\n");
    printf("=========================================\n\n");

    const char *argv[] = {
        "program_name",
        "-c",
        "0x3",
        "-n",
        "4",
        "--log-level=7"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    char *eal_args = make_eal_args_string(argc, argv);
    const char *expected = "program_name -c 0x3 -n 4 --log-level=7";

    printf("Test 1: \"%s\"\n", expected);
    TEST_ASSERT(strcmp(eal_args, expected) == 0, 
        "make_eal_args_string produces expected output", "got %s", eal_args);

    free(eal_args);
}

void test_parse_ip_range()
{
    U32 ip_start, ip_end;
    STATUS ret;

    printf("\nTesting parse_ip_range function:\n");
    printf("=========================================\n\n");

    printf("Test 1: \"192.168.1.1~192.168.1.150\"\n");
    ret = parse_ip_range("192.168.1.1~192.168.1.150", &ip_start, &ip_end);
    TEST_ASSERT(ret == SUCCESS && ip_start == 0x0101a8c0 && ip_end == 0x9601a8c0, 
        "Test 1: Valid IP range", "got ip_start=0x%08x, ip_end=0x%08x", ip_start, ip_end);

    printf("Test 2: \"10.0.0.1-10.0.0.100\"\n");
    ret = parse_ip_range("10.0.0.1-10.0.0.100", &ip_start, &ip_end);
    TEST_ASSERT(ret == SUCCESS && ip_start == 0x0100000a && ip_end == 0x6400000a, 
        "Test 2: Valid IP range", "got ip_start=0x%08x, ip_end=0x%08x", ip_start, ip_end);

    printf("Test 3: \"172.16.0.1~172.16.0.1\"\n");
    ret = parse_ip_range("172.16.0.1~172.16.0.1", &ip_start, &ip_end);
    TEST_ASSERT(ret == SUCCESS && ip_start == ip_end, "Test 3: Valid IP range", 
        "got ip_start=0x%08x, ip_end=0x%08x", ip_start, ip_end);

    printf("Test 4: Invalid \"192.168.1.1\" (no delimiter)\n");
    ret = parse_ip_range("192.168.1.1", &ip_start, &ip_end);
    TEST_ASSERT(ret == ERROR, "Test 4: Invalid IP range", 
        "got ip_start=0x%08x, ip_end=0x%08x", ip_start, ip_end);

    printf("Test 5: Invalid \"192.168.1.150~192.168.1.1\"\n");
    ret = parse_ip_range("192.168.1.150~192.168.1.1", &ip_start, &ip_end);
    TEST_ASSERT(ret == ERROR, "Test 5: Invalid IP range", 
        "got ip_start=0x%08x, ip_end=0x%08x", ip_start, ip_end);

    return;
}

void test_parse_ip()
{
    printf("\nTesting ip parsing:\n");
    printf("=========================================\n\n");

    U32 address;
    printf("Test 1: \"255.255.255.0\"\n");
    int ret = parse_ip("255.255.255.0", &address);
    TEST_ASSERT(ret == SUCCESS && address == 0x00ffffff, "Test 1: Valid IP address", 
        "return %d and got 0x%08x", ret, address);

    printf("Test 2: Invalid \"255.255.255.256\"\n");
    ret = parse_ip("255.255.255.256", &address);
    TEST_ASSERT(ret == ERROR, "Test 2: Invalid IP address", "got return ERROR");

    printf("Test 3: \"192.168.1.1\"\n");
    ret = parse_ip("192.168.1.1", &address);
    TEST_ASSERT(ret == SUCCESS && address == 0x0101a8c0, "Test 3: Valid IP address", 
        "return ERROR and got 0x%08x", address);

    return;
}

void test_is_ip_in_range()
{
    U32 gateway_ip = 0xc0a80101; // 192.168.1.1
    U32 subnet_mask = 0xffffff00; // 255.255.255.0
    U32 ip;
    BOOL ret;

    printf("\nTesting is_ip_in_range function:\n");
    printf("=========================================\n\n");
    ip = 0xc0a80164; // 192.168.1.100
    ret = is_ip_in_range(ip, gateway_ip, subnet_mask);
    TEST_ASSERT(ret == TRUE, "Test 1: IP in range", "got return FALSE");

    ip = 0xc0a80201; // 192.168.2.1
    ret = is_ip_in_range(ip, gateway_ip, subnet_mask);
    TEST_ASSERT(ret == FALSE, "Test 2: IP not in range", "got return TRUE");
}

void test_parse_unix_sock_path()
{
    char *path = NULL;
    size_t path_len = 0;
    STATUS ret;

    printf("\nTesting parse_unix_sock_path function:\n");
    printf("=========================================\n\n");

    printf("Test 1: \"unix:///var/run/fastrg/fastrg.sock\"\n");
    ret = parse_unix_sock_path("unix:///var/run/fastrg/fastrg.sock", 
        &path, &path_len);
    TEST_ASSERT(ret == SUCCESS && path_len == strlen("/var/run/fastrg") && 
        strncmp(path, "/var/run/fastrg/fastrg.sock", path_len) == 0, 
        "Test 1: Valid unix socket path", "got path=\"%.*s\", length=%zu", 
        (int)path_len, path, path_len);

    printf("Test 2: Invalid \"unix://fastrg.sock\" (no leading slash)\n");
    ret = parse_unix_sock_path("unix://fastrg.sock", &path, &path_len);
    TEST_ASSERT(ret == ERROR, "Test 2: Invalid unix socket path", 
        "got path=\"%.*s\", length=%zu", (int)path_len, path, path_len);

    printf("Test 3: Invalid \"http:///var/run/fastrg/fastrg.sock\" (wrong prefix)\n");
    ret = parse_unix_sock_path("http:///var/run/fastrg/fastrg.sock", &path, &path_len);
    TEST_ASSERT(ret == ERROR, "Test 3: Invalid unix socket path", 
        "got path=\"%.*s\", length=%zu", (int)path_len, path, path_len);
}

void test_create_dir_if_not_exists()
{
    printf("\nTesting create_dir_if_not_exists function:\n");
    printf("=========================================\n\n");

    const char *test_dir = "/tmp/fastrg_test_dir";

    // Test creating a new directory
    STATUS ret = create_dir_if_not_exists(test_dir);
    TEST_ASSERT(ret == SUCCESS, "Test 1: Create new directory", 
        "return %d", ret);

    // Test creating the same directory again (should succeed)
    ret = create_dir_if_not_exists(test_dir);
    TEST_ASSERT(ret == SUCCESS, "Test 2: Create existing directory", 
        "return %d", ret);

    // Cleanup
    rmdir(test_dir);
}

void test_utils(FastRG_t *fastrg_ccb, U32 *total_tests, U32 *total_pass)
{
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║           Utilities Unit Tests                             ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");

    test_count = 0;
    pass_count = 0;

    test_make_eal_args_string();
    test_parse_ip_range();
    test_parse_ip();
    test_is_ip_in_range();
    test_parse_unix_sock_path();
    test_create_dir_if_not_exists();

    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║  Test Summary                                              ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");
    printf("║  Total Tests:  %3d                                         ║\n", test_count);
    printf("║  Passed:       %3d                                         ║\n", pass_count);
    printf("║  Failed:       %3d                                         ║\n", test_count - pass_count);
    printf("║  Success Rate: %3d%%                                        ║\n", 
           test_count > 0 ? (pass_count * 100 / test_count) : 0);
    printf("╚════════════════════════════════════════════════════════════╝\n");

    if (pass_count == test_count) {
        printf("\n✓ All tests passed!\n");
    } else {
        printf("\n✗ Some tests failed!\n");
    }

    *total_tests += test_count;
    *total_pass += pass_count;
}
