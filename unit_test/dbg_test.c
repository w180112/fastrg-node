#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "../src/dbg.h"
#include "../src/pppd/fsm.h"
#include "../src/dhcpd/dhcp_fsm.h"
#include "../src/fastrg.h"
#include "test_helper.h"

static int test_count = 0;
static int pass_count = 0;

void test_loglvl2str()
{
    printf("\nTesting loglvl2str function:\n");
    printf("=========================================\n\n");

    TEST_ASSERT(strcmp(loglvl2str(LOGDBG), "DBG") == 0, "LOG level to string", "LOGDBG -> DBG");
    TEST_ASSERT(strcmp(loglvl2str(LOGINFO), "INFO") == 0, "LOG level to string", "LOGINFO -> INFO");
    TEST_ASSERT(strcmp(loglvl2str(LOGWARN), "WARN") == 0, "LOG level to string", "LOGWARN -> WARN");
    TEST_ASSERT(strcmp(loglvl2str(LOGERR), "ERR") == 0, "LOG level to string", "LOGERR -> ERR");
    TEST_ASSERT(strcmp(loglvl2str(99), "UNKNOWN") == 0, "LOG level to string", "Invalid level -> UNKNOWN");

    printf("✓ Test passed\n");
}

void test_logstr2lvl()
{
    printf("\nTesting logstr2lvl function:\n");
    printf("=========================================\n\n");

    TEST_ASSERT(logstr2lvl("DBG") == LOGDBG, 
        "LOG string to level", "DBG -> LOGDBG");
    TEST_ASSERT(logstr2lvl("INFO") == LOGINFO, 
        "LOG string to level", "INFO -> LOGINFO");
    TEST_ASSERT(logstr2lvl("WARN") == LOGWARN, 
        "LOG string to level", "WARN -> LOGWARN");
    TEST_ASSERT(logstr2lvl("ERR") == LOGERR, 
        "LOG string to level", "ERR -> LOGERR");
    TEST_ASSERT(logstr2lvl("INVALID") == LOGUNKNOWN, 
        "LOG string to level", "INVALID -> LOGUNKNOWN");
    TEST_ASSERT(logstr2lvl(NULL) == LOGUNKNOWN, 
        "LOG string to level", "NULL -> LOGUNKNOWN");

    printf("✓ Test passed\n");
}

void test_ppp_state2str()
{
    printf("\nTesting PPP_state2str function:\n");
    printf("=========================================\n\n");

    TEST_ASSERT(strcmp(PPP_state2str(S_INIT), "INIT") == 0, 
        "PPP state to string", "State is not INIT");
    TEST_ASSERT(strcmp(PPP_state2str(S_OPENED), "OPENED") == 0, 
        "PPP state to string", "State is not OPENED");
    TEST_ASSERT(strcmp(PPP_state2str(S_INVLD), "Unknown") == 0, 
        "PPP state to string", "State is not Unknown");

    printf("✓ Test passed\n");
}

void test_ppp_event2str()
{
    printf("\nTesting PPP_event2str function:\n");
    printf("=========================================\n\n");

    TEST_ASSERT(strcmp(PPP_event2str(E_UP), "UP") == 0, 
        "PPP event to string", "E_UP -> UP");
    TEST_ASSERT(strcmp(PPP_event2str(E_OPEN), "OPEN") == 0, 
        "PPP event to string", "E_OPEN -> OPEN");
    TEST_ASSERT(strcmp(PPP_event2str(E_UNKNOWN), "UNKNOWN") == 0, 
        "PPP event to string", "E_UNKNOWN -> UNKNOWN");

    printf("✓ Test passed\n");
}

void test_dhcp_state2str()
{
    printf("\nTesting DHCP_state2str function:\n");
    printf("=========================================\n\n");

    TEST_ASSERT(strcmp(DHCP_state2str(S_DHCP_INIT), "DHCP INIT") == 0, 
        "DHCP state to string", "S_DHCP_INIT -> DHCP INIT");
    TEST_ASSERT(strcmp(DHCP_state2str(S_DHCP_ACK_SENT), "DHCP ACK SENT") == 0, 
        "DHCP state to string", "S_DHCP_ACK_SENT -> DHCP ACK SENT");
    TEST_ASSERT(strcmp(DHCP_state2str(S_DHCP_INVLD), "DHCP INVALID") == 0, 
        "DHCP state to string", "S_DHCP_INVLD -> DHCP INVALID");

    printf("✓ Test passed\n");
}

void test_dbg(FastRG_t *fastrg_ccb, U32 *total_tests, U32 *total_pass)
{
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║              Debug Module Unit Tests                      ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");

    test_loglvl2str();
    test_logstr2lvl();
    test_ppp_state2str();
    test_ppp_event2str();
    test_dhcp_state2str();

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

    *total_tests += test_count;
    *total_pass += pass_count;
}
