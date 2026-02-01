#include <sys/resource.h>

#include <common.h>

#include "../src/fastrg.h"
#include "../src/pppd/codec.h"
#include "../src/pppd/fsm.h"
#include "../src/dbg.h"
#include "test.h"

FastRG_t *init_ccb()
{
    FastRG_t *ccb = malloc(sizeof(FastRG_t));

    ccb->fp = NULL,
    ccb->nic_info = (struct nic_info){
        .hsi_wan_src_mac = {
            .addr_bytes = {0x9c, 0x69, 0xb4, 0x61, 0x16, 0xdd},
        },
        .hsi_lan_mac = {
            .addr_bytes = {0x9c, 0x69, 0xb4, 0x61, 0x16, 0xdc},
        },
    };
    ccb->user_count = 1;
    ccb->loglvl = -1;
    dbg_init((void *)ccb);

    return ccb;
}

int main()
{
    struct rlimit rlim;
    int ret = 0;

    // Set ulimit to unlimited for core dumps and file descriptors
    rlim.rlim_cur = RLIM_INFINITY;
    rlim.rlim_max = RLIM_INFINITY;

    if (setrlimit(RLIMIT_CORE, &rlim) == 0)
        printf("Set core dump size to unlimited\n");

    if (setrlimit(RLIMIT_NOFILE, &rlim) == 0)
        printf("Set max open files to unlimited\n");

    /* Set stack size to unlimited (equivalent to `ulimit -s unlimited`) */
    if (setrlimit(RLIMIT_STACK, &rlim) == 0)
        printf("Set stack size to unlimited\n");

    signal(SIGCHLD, SIG_IGN);

    puts("====================start unit tests====================\n");
    FastRG_t *fastrg_ccb = init_ccb();
    if (fastrg_ccb == NULL) {
        puts("Failed to mock FastRG CCB");
        return 1;
    }
    U32 total_tests = 0;
    U32 total_pass = 0;

    puts("====================test pppd/codec.c====================");
    test_ppp_codec(fastrg_ccb, &total_tests, &total_pass);
    puts("ok!");

    puts("====================test pppd/fsm.c====================");
    test_ppp_fsm(fastrg_ccb, &total_tests, &total_pass);
    puts("ok!");

    puts("====================test dhcpd/dhcp_codec.c====================");
    test_dhcp_codec(fastrg_ccb, &total_tests, &total_pass);
    puts("ok!");

    puts("====================test utils.c====================");
    test_utils(fastrg_ccb, &total_tests, &total_pass);
    puts("ok!");

    puts("====================test avl_tree.c====================");
    test_avl_tree(fastrg_ccb, &total_tests, &total_pass);
    puts("ok!");

    puts("====================test pppd/nat.h====================");
    test_nat(fastrg_ccb, &total_tests, &total_pass);
    puts("ok!");

    puts("====================test etcd_integration.c====================");
    test_etcd_integration(fastrg_ccb, &total_tests, &total_pass);
    puts("ok!");

    puts("====================test dp_codec.h====================");
    test_dp_codec(fastrg_ccb, &total_tests, &total_pass);
    puts("ok!");

    puts("====================test dbg.c====================");
    test_dbg(fastrg_ccb, &total_tests, &total_pass);
    puts("ok!");

    puts("====================test config.c====================");
    test_config(fastrg_ccb, &total_tests, &total_pass);
    puts("ok!");

    printf("\n====================Unit Test Summary====================\n\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║  All Test Summary                                          ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");
    printf("║  Total Tests:  %3d                                         ║\n", total_tests);
    printf("║  Passed:       %3d                                         ║\n", total_pass);
    printf("║  Failed:       %3d                                         ║\n", total_tests - total_pass);
    printf("║  Success Rate: %3d%%                                        ║\n", 
           total_tests > 0 ? (total_pass * 100 / total_tests) : 0);
    printf("╚════════════════════════════════════════════════════════════╝\n");
    if (total_tests == total_pass) {
        printf("\nAll %u tests passed successfully\n\n", total_tests);
        ret = 0;
    } else {
        printf("\n%d/%d tests failed\n\n", total_tests - total_pass, total_tests);
        ret = 1;
    }

    puts("====================end of unit tests====================");

    return ret;
}
