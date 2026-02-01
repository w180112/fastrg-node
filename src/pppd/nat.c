#include <rte_cycles.h>
#include <rte_timer.h>
#include <rte_atomic.h>

#include "pppd.h"
#include "nat.h"

void nat_rule_timer(__attribute__((unused)) struct rte_timer *tim, ppp_ccb_t *s_ppp_ccb)
{
    addr_table_t *table = s_ppp_ccb->addr_table;
    for(int i=0; i<MAX_NAT_ENTRIES; i++) {
        if (rte_atomic16_read(&table[i].is_fill) != NAT_ENTRY_READY)
            continue;
        rte_atomic_thread_fence(rte_memory_order_acquire);
        if (rte_atomic16_read(&table[i].is_alive) > 0) {
            rte_atomic16_sub(&table[i].is_alive, 1);
        } else {
            if (rte_atomic16_cmpset((volatile uint16_t *)&table[i].is_fill, 
                    NAT_ENTRY_READY, NAT_ENTRY_FREE)) {
                rte_atomic_thread_fence(rte_memory_order_acq_rel);

                if (rte_atomic16_read(&table[i].is_alive) > 0)
                    rte_atomic16_set(&table[i].is_fill, NAT_ENTRY_READY);
            }
        }
    }
}
