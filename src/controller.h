#ifndef _CONTROLLER_H_
#define _CONTROLLER_H_

#include <rte_timer.h>

#include "fastrg.h"

/* Controller timer callback functions */
void controller_heartbeat_timer_cb(__rte_unused struct rte_timer *tim, void *arg);

/* Controller initialization and cleanup */
int controller_init(FastRG_t *fastrg_ccb);
void controller_cleanup(FastRG_t *fastrg_ccb);

/* Controller node registration */
int controller_register_this_node(FastRG_t *fastrg_ccb);

#endif /* _CONTROLLER_H_ */