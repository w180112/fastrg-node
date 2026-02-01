#ifndef _TIMER_H_
#define _TIMER_H_

/**
 * @fn timer_loop
 * 
 * @brief FastRG timer thread main loop for system wide timer management
 * @param arg
 *      unused
 * @return
 *      int
 */
int timer_loop(__rte_unused void *arg);

#endif
