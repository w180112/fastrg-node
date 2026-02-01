#include <common.h>

#include "fastrg.h"
#include "dbg.h"
#include "dhcpd/dhcpd.h"
#include "pppd/pppd.h"
#include "../northbound/controller/etcd_client.h"

BOOL is_valid_ccb_id(const FastRG_t *fastrg_ccb, int ccb_id)
{
    return (fastrg_ccb != NULL && 
            fastrg_ccb->ppp_ccb != NULL && 
            fastrg_ccb->dhcp_ccb != NULL &&
            ccb_id >= 0 && 
            ccb_id < fastrg_ccb->user_count && 
            DHCPD_GET_CCB(fastrg_ccb, ccb_id) != NULL &&
            PPPD_GET_CCB(fastrg_ccb, ccb_id) != NULL);
}

static inline STATUS set_vlan_map_ccb_id(FastRG_t *fastrg_ccb, U16 vlan_id, U16 ccb_id)
{
    if (vlan_id < 1 || vlan_id > MAX_VLAN_ID) {
        FastRG_LOG(ERR, fastrg_ccb->fp, NULL, NULL, "Invalid VLAN ID: %u (must be 1-%d)", vlan_id, MAX_VLAN_ID);
        return ERROR;
    }

    if (rte_atomic16_cmpset((volatile uint16_t *)&fastrg_ccb->vlan_userid_map[vlan_id - 1].cnt,
            INVALID_CCB_ID, ccb_id) == 0) {
        FastRG_LOG(ERR, fastrg_ccb->fp, NULL, NULL, "VLAN ID %u is already assigned to another user", vlan_id);
        return ERROR;
    }
    return SUCCESS;
}

void reset_vlan_map_ccb_id(FastRG_t *fastrg_ccb, U16 vlan_id)
{
    if (vlan_id < 1 || vlan_id > MAX_VLAN_ID)
        return;

    rte_atomic16_set(&fastrg_ccb->vlan_userid_map[vlan_id - 1], INVALID_CCB_ID);
}

STATUS apply_hsi_config(FastRG_t *fastrg_ccb, int ccb_id, const hsi_config_t *config, BOOL is_update)
{
    U32 dhcp_ip_start, dhcp_ip_end, dhcp_subnet_mask, dhcp_gateway;
    int ret;

    if (!is_valid_ccb_id(fastrg_ccb, ccb_id) || !config)
        return ERROR;

    ppp_ccb_t *ppp_ccb = PPPD_GET_CCB(fastrg_ccb, ccb_id);
    dhcp_ccb_t *dhcp_ccb = DHCPD_GET_CCB(fastrg_ccb, ccb_id);

    U16 vlan_id;
    if (parse_vlan_id(config->vlan_id, &vlan_id) == ERROR) {
        FastRG_LOG(ERR, fastrg_ccb->fp, NULL, NULL, "Invalid VLAN ID: %s", config->vlan_id);
        return ERROR;
    }
    U16 ori_ppp_status = rte_atomic16_read(&ppp_ccb->ppp_bool);
    U16 ori_dp_status = rte_atomic16_read(&ppp_ccb->dp_start_bool);
    U16 ori_dhcp_status = rte_atomic16_read(&dhcp_ccb->dhcp_bool);

    rte_atomic16_set(&ppp_ccb->ppp_bool, 0);
    rte_atomic16_set(&ppp_ccb->dp_start_bool, 0);
    rte_atomic16_set(&dhcp_ccb->dhcp_bool, 0);

    // Enable HSI for this user
    if (is_update == FALSE) {
        if (set_vlan_map_ccb_id(fastrg_ccb, vlan_id, ccb_id) == ERROR) {
            FastRG_LOG(ERR, fastrg_ccb->fp, NULL, NULL, "config new VLAN ID %u to user %u failed", vlan_id, ccb_id + 1);
            ret = ERROR;
            goto out;
        }
        if (rte_atomic16_read(&ppp_ccb->ppp_bool) == 1) {
            FastRG_LOG(INFO, fastrg_ccb->fp, NULL, NULL, "PPPoE is already enabled for user %d", ccb_id + 1);
            ret = ERROR;
            goto out;
        }
        ppp_init_config_by_user(fastrg_ccb, ppp_ccb, ccb_id, vlan_id, config->account_name, config->password);
    } else {
        if (rte_atomic16_read(&ppp_ccb->vlan_id) != vlan_id) {
            if (set_vlan_map_ccb_id(fastrg_ccb, vlan_id, ccb_id) == ERROR) {
                FastRG_LOG(ERR, fastrg_ccb->fp, NULL, NULL, "config new VLAN ID %u to user %u failed", vlan_id, ccb_id + 1);
                ret = ERROR;
                goto out;
            }
            /* Remove original vlan map */
            reset_vlan_map_ccb_id(fastrg_ccb, rte_atomic16_read(&ppp_ccb->vlan_id));
        }
        if (ppp_ccb->phase == NOT_CONFIGURED) // means the config exists in etcd but not in local
            ppp_init_config_by_user(fastrg_ccb, ppp_ccb, ccb_id, vlan_id, config->account_name, config->password);
        else
            ppp_update_config_by_user(ppp_ccb, vlan_id, config->account_name, config->password);
    }

    // Apply DHCP configuration
    if (is_update == FALSE) {
        if (rte_atomic16_read(&dhcp_ccb->dhcp_bool) == 1) {
            FastRG_LOG(INFO, fastrg_ccb->fp, NULL, NULL, "DHCP is already enabled for user %d", ccb_id + 1);
            ret = ERROR;
            goto out;
        }
    }

    if (parse_ip_range(config->dhcp_addr_pool, &dhcp_ip_start, &dhcp_ip_end) == ERROR) {
        FastRG_LOG(ERR, fastrg_ccb->fp, NULL, NULL, "Invalid DHCP address pool: %s", config->dhcp_addr_pool);
        ret = ERROR;
        goto out;
    }
    if (parse_ip(config->dhcp_subnet, &dhcp_subnet_mask) == ERROR) {
        FastRG_LOG(ERR, fastrg_ccb->fp, NULL, NULL, "Invalid DHCP subnet mask: %s", config->dhcp_subnet);
        ret = ERROR;
        goto out;
    }
    if (parse_ip(config->dhcp_gateway, &dhcp_gateway) == ERROR) {
        FastRG_LOG(ERR, fastrg_ccb->fp, NULL, NULL, "Invalid DHCP gateway: %s", config->dhcp_gateway);
        ret = ERROR;
        goto out;
    }

    /* On x86, rte_atomic32_inc() ensures the processing order of active_count 
        and dhcp_bool are strong order. Therefore, we don't need barrier here. */
    //rte_smp_mb();

    /* check if there are active DHCP packets being processed */
    U32 spin_count = 0;
    U32 yield_threshold = 1000; // check fast for 1000 times
    uint64_t start_tsc = rte_rdtsc();
    uint64_t timeout_us = 1000000; // 1 second timeout
    while (rte_atomic32_read(&dhcp_ccb->active_count) > 0) {
        if (spin_count < yield_threshold) {
            rte_pause();
            spin_count++;
        } else {
            rte_delay_ms(1);
            uint64_t elapsed_us = (rte_rdtsc() - start_tsc) * 1000000 / rte_get_tsc_hz();
            if (elapsed_us > timeout_us) {
                FastRG_LOG(ERR, fastrg_ccb->fp, NULL, DHCPLOGMSG, 
                    "DHCP: Timeout waiting for active dhcp packets\n");
                ret = ERROR;
                goto out;
            }
        }
    }

    /* No more active DHCP packets, we can update now */
    dhcp_pool_init_by_user(dhcp_ccb, dhcp_gateway, 
        dhcp_ip_start, dhcp_ip_end, dhcp_subnet_mask);

    FastRG_LOG(INFO, fastrg_ccb->fp, NULL, NULL, 
        "Applied HSI config for user %d: DHCP enabled with pool %s", 
        ccb_id + 1, config->dhcp_addr_pool);

    ret = SUCCESS;

out:
    rte_atomic16_set(&ppp_ccb->ppp_bool, ori_ppp_status);
    rte_atomic16_set(&ppp_ccb->dp_start_bool, ori_dp_status);
    rte_atomic16_set(&dhcp_ccb->dhcp_bool, ori_dhcp_status);

    return ret;
}

STATUS remove_hsi_config(FastRG_t *fastrg_ccb, int ccb_id)
{
    if (!is_valid_ccb_id(fastrg_ccb, ccb_id))
        return ERROR;

    ppp_ccb_t *ppp_ccb = PPPD_GET_CCB(fastrg_ccb, ccb_id);
    dhcp_ccb_t *dhcp_ccb = DHCPD_GET_CCB(fastrg_ccb, ccb_id);

    if (rte_atomic16_read(&ppp_ccb->vlan_id) == 0) {
        FastRG_LOG(WARN, fastrg_ccb->fp, NULL, NULL, "User %u is not active", ccb_id + 1);
        return ERROR;
    }

    // Disable HSI and DHCP for this user
    if (rte_atomic16_read(&ppp_ccb->ppp_bool) != 0) {
        FastRG_LOG(WARN, fastrg_ccb->fp, NULL, NULL, "PPPoE is still used for user %d", ccb_id + 1);
        return ERROR;
    }

    if (rte_atomic16_read(&dhcp_ccb->dhcp_bool) != 0) {
        FastRG_LOG(WARN, fastrg_ccb->fp, NULL, NULL, "DHCP is still used for user %d", ccb_id + 1);
        return ERROR;
    }

    reset_vlan_map_ccb_id(fastrg_ccb, rte_atomic16_read(&ppp_ccb->vlan_id));
    // Remove DHCP and PPPoE configuration
    ppp_cleanup_config_by_user(ppp_ccb, ccb_id);
    dhcp_pool_init_by_user(dhcp_ccb, 0, 0, 0, 0); //initialize with empty pool

    FastRG_LOG(INFO, fastrg_ccb->fp, NULL, NULL, "Removed HSI config for user %d", ccb_id + 1);

    return SUCCESS;
}

// Helper function to execute PPPoE dial
STATUS execute_pppoe_dial(FastRG_t *fastrg_ccb, int ccb_id, const pppoe_command_t *command)
{
    if (!is_valid_ccb_id(fastrg_ccb, ccb_id) || !command)
        return ERROR;

    // Set up PPPoE session parameters
    // This would typically involve calling into the PPPoE subsystem
    // For now, just log the action
    FastRG_LOG(INFO, fastrg_ccb->fp, NULL, NULL, 
        "Executing PPPoE dial for user %d: VLAN %s, Account %s", 
        ccb_id + 1, command->vlan, command->account);

    ppp_ccb_t *ppp_ccb = PPPD_GET_CCB(fastrg_ccb, ccb_id);
    dhcp_ccb_t *dhcp_ccb = DHCPD_GET_CCB(fastrg_ccb, ccb_id);

    if (rte_atomic16_read(&ppp_ccb->ppp_bool) == 1)
        FastRG_LOG(INFO, fastrg_ccb->fp, NULL, NULL, "HSI is already enabled for user %d", ccb_id + 1);

    if (rte_atomic16_read(&dhcp_ccb->dhcp_bool) == 1)
        FastRG_LOG(INFO, fastrg_ccb->fp, NULL, NULL, "DHCP is already enabled for user %d", ccb_id + 1);

    if (fastrg_gen_northbound_event(EV_NORTHBOUND_PPPoE, PPPoE_CMD_ENABLE, ccb_id) == ERROR) {
        FastRG_LOG(ERR, fastrg_ccb->fp, NULL, NULL, "Failed to generate PPPoE enable event for user %d", ccb_id + 1);
        return ERROR;
    }

    if (fastrg_gen_northbound_event(EV_NORTHBOUND_DHCP, DHCP_CMD_ENABLE, ccb_id) == ERROR) {
        FastRG_LOG(ERR, fastrg_ccb->fp, NULL, NULL, "Failed to generate DHCP enable event for user %d", ccb_id + 1);
        if (fastrg_gen_northbound_event(EV_NORTHBOUND_PPPoE, PPPoE_CMD_DISABLE, ccb_id) == ERROR) {
            FastRG_LOG(ERR, fastrg_ccb->fp, NULL, NULL, "Failed to generate PPPoE disable event for user %d", ccb_id + 1);
            return ERROR;
        }
        return ERROR;
    }

    FastRG_LOG(INFO, fastrg_ccb->fp, NULL, NULL, 
        "Applied HSI config for user %d", 
        ccb_id + 1);

    return SUCCESS;
}

// Helper function to execute PPPoE hangup
STATUS execute_pppoe_hangup(FastRG_t *fastrg_ccb, int ccb_id)
{
    if (!is_valid_ccb_id(fastrg_ccb, ccb_id))
        return ERROR;

    FastRG_LOG(INFO, fastrg_ccb->fp, NULL, NULL, 
            "Executing PPPoE hangup for user %d", ccb_id + 1);

    ppp_ccb_t *ppp_ccb = PPPD_GET_CCB(fastrg_ccb, ccb_id);
    dhcp_ccb_t *dhcp_ccb = DHCPD_GET_CCB(fastrg_ccb, ccb_id);

    if (rte_atomic16_read(&ppp_ccb->ppp_bool) == 0)
        FastRG_LOG(WARN, fastrg_ccb->fp, NULL, NULL, "HSI is already disabled for user %d", ccb_id + 1);
    if (rte_atomic16_read(&dhcp_ccb->dhcp_bool) == 0)
        FastRG_LOG(WARN, fastrg_ccb->fp, NULL, NULL, "DHCP is already disabled for user %d", ccb_id + 1);

    if (fastrg_gen_northbound_event(EV_NORTHBOUND_PPPoE, PPPoE_CMD_DISABLE, ccb_id) == ERROR) {
        FastRG_LOG(ERR, fastrg_ccb->fp, NULL, NULL, "Failed to generate PPPoE disable event for user %d", ccb_id + 1);
        return ERROR;
    }

    if (fastrg_gen_northbound_event(EV_NORTHBOUND_DHCP, DHCP_CMD_DISABLE, ccb_id) == ERROR) {
        FastRG_LOG(ERR, fastrg_ccb->fp, NULL, NULL, "Failed to generate DHCP disable event for user %d", ccb_id + 1);
        return ERROR;
    }

    return SUCCESS;
}
