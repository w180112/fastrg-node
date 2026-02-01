#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_ip.h>
#include <rte_icmp.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_timer.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <rte_memcpy.h>
#include <rte_atomic.h>
#include <rte_ip_frag.h>

#include "fastrg.h"
#include "protocol.h"
#include "pppd/nat.h"
#include "init.h"
#include "dp_codec.h"
#include "dhcpd/dhcpd.h"
#include "dbg.h"
#include "dp.h"
#include "trace.h"
#include "utils.h"

#define RX_RING_SIZE 128

#define TX_RING_SIZE 512

#define BURST_SIZE 32

#define	IPV4_MTU_DEFAULT	RTE_ETHER_MTU
#define	IPV6_MTU_DEFAULT	RTE_ETHER_MTU

extern struct rte_mempool 		*direct_pool[PORT_AMOUNT], *indirect_pool[PORT_AMOUNT];
extern struct rte_ring 			*cp_q, *free_mail_ring;
extern struct rte_ring 			*gateway_q, *uplink_q, *downlink_q;
static U16 						nb_rxd = RX_RING_SIZE;
static U16 						nb_txd = TX_RING_SIZE;

static struct rte_eth_conf port_conf_default = {
    /* https://github.com/DPDK/dpdk/commit/1bb4a528c41f4af4847bd3d58cc2b2b9f1ec9a27#diff-71b61db11e3ee1ca6bb272a90e3c1aa0e8c90071b1a38387fd541687314b1843
     * From this commit, mtu field is only for jumbo frame
     **/
    //.rxmode = { .mtu = RTE_ETHER_MAX_JUMBO_FRAME_LEN - RTE_ETHER_HDR_LEN - RTE_ETHER_CRC_LEN, }, 
    .txmode = { .offloads = RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | 
                            RTE_ETH_TX_OFFLOAD_UDP_CKSUM | 
                            /*RTE_ETH_TX_OFFLOAD_MT_LOCKFREE |*/
                            RTE_ETH_TX_OFFLOAD_TCP_CKSUM, },
    .intr_conf = {
        .lsc = 1, /**< link status interrupt feature enabled */ },
};
static int lsi_event_callback(U16 port_id, enum rte_eth_event_type type, void *param);

STATUS PORT_INIT(FastRG_t *fastrg_ccb, U16 port)
{
    struct rte_eth_conf port_conf = port_conf_default;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_rxconf rxq_conf;
    struct rte_eth_txconf *txconf;
    const U16 rx_rings = 1, tx_rings = 4;
    int retval;
    U16 q;

    if (fastrg_ccb->nic_info.vendor_id > NIC_VENDOR_VMXNET3)
        port_conf.intr_conf.lsc = 0;
    if (!rte_eth_dev_is_valid_port(port)) {
        FastRG_LOG(ERR, fastrg_ccb->fp, NULL, NULL, "Invalid port: %u", port);
        return ERROR;
    }
    int ret = rte_eth_dev_info_get(port, &dev_info);
    if (ret != 0) {
        FastRG_LOG(ERR, fastrg_ccb->fp, NULL, NULL, "Error during getting device (port %u) info: %s\n", port, strerror(-ret));
        return ERROR;
    }
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0) {
        FastRG_LOG(ERR, fastrg_ccb->fp, NULL, NULL, "Cannot configure port %d: %s", port, rte_strerror(rte_errno));
        return ERROR;
    }
    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd,&nb_txd);
    if (retval < 0) {
        FastRG_LOG(ERR, fastrg_ccb->fp, NULL, NULL, "Cannot adjust number of descriptors: err=%s, port=%u\n", strerror(-retval), port);
        return ERROR;
    }

    retval = rte_eth_dev_callback_register(port, RTE_ETH_EVENT_INTR_LSC, (rte_eth_dev_cb_fn)lsi_event_callback, fastrg_ccb);
    if (retval < 0) {
        FastRG_LOG(ERR, fastrg_ccb->fp, NULL, NULL, "Cannot register lsc callback: err=%s, port=%u\n", strerror(-retval), port);
        return ERROR;
    }

    rxq_conf = dev_info.default_rxconf;
    rxq_conf.offloads = port_conf.rxmode.offloads;
    /* Allocate and set up 1 RX queue per Ethernet port. */
    for(q=0; q<rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd, rte_eth_dev_socket_id(port), &rxq_conf, direct_pool[port]);
        if (retval < 0) {
            FastRG_LOG(ERR, fastrg_ccb->fp, NULL, NULL, "Cannot setup RX queue: err=%s, port=%u\n", strerror(-retval), port);
            goto err_unregister_callback;
        }
    }

    txconf = &dev_info.default_txconf;
    txconf->offloads = port_conf.txmode.offloads;
    /* Allocate and set up 4 TX queue per Ethernet port. */
    for(q=0; q<tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd, rte_eth_dev_socket_id(port), txconf);
        if (retval < 0) {
            FastRG_LOG(ERR, fastrg_ccb->fp, NULL, NULL, "Cannot setup TX queue: err=%s, port=%u\n", strerror(-retval), port);
            goto err_unregister_callback;
        }
    }

    /* Start the Ethernet port. */
    retval = rte_eth_dev_start(port);
    if (retval < 0) {
        FastRG_LOG(ERR, fastrg_ccb->fp, NULL, NULL, "Cannot start port %d: %s", port, strerror(-retval));
        goto err_unregister_callback;
    }

    retval = rte_eth_promiscuous_enable(port);
    if (retval < 0) {
        FastRG_LOG(ERR, fastrg_ccb->fp, NULL, NULL, "Cannot enable promiscuous mode for port %u: %s", port, strerror(-retval));
        goto err_dev_stop;
    }

    return SUCCESS;

err_dev_stop:
    rte_eth_dev_stop(port);

err_unregister_callback:
    rte_eth_dev_callback_unregister(port, RTE_ETH_EVENT_INTR_LSC, 
        (rte_eth_dev_cb_fn)lsi_event_callback, fastrg_ccb);
    return ERROR;
}

static inline STATUS parse_l2_hdr(FastRG_t *fastrg_ccb, struct rte_mbuf *single_pkt, 
    U8 port_id)
{
    mbuf_priv_t *mbuf_priv = rte_mbuf_to_priv(single_pkt);
    struct rte_ether_hdr *eth_hdr;
    vlan_header_t *vlan_header;
    U16 ccb_id;
    U16 vlan_id;
    struct per_ccb_stats *stats;

    eth_hdr = rte_pktmbuf_mtod(single_pkt, struct rte_ether_hdr *);
    mbuf_priv->eth_hdr = eth_hdr;
    if (unlikely(eth_hdr->ether_type != rte_cpu_to_be_16(VLAN))) {
        stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, port_id, fastrg_ccb->user_count);
        if (likely(stats)) increase_ccb_drop_count(stats, single_pkt->pkt_len);
        return ERROR;
    }
    vlan_header = (vlan_header_t *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr));
    mbuf_priv->vlan_hdr = vlan_header;

    vlan_id = rte_be_to_cpu_16(vlan_header->tci_union.tci_value) & 0xFFF;
    if (unlikely(vlan_id < MIN_VLAN_ID || vlan_id > MAX_VLAN_ID)) {
        stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, port_id, fastrg_ccb->user_count);
        if (likely(stats)) increase_ccb_drop_count(stats, single_pkt->pkt_len);
        return ERROR;
    }

    ccb_id = rte_atomic16_read(&fastrg_ccb->vlan_userid_map[vlan_id - 1]);
    if (unlikely(ccb_id > fastrg_ccb->user_count - 1)) {
        stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, port_id, fastrg_ccb->user_count);
        if (likely(stats)) increase_ccb_drop_count(stats, single_pkt->pkt_len);
        return ERROR;
    }

    dhcp_ccb_t *dhcp_ccb = DHCPD_GET_CCB(fastrg_ccb, ccb_id);

    mbuf_priv->ccb_id = ccb_id;
    mbuf_priv->dhcp_server_ip = dhcp_ccb->dhcp_server_ip;
    mbuf_priv->dhcp_subnet_mask = dhcp_ccb->subnet_mask;

    return SUCCESS;
}

#define VOD_IP_PREFIX_HOST 10  // 10.0.0.0/24 in host order
#define VOD_IP_MASK 0x000000FF
static inline BOOL is_iptv_pkt_need_drop(FastRG_t *fastrg_ccb, vlan_header_t *vlan_hdr)
{
    /* We need to detect IGMP and multicast msg here */
    if (vlan_hdr->next_proto == rte_cpu_to_be_16(FRAME_TYPE_IP)) {
        struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(vlan_hdr + 1);
        if (ip_hdr->next_proto_id == PROTO_TYPE_UDP) { // use 4001 vlan tag to detect IPTV and VOD packet
            U16 vlan_id = rte_be_to_cpu_16(vlan_hdr->tci_union.tci_value) & 0xFFF;
            struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
            // VOD pkt dst ip is always 10.x.x.x, we compare it in network order
            if (likely(vlan_id == MULTICAST_TAG || 
                    ((ip_hdr->dst_addr) & VOD_IP_MASK) == VOD_IP_PREFIX_HOST)) {
                return FALSE;
            } else if (ip_hdr->total_length > rte_cpu_to_be_16(
                    sizeof(struct rte_udp_hdr) + sizeof(struct rte_ipv4_hdr)) && 
                    udp_hdr->dst_port == rte_be_to_cpu_16(DHCP_CLIENT_PORT)) {
                return FALSE;
            } else {
                return TRUE;
            }
        }
        if (ip_hdr->next_proto_id == IPPROTO_IGMP)
            return FALSE;
    }
    return TRUE;
}

static inline void send2cp(FastRG_t *fastrg_ccb, struct rte_mbuf *single_pkt)
{
    /* Try to get a free mail slot from free_mail_ring */
    tFastRG_MBX *slot = NULL;
    U16 ccb_id = ((mbuf_priv_t *)rte_mbuf_to_priv(single_pkt))->ccb_id;

    /* Get a free mail slot */
    if (rte_ring_dequeue(free_mail_ring, (void **)&slot) == 0) {
        /* Deep copy packet data to slot's refp buffer to avoid data buffer being overwritten by rx_burst */
        U16 copy_len = RTE_MIN(single_pkt->pkt_len, sizeof(slot->refp));
        rte_memcpy(slot->refp, rte_pktmbuf_mtod(single_pkt, void *), copy_len);
        slot->type = EV_DP;
        slot->len = copy_len;
        /* cp_q is full: return slot to free_mail_ring */
        if (rte_ring_enqueue(cp_q, slot) != 0) {
            rte_ring_enqueue(free_mail_ring, slot);
            struct per_ccb_stats *stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, WAN_PORT, ccb_id);
            if (likely(stats)) increase_ccb_drop_count(stats, single_pkt->pkt_len);
        } else {
            struct per_ccb_stats *stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, WAN_PORT, ccb_id);
            if (likely(stats)) increase_ccb_rx_count(stats, single_pkt->pkt_len);
        }
    } else {
        struct per_ccb_stats *stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, WAN_PORT, ccb_id);
        if (likely(stats)) increase_ccb_drop_count(stats, single_pkt->pkt_len);
    }
    rte_pktmbuf_free(single_pkt);
}

int wan_recvd(void *arg)
{
    struct rte_mbuf      *single_pkt;
    uint64_t             total_tx = 0;
    struct rte_ether_hdr *eth_hdr, tmp_eth_hdr;
    vlan_header_t        *vlan_header, tmp_vlan_header;
    struct rte_ipv4_hdr  *ip_hdr;
    struct rte_icmp_hdr  *icmphdr;
    struct rte_mbuf      *pkt[BURST_SIZE];
    U16                  nb_rx;
    ppp_payload_t        *ppp_payload;
    U16                  ccb_id;
    U16                  pppoe_len = sizeof(pppoe_header_t) + sizeof(ppp_payload_t);
    FastRG_t             *fastrg_ccb = (FastRG_t *)arg;

    rte_thread_t thread_id = rte_thread_self();
    rte_thread_set_name(thread_id, "fastrg_wan_recvd");

    while(rte_atomic16_read(&start_flag) == 0)
        rte_pause();

    while(likely(rte_atomic16_read(&stop_flag) == 0)) {
        nb_rx = rte_eth_rx_burst(WAN_PORT, gen_port_q, pkt, BURST_SIZE);
        for(int i=0; i<nb_rx; i++) {
            single_pkt = pkt[i];
            rte_prefetch0(rte_pktmbuf_mtod(single_pkt, void *));
            // TODO: enable tracing point
            //rte_ethdev_trace_rx_pkt(rte_pktmbuf_mtod(single_pkt, void *));
            if (unlikely(parse_l2_hdr(fastrg_ccb, single_pkt, 1) == ERROR)) {
                rte_pktmbuf_free(single_pkt);
                continue;
            }
            mbuf_priv_t *mbuf_priv = rte_mbuf_to_priv(single_pkt);
            vlan_header = mbuf_priv->vlan_hdr;
            eth_hdr = mbuf_priv->eth_hdr;
            ccb_id = mbuf_priv->ccb_id;

            /* Usually if a packet is not a PPPoE packet, it should be an IPTV packet. */
            if (unlikely(vlan_header->next_proto != rte_cpu_to_be_16(ETH_P_PPP_SES) && 
                    vlan_header->next_proto != rte_cpu_to_be_16(ETH_P_PPP_DIS))) {
                if (is_iptv_pkt_need_drop(fastrg_ccb, vlan_header) == TRUE) {
                    { 
                        struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, WAN_PORT, ccb_id); 
                        if (likely(__stats)) increase_ccb_drop_count(__stats, single_pkt->pkt_len); 
                    };
                    rte_pktmbuf_free(single_pkt);
                } else {
                    { 
                        struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, WAN_PORT, ccb_id); 
                        if (likely(__stats)) increase_ccb_rx_count(__stats, single_pkt->pkt_len); 
                    };
                    pkt[total_tx++] = single_pkt;
                    { 
                        struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, LAN_PORT, ccb_id); 
                        if (likely(__stats)) increase_ccb_tx_count(__stats, single_pkt->pkt_len); 
                    };
                }
                continue;
            }

            ppp_ccb_t *ppp_ccb = PPPD_GET_CCB(fastrg_ccb, ccb_id);
            ppp_payload = ((ppp_payload_t *)((char *)eth_hdr + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(pppoe_header_t)));
            if (unlikely(vlan_header->next_proto == rte_cpu_to_be_16(ETH_P_PPP_DIS) || 
                    (ppp_payload->ppp_protocol == rte_cpu_to_be_16(LCP_PROTOCOL) || 
                    ppp_payload->ppp_protocol == rte_cpu_to_be_16(PAP_PROTOCOL) || 
                    ppp_payload->ppp_protocol == rte_cpu_to_be_16(IPCP_PROTOCOL)))) {
                /* Check whether ppp_bool is enabled */
                if (unlikely(rte_atomic16_read(&ppp_ccb->ppp_bool) == 0)) {
                    { 
                        struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, WAN_PORT, ccb_id); 
                        if (likely(__stats)) increase_ccb_drop_count(__stats, single_pkt->pkt_len); 
                    };
                    rte_pktmbuf_free(single_pkt);
                    continue;
                }
                send2cp(fastrg_ccb, single_pkt);
                continue;
            }

            if (unlikely(rte_atomic16_read(&ppp_ccb->dp_start_bool) == (BIT16)0)) {
                { 
                    struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, WAN_PORT, ccb_id); 
                    if (likely(__stats)) increase_ccb_drop_count(__stats, single_pkt->pkt_len);
                };
                rte_pktmbuf_free(single_pkt);
                continue;
            }

            vlan_header->next_proto = rte_cpu_to_be_16(FRAME_TYPE_IP);
            rte_memcpy(&tmp_eth_hdr, eth_hdr, sizeof(struct rte_ether_hdr));
            rte_memcpy(&tmp_vlan_header, vlan_header, sizeof(vlan_header_t));
            rte_memcpy((char *)eth_hdr+pppoe_len, &tmp_eth_hdr, sizeof(struct rte_ether_hdr));
            rte_memcpy((char *)vlan_header+pppoe_len, &tmp_vlan_header, sizeof(vlan_header_t));
            single_pkt->data_off += pppoe_len;
            single_pkt->pkt_len -= pppoe_len;
            single_pkt->data_len -= pppoe_len;
            eth_hdr = (struct rte_ether_hdr *)((char *)eth_hdr + pppoe_len);
            vlan_header = (vlan_header_t *)(eth_hdr + 1);
            mbuf_priv->vlan_hdr = vlan_header;
            mbuf_priv->eth_hdr = eth_hdr;

            ip_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(single_pkt, 
                unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t));
            single_pkt->l2_len = sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t);
            single_pkt->l3_len = sizeof(struct rte_ipv4_hdr);
            switch(ip_hdr->next_proto_id) {
                case PROTO_TYPE_ICMP:
                    icmphdr = (struct rte_icmp_hdr *)(rte_pktmbuf_mtod(single_pkt, 
                        unsigned char *) + sizeof(struct rte_ether_hdr) + 
                        sizeof(vlan_header_t) + sizeof(struct rte_ipv4_hdr));
                    if (icmphdr->icmp_type != ICMP_ECHO_REPLY) {
                        { 
                            struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, WAN_PORT, ccb_id); 
                            if (likely(__stats)) increase_ccb_drop_count(__stats, single_pkt->pkt_len);
                        };
                        rte_pktmbuf_free(single_pkt);
                        continue;
                    }
                    //single_pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM;
                    addr_table_t *entry = nat_reverse_lookup(icmphdr->icmp_ident, 
                        ip_hdr->src_addr, ICMP_ECHO_REQUEST, ppp_ccb->addr_table);
                    if (entry == NULL) {
                        { 
                            struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, WAN_PORT, ccb_id); 
                            if (likely(__stats)) increase_ccb_drop_count(__stats, single_pkt->pkt_len);
                        };
                        rte_pktmbuf_free(single_pkt);
                        continue;
                    }
                    int32_t icmp_cksum_diff = (int32_t)icmphdr->icmp_ident - (int32_t)entry->src_port;
                    U32 icmp_new_cksum;

                    rte_ether_addr_copy(&fastrg_ccb->nic_info.hsi_lan_mac, 
                        &eth_hdr->src_addr);
                    rte_ether_addr_copy(&entry->mac_addr, &eth_hdr->dst_addr);
                    ip_hdr->dst_addr = entry->src_ip;
                    icmphdr->icmp_ident = entry->src_port;

                    if (((icmp_new_cksum = (U32)icmp_cksum_diff + (U32)icmphdr->icmp_cksum) >> 16) != 0)
                        icmp_new_cksum = (icmp_new_cksum & 0xFFFF) + (icmp_new_cksum >> 16);
                    icmphdr->icmp_cksum = (U16)icmp_new_cksum;
                    ip_hdr->hdr_checksum = 0;
                    ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
                    pkt[total_tx++] = single_pkt;
                    { 
                        struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, LAN_PORT, ccb_id); 
                        if (likely(__stats)) increase_ccb_tx_count(__stats, single_pkt->pkt_len);
                    };
                    { 
                        struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, WAN_PORT, ccb_id); 
                        if (likely(__stats)) increase_ccb_rx_count(__stats, single_pkt->pkt_len);
                    };
                    increase_pppoes_rx_count(ppp_ccb, single_pkt->pkt_len);
                    break;
                case PROTO_TYPE_UDP:
                case PROTO_TYPE_TCP:
                    fastrg_ring_enqueue(downlink_q, (void **)&single_pkt, 1);
                    break;
                default:
                    { 
                        struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, WAN_PORT, ccb_id); 
                        if (likely(__stats)) increase_ccb_drop_count(__stats, single_pkt->pkt_len);
                    };
                    rte_pktmbuf_free(single_pkt);
                    break;
            }
        }
        if (likely(total_tx > 0)) {
            U16 nb_tx = rte_eth_tx_burst(LAN_PORT, gen_port_q, pkt, total_tx);
            if (unlikely(nb_tx < total_tx)) {
                for(U16 buf=nb_tx; buf<total_tx; buf++)
                    rte_pktmbuf_free(pkt[buf]);
            }
            total_tx = 0;
        }
    }
    return 0;
}

#if 0
int ds_mc(void)
{
    struct rte_mbuf 	*pkt[BURST_SIZE], *single_pkt;
    uint64_t 			total_tx;
    U16			burst_size;
    struct rte_ipv4_hdr *ip_hdr;
    vlan_header_t		*vlan_header;
    int 				i;

    for(i=0; i<BURST_SIZE; i++)
        pkt[i] = rte_pktmbuf_alloc(mbuf_pool);

    for(;;) {
        burst_size = rte_ring_dequeue_burst(ds_mc_queue,(void **)pkt,BURST_SIZE,NULL);
        if (unlikely(burst_size == 0))
            continue;
        total_tx = 0;
        for(i=0; i<burst_size; i++) {
            single_pkt = pkt[i];
            rte_prefetch0(rte_pktmbuf_mtod(single_pkt, void *));
            /* Need to check whether the packet is multicast or VOD */
            vlan_header = (vlan_header_t *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr));
            U16 vlan_id = rte_be_to_cpu_16(vlan_header->tci_union.tci_value) & 0xFFF;
            ip_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t));
            if (likely(vlan_id == MULTICAST_TAG || ((ip_hdr->dst_addr) & 0xFFFFFF00) == 10)) // VOD pkt dst ip is always 10.x.x.x
                pkt[total_tx++] = single_pkt;
            //else
                //rte_pktmbuf_free(single_pkt);
        }
        if (likely(total_tx > 0)) {
            U16 nb_tx = rte_eth_tx_burst(LAN_PORT, mc_port_q, pkt, total_tx);
            if (unlikely(nb_tx < total_tx)) {
                for(U16 buf=nb_tx; buf<total_tx; buf++)
                    rte_pktmbuf_free(pkt[buf]);
            }
        }
    }
    return 0;
}
#endif

int downlink(void *arg)
{
    uint64_t 			total_tx;
    struct rte_ether_hdr *eth_hdr;
    vlan_header_t		*vlan_header;
    struct rte_ipv4_hdr *ip_hdr;
    U16 				burst_size, ccb_id;
    struct rte_mbuf 	*pkt[BURST_SIZE], *single_pkt;
    int 				pkt_num;
    FastRG_t            *fastrg_ccb = (FastRG_t *)arg;

    rte_thread_t thread_id = rte_thread_self();
    rte_thread_set_name(thread_id, "fastrg_downlink");

    while(likely(rte_atomic16_read(&stop_flag) == 0)) {
        burst_size = rte_ring_dequeue_burst(downlink_q, (void **)pkt, BURST_SIZE, NULL);
        if (unlikely(burst_size == 0))
            continue;
        total_tx = 0;
        for(int i=0; i<burst_size; i++) {
            single_pkt = pkt[i];
            rte_prefetch0(rte_pktmbuf_mtod(single_pkt, void *));
            mbuf_priv_t *mbuf_priv = rte_mbuf_to_priv(single_pkt);
            vlan_header = mbuf_priv->vlan_hdr;
            eth_hdr = mbuf_priv->eth_hdr;
            ccb_id = mbuf_priv->ccb_id;
            /* for NAT mapping */
            ip_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(single_pkt, 
                unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t));
            ip_hdr->hdr_checksum = 0;
            if (ip_hdr->next_proto_id == PROTO_TYPE_UDP) {
                pkt_num = decaps_udp(fastrg_ccb, single_pkt, eth_hdr, 
                    vlan_header, ip_hdr, ccb_id);
            } else if (ip_hdr->next_proto_id == PROTO_TYPE_TCP) {
                pkt_num = decaps_tcp(fastrg_ccb, single_pkt, eth_hdr, 
                    vlan_header, ip_hdr, ccb_id);
            } else {
                { 
                    struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, WAN_PORT, ccb_id); 
                    if (likely(__stats)) increase_ccb_drop_count(__stats, single_pkt->pkt_len);
                };
                rte_pktmbuf_free(single_pkt);
                continue;
            }
            for(int j=0; j<pkt_num; j++) {
                pkt[total_tx++] = single_pkt;
                single_pkt = single_pkt->next;
            }
        }
        if (likely(total_tx > 0))
            rte_eth_tx_burst(LAN_PORT, down_port_q, pkt, total_tx);
    }
    return 0;
}

int uplink(void *arg)
{
    struct rte_mbuf 	*pkt[BURST_SIZE], *single_pkt;
    uint64_t 			total_tx;
    U16					burst_size;
    struct rte_ether_hdr *eth_hdr;
    U16					ccb_id;
    vlan_header_t		*vlan_header;
    struct rte_ipv4_hdr *ip_hdr;
    int 				pkt_num;
    FastRG_t            *fastrg_ccb = (FastRG_t *)arg;

    rte_thread_t thread_id = rte_thread_self();
    rte_thread_set_name(thread_id, "fastrg_uplink");

    while(likely(rte_atomic16_read(&stop_flag) == 0)) {
        burst_size = rte_ring_dequeue_burst(uplink_q, (void **)pkt, BURST_SIZE, NULL);
        if (unlikely(burst_size == 0))
            continue;
        total_tx = 0;
        for(int i=0; i<burst_size; i++) {
            single_pkt = pkt[i];
            rte_prefetch0(rte_pktmbuf_mtod(single_pkt, void *));
            mbuf_priv_t *mbuf_priv = rte_mbuf_to_priv(single_pkt);
            vlan_header = mbuf_priv->vlan_hdr;
            eth_hdr = mbuf_priv->eth_hdr;
            ccb_id = mbuf_priv->ccb_id;
            ip_hdr = (struct rte_ipv4_hdr *)rte_pktmbuf_adj(single_pkt, 
                (U16)(sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t)));
            if (ip_hdr->next_proto_id == PROTO_TYPE_UDP) {
                pkt_num = encaps_udp(fastrg_ccb, &single_pkt, eth_hdr, 
                    vlan_header, ip_hdr, ccb_id);
            } else if (ip_hdr->next_proto_id == PROTO_TYPE_TCP) {
                pkt_num = encaps_tcp(fastrg_ccb, &single_pkt, eth_hdr, 
                    vlan_header, ip_hdr, ccb_id);
            } else {
                rte_pktmbuf_free(single_pkt);
                { 
                    struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, LAN_PORT, ccb_id);
                    if (likely(__stats)) increase_ccb_drop_count(__stats, single_pkt->pkt_len);
                };
                continue;
            }
            for(int j=0; j<pkt_num; j++) {
                pkt[total_tx++] = single_pkt;
                single_pkt = single_pkt->next;
            }
        }
        if (likely(total_tx > 0)) {
            uint16_t nb_tx = rte_eth_tx_burst(WAN_PORT, up_port_q, pkt, total_tx);
            if (unlikely(nb_tx < total_tx)) {
                for(U16 buf=nb_tx; buf<total_tx; buf++)
                    rte_pktmbuf_free(pkt[buf]);
            }
        }
    }
    return 0;
}

#if 0
int us_mc(void)
{
    struct rte_mbuf 	*pkt[BURST_SIZE], *single_pkt;
    uint64_t 			total_tx;
    U16			burst_size;
    int 				i;

    for(i=0; i<BURST_SIZE; i++)
        pkt[i] = rte_pktmbuf_alloc(mbuf_pool);

    for(;;) {
        burst_size = rte_ring_dequeue_burst(us_mc_queue,(void **)pkt,BURST_SIZE,NULL);
        if (unlikely(burst_size == 0))
            continue;
        total_tx = 0;
        for(i=0; i<burst_size; i++) {
            single_pkt = pkt[i];
            /* Need to check whether the packet is multicast */
            pkt[total_tx++] = single_pkt;
        }
        if (likely(total_tx > 0))
            rte_eth_tx_burst(WAN_PORT, mc_port_q, pkt, total_tx);
    }
    return 0;
}
#endif

int lan_recvd(void *arg)
{
    struct rte_mbuf 	*single_pkt;
    uint64_t 			total_tx = 0;
    struct rte_ether_hdr *eth_hdr;
    vlan_header_t		*vlan_header;
    struct rte_ipv4_hdr *ip_hdr;
    struct rte_icmp_hdr *icmphdr;
    struct rte_mbuf 	*pkt[BURST_SIZE];
    char 				*cur;
    pppoe_header_t 		*pppoe_header;
    U16 				nb_tx, nb_rx, ccb_id;
    U16                 pppoe_len = sizeof(pppoe_header_t) + sizeof(ppp_payload_t);
    FastRG_t            *fastrg_ccb = (FastRG_t *)arg;

    rte_thread_t thread_id = rte_thread_self();
    rte_thread_set_name(thread_id, "fastrg_lan_recvd");

    while(rte_atomic16_read(&start_flag) == 0)
        rte_pause();

    while(likely(rte_atomic16_read(&stop_flag) == 0)) {
        nb_rx = rte_eth_rx_burst(LAN_PORT, gen_port_q, pkt, BURST_SIZE);
        for(int i=0; i<nb_rx; i++) {
            single_pkt = pkt[i];
            rte_prefetch0(rte_pktmbuf_mtod(single_pkt, void *));
            if (unlikely(parse_l2_hdr(fastrg_ccb, single_pkt, 0) == ERROR)) {
                rte_pktmbuf_free(single_pkt);
                continue;
            }
            mbuf_priv_t *mbuf_priv = rte_mbuf_to_priv(single_pkt);
            vlan_header = mbuf_priv->vlan_hdr;
            eth_hdr = mbuf_priv->eth_hdr;
            ccb_id = mbuf_priv->ccb_id;

            if (unlikely(vlan_header->next_proto == rte_cpu_to_be_16(FRAME_TYPE_ARP))) { 
                /* We only reply arp request to us */
                fastrg_ring_enqueue(gateway_q, (void **)&single_pkt, 1);
                continue;
            } else if (unlikely(vlan_header->next_proto == rte_cpu_to_be_16(ETH_P_PPP_DIS) || 
                    (vlan_header->next_proto == rte_cpu_to_be_16(ETH_P_PPP_SES)))) {
                #ifdef TEST_MODE
                {
                    struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, LAN_PORT, ccb_id);
                    if (likely(__stats)) increase_ccb_drop_count(__stats, single_pkt->pkt_len);
                };
                rte_pktmbuf_free(single_pkt);
                continue;
                #else
                { 
                    struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, LAN_PORT, ccb_id); 
                    if (likely(__stats)) increase_ccb_rx_count(__stats, single_pkt->pkt_len);
                };
                { 
                    struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, WAN_PORT, ccb_id); 
                    if (likely(__stats)) increase_ccb_tx_count(__stats, single_pkt->pkt_len);
                };
                pkt[total_tx++] = single_pkt;
                #endif
            } else if (likely(vlan_header->next_proto == rte_cpu_to_be_16(FRAME_TYPE_IP))) {
                ip_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + 
                    sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t));
                /* This means it is sent to another instance in the same LAN */
                U32 dhcp_server_ip = mbuf_priv->dhcp_server_ip;;
                U32 subnet_mask = mbuf_priv->dhcp_subnet_mask;
                if (unlikely(is_ip_in_range(ip_hdr->dst_addr, 
                        dhcp_server_ip, subnet_mask))) {
                    fastrg_ring_enqueue(gateway_q, (void **)&single_pkt, 1);
                    continue;
                }
                single_pkt->l2_len = sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(pppoe_header_t) + sizeof(ppp_payload_t);
                single_pkt->l3_len = sizeof(struct rte_ipv4_hdr);

                ppp_ccb_t *ppp_ccb = PPPD_GET_CCB(fastrg_ccb, ccb_id);
                if (ip_hdr->next_proto_id == PROTO_TYPE_ICMP) {
                    if (unlikely(!rte_is_same_ether_addr(&eth_hdr->dst_addr, &fastrg_ccb->nic_info.hsi_lan_mac))) {
                        { 
                            struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, LAN_PORT, ccb_id);
                            if (likely(__stats)) increase_ccb_rx_count(__stats, single_pkt->pkt_len);
                        };
                        { 
                            struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, WAN_PORT, ccb_id);
                            if (likely(__stats)) increase_ccb_tx_count(__stats, single_pkt->pkt_len);
                        };
                        pkt[total_tx++] = single_pkt;
                        continue;
                    }
                    //single_pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM;
                    icmphdr = (struct rte_icmp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(struct rte_ipv4_hdr));
                    if (unlikely(rte_atomic16_read(&ppp_ccb->dp_start_bool) == (BIT16)0)) {
                        {
                            struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, LAN_PORT, ccb_id);
                            if (likely(__stats)) increase_ccb_drop_count(__stats, single_pkt->pkt_len);
                        };
                        rte_pktmbuf_free(single_pkt);
                        continue;
                    }
                    U16 new_port_id;
                    U32 icmp_new_cksum;
                    U16 ori_ident = icmphdr->icmp_ident;

                    new_port_id = nat_icmp_learning(eth_hdr, ip_hdr, icmphdr, 
                        ppp_ccb->addr_table);
                    if (unlikely(new_port_id == 0)) {
                        struct per_ccb_stats *stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, LAN_PORT, ccb_id);
                        if (likely(stats)) increase_ccb_drop_count(stats, single_pkt->pkt_len);
                        rte_pktmbuf_free(single_pkt);
                        continue;
                    }
                    ip_hdr->src_addr = ppp_ccb->hsi_ipv4;
                    icmphdr->icmp_ident = new_port_id;
                    ip_hdr->hdr_checksum = 0;
                    ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);

                    if (((icmp_new_cksum = icmphdr->icmp_cksum + ori_ident - new_port_id) >> 16) != 0)
                        icmp_new_cksum = (icmp_new_cksum & 0xFFFF) + (icmp_new_cksum >> 16);
                    icmphdr->icmp_cksum = (U16)icmp_new_cksum;

                    rte_ether_addr_copy(&fastrg_ccb->nic_info.hsi_wan_src_mac, &eth_hdr->src_addr);
                    rte_ether_addr_copy(&ppp_ccb->PPP_dst_mac, &eth_hdr->dst_addr);

                    vlan_header->next_proto = rte_cpu_to_be_16(ETH_P_PPP_SES);
                    cur = (char *)eth_hdr - pppoe_len;
                    rte_memcpy(cur, eth_hdr, sizeof(struct rte_ether_hdr));
                    rte_memcpy(cur+sizeof(struct rte_ether_hdr), vlan_header, sizeof(vlan_header_t));
                    pppoe_header = (pppoe_header_t *)(cur + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t));
                    pppoe_header->ver_type = VER_TYPE;
                    pppoe_header->code = 0;
                    pppoe_header->session_id = ppp_ccb->session_id;
                    pppoe_header->length = rte_cpu_to_be_16((single_pkt->pkt_len) - 
                        (sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t)) + sizeof(ppp_payload_t));
                    *((U16 *)(cur + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + 
                        sizeof(pppoe_header_t))) = rte_cpu_to_be_16(PPP_IP_PROTOCOL);
                    single_pkt->data_off -= pppoe_len;
                    single_pkt->pkt_len += pppoe_len;
                    single_pkt->data_len += pppoe_len;
                    { 
                        struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, LAN_PORT, ccb_id);
                        if (likely(__stats)) increase_ccb_rx_count(__stats, single_pkt->pkt_len);
                    };
                    { 
                        struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, WAN_PORT, ccb_id);
                        if (likely(__stats)) increase_ccb_tx_count(__stats, single_pkt->pkt_len);
                    };
                    increase_pppoes_tx_count(ppp_ccb, single_pkt->pkt_len);
                    pkt[total_tx++] = single_pkt;
                } else if (ip_hdr->next_proto_id == IPPROTO_IGMP) {
                    #ifdef TEST_MODE
                    { 
                        struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, LAN_PORT, ccb_id);
                        if (likely(__stats)) increase_ccb_drop_count(__stats, single_pkt->pkt_len);
                    };
                    rte_pktmbuf_free(single_pkt);
                    continue;
                    #else
                    { 
                        struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, LAN_PORT, ccb_id);
                        if (likely(__stats)) increase_ccb_rx_count(__stats, single_pkt->pkt_len);
                    };
                    { 
                        struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, WAN_PORT, ccb_id);
                        if (likely(__stats)) increase_ccb_tx_count(__stats, single_pkt->pkt_len);
                    };
                    pkt[total_tx++] = single_pkt;
                    #endif
                } else if (ip_hdr->next_proto_id == PROTO_TYPE_TCP) {
                    if (unlikely(!rte_is_same_ether_addr(&eth_hdr->dst_addr, &fastrg_ccb->nic_info.hsi_lan_mac))) {
                        { 
                            struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, LAN_PORT, ccb_id);
                            if (likely(__stats)) increase_ccb_rx_count(__stats, single_pkt->pkt_len);
                        };
                        { 
                            struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, WAN_PORT, ccb_id);
                            if (likely(__stats)) increase_ccb_tx_count(__stats, single_pkt->pkt_len);
                        };
                        pkt[total_tx++] = single_pkt;
                        continue;
                    }
                    if (unlikely(rte_atomic16_read(&ppp_ccb->dp_start_bool) == (BIT16)0)) {
                        { 
                            struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, LAN_PORT, ccb_id);
                            if (likely(__stats)) increase_ccb_drop_count(__stats, single_pkt->pkt_len);
                        };
                        rte_pktmbuf_free(single_pkt);
                        continue;
                    }
                    fastrg_ring_enqueue(uplink_q, (void **)&single_pkt, 1);
                } else if (ip_hdr->next_proto_id == PROTO_TYPE_UDP) {
                    if (unlikely(RTE_IS_IPV4_MCAST(rte_be_to_cpu_32(ip_hdr->dst_addr)))) {
                        {
                            struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, LAN_PORT, ccb_id);
                            if (likely(__stats)) increase_ccb_drop_count(__stats, single_pkt->pkt_len);
                        };
                        rte_pktmbuf_free(single_pkt);
                        continue;
                    }
                    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
                    if (unlikely(udp_hdr->dst_port == rte_be_to_cpu_16(DHCP_SERVER_PORT))) {
                        fastrg_ring_enqueue(gateway_q, (void **)&single_pkt, 1);
                        continue;
                    }
                    if (unlikely(!rte_is_same_ether_addr(&eth_hdr->dst_addr, &fastrg_ccb->nic_info.hsi_lan_mac))) {
                        {
                            struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, LAN_PORT, ccb_id);
                            if (likely(__stats)) increase_ccb_rx_count(__stats, single_pkt->pkt_len);
                        };
                        {
                            struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, WAN_PORT, ccb_id);
                            if (likely(__stats)) increase_ccb_tx_count(__stats, single_pkt->pkt_len);
                        };
                        pkt[total_tx++] = single_pkt;
                        continue;
                    }
                    if (unlikely(rte_atomic16_read(&ppp_ccb->dp_start_bool) == (BIT16)0)) {
                        { 
                            struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, LAN_PORT, ccb_id);
                            if (likely(__stats)) increase_ccb_drop_count(__stats, single_pkt->pkt_len);
                        };
                        rte_pktmbuf_free(single_pkt);
                        continue;
                    }
                    fastrg_ring_enqueue(uplink_q, (void **)&single_pkt, 1);
                } else {
                    FastRG_LOG(DBG, fastrg_ccb->fp, NULL, NULL, "unknown L4 packet with protocol id %x recv on LAN port queue", ip_hdr->next_proto_id);
                    {
                        struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, LAN_PORT, ccb_id);
                        if (likely(__stats)) increase_ccb_drop_count(__stats, single_pkt->pkt_len);
                    };
                    rte_pktmbuf_free(single_pkt);
                }
            } else {
                FastRG_LOG(DBG, fastrg_ccb->fp, NULL, NULL, "unknown ether type %x recv on gateway LAN port queue", rte_be_to_cpu_16(vlan_header->next_proto));
                { 
                    struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, LAN_PORT, ccb_id);
                    if (likely(__stats)) increase_ccb_drop_count(__stats, single_pkt->pkt_len);
                };
                rte_pktmbuf_free(single_pkt);
                continue;
            }
        }
        if (likely(total_tx > 0)) {
            nb_tx = rte_eth_tx_burst(WAN_PORT, gen_port_q, pkt, total_tx);
            if (unlikely(nb_tx < total_tx)) {
                for(U16 buf=nb_tx; buf<total_tx; buf++)
                    rte_pktmbuf_free(pkt[buf]);
            }
            total_tx = 0;
        }
    }
    return 0;
}


/* process RG function such as DHCP server, gateway ARP replying */
int gateway(void *arg)
{
    struct rte_mbuf 	*pkt[BURST_SIZE], *single_pkt;
    U16					burst_size, ccb_id;
    struct rte_ether_hdr *eth_hdr;
    vlan_header_t		*vlan_header;
    struct rte_ipv4_hdr *ip_hdr;
    int 				i, ret;
    struct rte_arp_hdr	*arphdr;
    struct rte_icmp_hdr *icmphdr;
    struct rte_udp_hdr 	*udp_hdr;
    FastRG_t 			*fastrg_ccb = (FastRG_t *)arg;

    rte_thread_t thread_id = rte_thread_self();
    rte_thread_set_name(thread_id, "fastrg_gateway");

    //for(i=0; i<BURST_SIZE; i++)
        //pkt[i] = rte_pktmbuf_alloc(direct_pool[0]);

    while(likely(rte_atomic16_read(&stop_flag) == 0)) {
        burst_size = rte_ring_dequeue_burst(gateway_q, (void **)pkt, BURST_SIZE, NULL);
        for(i=0; i<burst_size; i++) {
            single_pkt = pkt[i];
            rte_prefetch0(rte_pktmbuf_mtod(single_pkt, void *));
            mbuf_priv_t *mbuf_priv = rte_mbuf_to_priv(single_pkt);
            vlan_header = mbuf_priv->vlan_hdr;
            eth_hdr = mbuf_priv->eth_hdr;
            ccb_id = mbuf_priv->ccb_id;
            U32 dhcp_server_ip = mbuf_priv->dhcp_server_ip;
            if (unlikely(vlan_header->next_proto == rte_cpu_to_be_16(FRAME_TYPE_ARP))) {
                arphdr = (struct rte_arp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t));
                /* This is arp request to us */
                if (arphdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST) && 
                        arphdr->arp_data.arp_tip == dhcp_server_ip) {
                    rte_ether_addr_copy(&eth_hdr->src_addr, &eth_hdr->dst_addr);
                    rte_ether_addr_copy(&fastrg_ccb->nic_info.hsi_lan_mac, &eth_hdr->src_addr);
                    rte_ether_addr_copy(&arphdr->arp_data.arp_sha, &arphdr->arp_data.arp_tha);
                    rte_ether_addr_copy(&fastrg_ccb->nic_info.hsi_lan_mac, &arphdr->arp_data.arp_sha);
                    arphdr->arp_data.arp_tip = arphdr->arp_data.arp_sip;
                    arphdr->arp_data.arp_sip = dhcp_server_ip;
                    arphdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
                    { struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, LAN_PORT, ccb_id); if (__stats) increase_ccb_rx_count(__stats, single_pkt->pkt_len); };
                    { struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, LAN_PORT, ccb_id); if (__stats) increase_ccb_tx_count(__stats, single_pkt->pkt_len); };
                    rte_eth_tx_burst(LAN_PORT, gen_port_q, &single_pkt, 1);
                    continue;
                }
                /*else if ((arphdr->arp_data.arp_tip << 8) ^ (fastrg_ccb.ppp_ccb[ccb_id].lan_ip << 8)) {
                    rte_eth_tx_burst(LAN_PORT, gen_port_q, &single_pkt, 1);
                    continue;
                }*/ else {
                    {
                        struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, LAN_PORT, ccb_id);
                        if (likely(__stats)) increase_ccb_rx_count(__stats, single_pkt->pkt_len);
                    };
                    { 
                        struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, WAN_PORT, ccb_id);
                        if (likely(__stats)) increase_ccb_tx_count(__stats, single_pkt->pkt_len);
                    };
                    rte_eth_tx_burst(WAN_PORT, gen_port_q, &single_pkt, 1);
                }
                continue;
            } else if (likely(vlan_header->next_proto == rte_cpu_to_be_16(FRAME_TYPE_IP))) {
                ip_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t));
                switch (ip_hdr->next_proto_id) {
                case PROTO_TYPE_ICMP:
                    icmphdr = (struct rte_icmp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(struct rte_ipv4_hdr));
                    if (ip_hdr->dst_addr == dhcp_server_ip) {
                        rte_ether_addr_copy(&eth_hdr->src_addr, &eth_hdr->dst_addr);
                        rte_ether_addr_copy(&fastrg_ccb->nic_info.hsi_lan_mac, &eth_hdr->src_addr);
                        ip_hdr->dst_addr = ip_hdr->src_addr;
                        ip_hdr->src_addr = dhcp_server_ip;
                        icmphdr->icmp_type = 0;
                        U32 cksum = ~icmphdr->icmp_cksum & 0xffff;
                        cksum += ~rte_cpu_to_be_16(8 << 8) & 0xffff;
                        cksum += rte_cpu_to_be_16(0 << 8);
          				cksum = (cksum & 0xffff) + (cksum >> 16);
                        cksum = (cksum & 0xffff) + (cksum >> 16);
                        icmphdr->icmp_cksum = ~cksum;
                        rte_eth_tx_burst(LAN_PORT, gen_port_q, &single_pkt, 1);
                        continue;
                    } else {
                        rte_eth_tx_burst(LAN_PORT, gen_port_q, &single_pkt, 1);
                        continue;
                    }
                    {
                        struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, LAN_PORT, ccb_id);
                        if (likely(__stats)) increase_ccb_rx_count(__stats, single_pkt->pkt_len);
                    };
                    {
                        struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, LAN_PORT, ccb_id);
                        if (likely(__stats)) increase_ccb_tx_count(__stats, single_pkt->pkt_len);
                    };
                    increase_pppoes_tx_count(PPPD_GET_CCB(fastrg_ccb, ccb_id), single_pkt->pkt_len);
                    break;
                case PROTO_TYPE_UDP:
                    udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
                    if (udp_hdr->dst_port == rte_be_to_cpu_16(DHCP_SERVER_PORT)) {
                        /* start to process dhcp client packet here */
                        dhcp_ccb_t *dhcp_ccb = DHCPD_GET_CCB(fastrg_ccb, ccb_id);
                        if (rte_atomic16_read(&dhcp_ccb->dhcp_bool) == 0) {
                            {
                                struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, LAN_PORT, ccb_id);
                                if (likely(__stats)) increase_ccb_drop_count(__stats, single_pkt->pkt_len);
                            };
                            rte_pktmbuf_free(single_pkt);
                            continue;
                        }
                        ret = dhcpd(fastrg_ccb, single_pkt, eth_hdr, vlan_header, ip_hdr, udp_hdr, ccb_id);
                        if (ret == 0) {
                            {
                                struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, LAN_PORT, ccb_id);
                                if (likely(__stats)) increase_ccb_rx_count(__stats, single_pkt->pkt_len);
                            };
                            {
                                struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, WAN_PORT, ccb_id);
                                if (likely(__stats)) increase_ccb_tx_count(__stats, single_pkt->pkt_len);
                            };
                            rte_eth_tx_burst(WAN_PORT, gen_port_q, &single_pkt, 1);
                        } else if (ret > 0) {
                            {
                                struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, LAN_PORT, ccb_id);
                                if (likely(__stats)) increase_ccb_rx_count(__stats, single_pkt->pkt_len);
                            };
                            {
                                struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, LAN_PORT, ccb_id);
                                if (likely(__stats)) increase_ccb_tx_count(__stats, single_pkt->pkt_len);
                            };
                            rte_eth_tx_burst(LAN_PORT, gen_port_q, &single_pkt, 1);
                        } else {
                            {
                                struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, LAN_PORT, ccb_id);
                                if (likely(__stats)) increase_ccb_drop_count(__stats, single_pkt->pkt_len);
                            };
                            rte_pktmbuf_free(single_pkt);
                        }
                        continue;
                    }
                    break;
                default:
                    break;
                }
                {
                    struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, LAN_PORT, ccb_id);
                    if (likely(__stats)) increase_ccb_drop_count(__stats, single_pkt->pkt_len);
                };
                rte_pktmbuf_free(single_pkt);
                continue;
            } else {
                {
                    struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, LAN_PORT, ccb_id);
                    if (likely(__stats)) increase_ccb_drop_count(__stats, single_pkt->pkt_len);
                };
                rte_pktmbuf_free(single_pkt);
                continue;
            }
        }
    }
    return 0;
}

void drv_xmit(FastRG_t *fastrg_ccb, U16 ccb_id, U8 *mu, U16 mulen)
{
    struct rte_mbuf *pkt;
    unsigned char *buf;

    pkt = rte_pktmbuf_alloc(direct_pool[0]);
    if (pkt == NULL) {
        {
            struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, WAN_PORT, ccb_id);
            if (likely(__stats)) increase_ccb_drop_count(__stats, mulen);
        };
        FastRG_LOG(ERR, fastrg_ccb->fp, NULL, NULL, "drv_xmit failed: rte_pktmbuf_alloc failed: %s\n", rte_strerror(rte_errno));
        return;
    }
    buf = rte_pktmbuf_mtod(pkt, unsigned char *);
    rte_memcpy(buf, mu, mulen);
    pkt->data_len = mulen;
    pkt->pkt_len = mulen;
    {
        struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, WAN_PORT, ccb_id);
        if (likely(__stats)) increase_ccb_tx_count(__stats, mulen);
    };
    if (rte_eth_tx_burst(WAN_PORT, ctrl_port_q, &pkt, 1) == 0) {
        {
            struct per_ccb_stats *__stats = OPENRG_GET_PER_SUBSCRIBER_STATS(fastrg_ccb, WAN_PORT, ccb_id);
            if (likely(__stats)) increase_ccb_drop_count(__stats, mulen);
        };
        rte_pktmbuf_free(pkt);
    }
}

static int lsi_event_callback(U16 port_id, enum rte_eth_event_type type, void *param)
{
    FastRG_t *fastrg_ccb = (FastRG_t *)param;
    struct rte_eth_link link = { 0 };
    tFastRG_MBX *mail = fastrg_malloc(tFastRG_MBX, sizeof(tFastRG_MBX), 2048);
    if (mail == NULL) {
        FastRG_LOG(ERR, fastrg_ccb->fp, NULL, NULL, 
            "lsi_event_callback failed: fastrg_malloc failed\n");
        return -1;
    }

    FastRG_LOG(WARN, fastrg_ccb->fp, NULL, NULL, "\n\nIn registered callback...\n");
    FastRG_LOG(WARN, fastrg_ccb->fp, NULL, NULL, "Event type: %s\n", 
        type == RTE_ETH_EVENT_INTR_LSC ? "LSC interrupt" : "unknown event");
    int link_get_err = rte_eth_link_get_nowait(port_id, &link);
    if (link_get_err != 0) {
        FastRG_LOG(ERR, fastrg_ccb->fp, NULL, NULL, 
            "lsi_event_callback failed: rte_eth_link_get_nowait failed: %s\n", 
            strerror(-link_get_err));
        fastrg_mfree(mail);
        return -1;
    }
    if (link.link_status) {
        FastRG_LOG(WARN, fastrg_ccb->fp, NULL, NULL, "Port %d Link Up - speed %u Mbps - %s\n\n",
                port_id, (unsigned)link.link_speed,
            (link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX) ?
                ("full-duplex") : ("half-duplex"));
        mail->refp[0] = LINK_UP;
    } else {
        FastRG_LOG(WARN, fastrg_ccb->fp, NULL, NULL, "Port %d Link Down\n\n", port_id);
        mail->refp[0] = LINK_DOWN;
    }
    *(U16 *)&(mail->refp[1]) = port_id;
    mail->type = EV_LINK;
    mail->len = 1;
    //enqueue down event to main thread
    fastrg_ring_enqueue(cp_q, (void **)&mail, 1);

    return 0;
}
