#include <linux/ethtool.h>

#include <common.h>

#include <rte_version.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_bus.h>
#include <rte_bus_pci.h>

int rte_ethtool_get_drvinfo(U16 port_id, struct ethtool_drvinfo *drvinfo)
{
    struct rte_eth_dev_info dev_info;
    struct rte_dev_reg_info reg_info;
    int n;

    if (drvinfo == NULL)
        return -EINVAL;

    RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -ENODEV);

    int ret = rte_eth_dev_fw_version_get(port_id, drvinfo->fw_version,
                  sizeof(drvinfo->fw_version));
    if (ret < 0) {
        printf("firmware version get error: (%s)\n", strerror(-ret));
    } else if (ret > 0) {
        printf("Insufficient fw version buffer size, "
               "the minimum size should be %d\n", ret);
    }

    memset(&dev_info, 0, sizeof(dev_info));
    ret = rte_eth_dev_info_get(port_id, &dev_info);
    if (ret != 0) {
        printf("get port %d info failed\n", port_id);
        return ret;
    }

    strlcpy(drvinfo->driver, dev_info.driver_name, sizeof(drvinfo->driver));
    strlcpy(drvinfo->version, rte_version(), sizeof(drvinfo->version));
    strlcpy(drvinfo->bus_info, rte_dev_name(dev_info.device), sizeof(drvinfo->bus_info));

    memset(&reg_info, 0, sizeof(reg_info));
    ret = rte_eth_dev_get_reg_info(port_id, &reg_info);
    if (ret != 0) {
        printf("get port %d register info failed\n", port_id);
        return ret;
    }
    n = reg_info.length;
    drvinfo->regdump_len = n ? n > 0 : 0;

    n = rte_eth_dev_get_eeprom_length(port_id);
    drvinfo->eedump_len = n > 0 ? n : 0;

    drvinfo->n_stats = sizeof(struct rte_eth_stats) / sizeof(uint64_t);
    drvinfo->testinfo_len = 0;

    return 0;
}