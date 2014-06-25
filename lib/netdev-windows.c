/*
 * Copyright (c) 2013 VMware
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <config.h>
#include <errno.h>

#include <arpa/inet.h>
#include <inttypes.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>

#include "coverage.h"
#include "dynamic-string.h"
#include "fatal-signal.h"
#include "netdev-provider.h"
#include "OvsPub.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "poll-loop.h"
#include "socket-util.h"
#include "shash.h"
#include "svec.h"
#include "vlog.h"
#include "dpif-windows.h"
#include "linux/openvswitch.h"

enum {
    VALID_IFINDEX           = 1 << 0,
    VALID_ETHERADDR         = 1 << 1,
    VALID_MTU               = 1 << 2,
    VALID_DRVINFO           = 1 << 3,
    VALID_CARRIER           = 1 << 4,
    VALID_FEATURES          = 1 << 5,
    VALID_IFFLAG            = 1 << 6,
};

VLOG_DEFINE_THIS_MODULE(netdev_windows);

static struct vlog_rate_limit netdev_win_rl = VLOG_RATE_LIMIT_INIT(1, 5);

struct netdev_win {
    struct netdev up;
    int32_t dev_type;
    uint32_t port_no;

    unsigned int change_seq;

    unsigned int cache_valid;
    int ifindex;
    uint8_t mac[ETH_ADDR_LEN];
    uint32_t mtu;
    unsigned int ifi_flags;
    int carrier;

    long long int carrier_reset;
    OVS_VPORT_EXT_INFO ext_info;

    enum netdev_features current;
    enum netdev_features advertised;
    enum netdev_features supported;
    enum netdev_features peer;
};

static int netdev_win_init(void);
static int netdev_win_query_port(uint32_t dpNo, const char *name, uint32_t *type,
                                 uint32_t *portNo, uint8_t *macAddr);
static int netdev_win_init_internal(const struct netdev
                                               *netdev_);
static int netdev_win_refresh(const struct netdev *netdev);
static int netdev_win_get_dp_mtu(uint32_t dpNo, uint32_t *mtu);
static void netdev_win_changed(struct netdev_win *dev);
static int netdev_win_set_flag(char *name, uint32_t flags);

static bool
is_netdev_win_class(const struct netdev_class *netdev_class)
{
    return netdev_class->init == netdev_win_init;
}

static struct netdev_win *
netdev_win_cast(const struct netdev *netdev)
{
    ovs_assert(is_netdev_win_class(netdev_get_class(netdev)));
    return CONTAINER_OF(netdev, struct netdev_win, up);
}

/*
 * Please see netdev-provider.h for eack callback functions descriptions
 */

static int
netdev_win_init(void)
{
    return 0;
}

static void
netdev_win_run(void)
{}

static void
netdev_win_wait(void)
{}

static struct netdev *
netdev_win_alloc(void)
{

   struct netdev_win *netdev = xzalloc(sizeof *netdev);
   return &netdev->up;
}

static int
netdev_win_system_construct(struct netdev *netdev_)
{
    struct netdev_win *netdev = netdev_win_cast(netdev_);
    uint8_t mac[ETH_ADDR_LEN];
    uint32_t type, portNo;

    int ret;

    ret = netdev_win_query_port(0, netdev_get_name(netdev_), &type, &portNo, mac);
    if (ret) {
        return ret;
    }

    netdev->change_seq = 1;
    netdev->carrier_reset = 0;
    netdev->dev_type = type;
    netdev->port_no = portNo;

    memcpy(netdev->mac, mac, ETH_ADDR_LEN);
    netdev->cache_valid = VALID_ETHERADDR;

    netdev_win_refresh(netdev_);

    netdev->ifindex = 0;
    netdev->cache_valid |= VALID_IFINDEX;

    VLOG_DBG("construct device %s, type: %u.", netdev_get_name(netdev_), type);
    return 0;
}

static int
netdev_win_init_internal(struct netdev_win *netdev)
{

    int error = 0;

    error = netdev_win_get_dp_mtu(0, &netdev->mtu);
    if (error) {
        netdev->mtu = 1500;
    }
    netdev->carrier = true;
    netdev->ifindex = 0;
    netdev->ifi_flags = IFF_UP | IFF_RUNNING | IFF_PROMISC;
    netdev->current = NETDEV_F_1GB_FD;
    netdev->advertised = NETDEV_F_1GB_FD;
    netdev->supported = NETDEV_F_1GB_FD;

    netdev->cache_valid = (VALID_IFINDEX | VALID_ETHERADDR |
                           VALID_MTU | VALID_CARRIER |
                           VALID_FEATURES | VALID_IFFLAG |
                           VALID_DRVINFO);
    return 0;

}

static int
netdev_win_internal_construct(struct netdev *netdev_)
{
    struct netdev_win *netdev = netdev_win_cast(netdev_);

    netdev->change_seq = 1;
    netdev->carrier_reset = 0;
    netdev->dev_type = OVSWIN_VPORT_TYPE_INTERNAL;
    netdev->port_no = 0;

    memset(netdev->mac, 0, ETH_ADDR_LEN);
    netdev->cache_valid = VALID_ETHERADDR;

    netdev_win_init_internal(netdev);

    VLOG_DBG("Create device %s, type: INTERNAL.", netdev_get_name(netdev_));
    return 0;
}


static int
netdev_win_refresh(const struct netdev *netdev_)
{
    struct netdev_win *netdev = netdev_win_cast(netdev_);
    const char *devname = netdev_->name;
    POVS_VPORT_EXT_INFO ext_info;
    bool oldCarrier;
    int error = 0;

    netdev->carrier = true;
    netdev->cache_valid |= VALID_CARRIER | VALID_FEATURES;


    error = dpif_windows_port_ext_info(0, devname,
                                       &netdev->ext_info);

    if (error == 0) {
        VLOG_WARN("Fail to get vport ext info: %s.", devname);
        return GetLastError();
    }

    ext_info  = &netdev->ext_info;

    /*
     * MTU
     */
    netdev->mtu = ext_info->mtu;
    netdev->cache_valid |= VALID_MTU;

    /*
     * ifflag
     */
    /*
     * IFF_UP reflects administrative state, IFF_RUNNING reflects current
     * link state.
     *
     * dpif_win_link_get does an ioctl which is handled by OVS kernel module.
     * This ioctl handler currently cannot distinguish between admin state
     * and link state.
     *
     * If we return IFF_UP = 0 if interface is administratively up but link is down,
     * netdev_get_carrier will not call get_carrier of netdev_class for interfaces
     * that are administratively down, hence the switch will never detect link
     * coming back up.
     *
     * Hence, for now, we always return IFF_UP = 1. If link is down because of the
     * interface being administratively down, we return IFF_RUNNING = 0, but
     * let the switch think that the interface is administratively up. This
     * allows link state detection and corresponding change in forwarding
     * logic to work properly for now.
     *
     * IFF_UP changes are handled in linux via netlink notifier, which we
     * don't have on WIN. Updating IFF_UP based on admin state on WIN is to
     * be figured out.
     */
    netdev->ifi_flags = 0;

    if (netdev->dev_type == OVSWIN_VPORT_TYPE_EXTERNAL) {
        netdev->ifi_flags |= IFF_UP | IFF_RUNNING;
        if (ext_info->status & OVS_EVENT_LINK_UP) {
            netdev->ifi_flags |= IFF_RUNNING;
        }
        /*
         * promisc should be always set for uplink
         */
        netdev->ifi_flags |= IFF_PROMISC;
    } else {
        netdev->ifi_flags = IFF_UP;
        if (ext_info->status & OVS_EVENT_LINK_UP) {
            netdev->ifi_flags |= IFF_RUNNING;
        }
    }
    netdev->cache_valid |= VALID_IFFLAG;

    return 0;
}

static void
netdev_win_destruct(struct netdev *netdev_)
{
    ovs_assert(is_netdev_win_class(netdev_get_class(netdev_)));
}


static void
netdev_win_dealloc(struct netdev *netdev_)
{
    struct netdev_win *netdev = netdev_win_cast(netdev_);
    free(netdev);
}

static int
netdev_win_get_etheraddr(const struct netdev *netdev_,
                         uint8_t mac[ETH_ADDR_LEN])
{
    struct netdev_win *netdev =
             netdev_win_cast(netdev_);

    if ((netdev->cache_valid & VALID_ETHERADDR) == 0) {
        const char *devname = netdev_get_name(netdev);
        int error;
        uint8_t macAddr[ETH_ADDR_LEN];
        uint32_t type, portNo;
        error = netdev_win_query_port(0, devname, &type, &portNo, macAddr);
        if (error == 0) {
            memcpy(netdev->mac, macAddr, ETH_ADDR_LEN);
            netdev->cache_valid |= VALID_ETHERADDR;
        }
    }
    if (netdev->cache_valid & VALID_ETHERADDR) {
        memcpy(mac, netdev->mac, ETH_ADDR_LEN);
    } else {
        return EINVAL;
    }
    return 0;
}

static int
netdev_win_get_mtu(const struct netdev *netdev_, int *mtup)
{
    struct netdev_win *netdev =
                netdev_win_cast(netdev_);
    if ((netdev->cache_valid & VALID_MTU) == 0) {
        netdev_win_refresh(netdev);
    }
    if (netdev->cache_valid & VALID_MTU) {
        *mtup = netdev->mtu;
    } else {
        return EINVAL;
    }

    return 0;
}

static int
netdev_win_get_ifindex(const struct netdev *netdev_)
{
    struct netdev_win *netdev =
                                netdev_win_cast(netdev_);
    return netdev->ifindex;
}

static int
netdev_win_get_carrier(const struct netdev *netdev_, bool *carrier)
{
    struct netdev_win *netdev = netdev_win_cast(netdev_);

    if ((netdev->cache_valid & VALID_CARRIER) == 0) {
        netdev_win_refresh(netdev);
    }
    if (netdev->cache_valid & VALID_CARRIER) {
        *carrier = netdev->carrier;
    } else {
        return EINVAL;
    }
    return 0;
}


static long long int
netdev_win_get_carrier_resets(const struct netdev *netdev_)
{
   struct netdev_win *netdev = netdev_win_cast(netdev_);
   return netdev->carrier_reset;
}

static void
netdev_win_stats_from_ovs_vport_stats(struct netdev_stats *dst,
                                      const struct ovs_vport_stats *src)
{
    dst->rx_packets = src->rx_packets;
    dst->tx_packets = src->tx_packets;
    dst->rx_bytes = src->rx_bytes;
    dst->tx_bytes = src->tx_bytes;
    dst->rx_errors = src->rx_errors;
    dst->tx_errors = src->tx_errors;
    dst->rx_dropped = src->rx_dropped;
    dst->tx_dropped = src->tx_dropped;
    dst->multicast = 0;
    dst->collisions = 0;
    dst->rx_length_errors = 0;
    dst->rx_over_errors = 0;
    dst->rx_crc_errors = 0;
    dst->rx_frame_errors = 0;
    dst->rx_fifo_errors = 0;
    dst->rx_missed_errors = 0;
    dst->tx_aborted_errors = 0;
    dst->tx_carrier_errors = 0;
    dst->tx_fifo_errors = 0;
    dst->tx_heartbeat_errors = 0;
    dst->tx_window_errors = 0;
}

/* Retrieves current device stats for 'netdev'. */
static int
netdev_win_get_stats_system(const struct netdev *netdev, struct netdev_stats *stats )
{
    struct dpif_windows_vport vport;
    struct ovs_vport_stats vport_stats;
    int error;

    if (stats) {
        vport.stats = &vport_stats;
        error = dpif_windows_vport_get(netdev_get_name(netdev), &vport);
        if (error != 0) {
            VLOG_WARN_RL(&netdev_win_rl, "Error %d in getting vport stats.", error);
            return error;
        }
        netdev_win_stats_from_ovs_vport_stats(stats, &vport_stats);
    } else {
        VLOG_INFO_RL(&netdev_win_rl, "NULL netdev_stats, not populating in %s",
                     __FUNCTION__);
    }
    return 0;
}

static int
netdev_win_get_stats_internal(const struct netdev *netdev OVS_UNUSED,
                              struct netdev_stats *stats)
{
    memset(stats, 0, sizeof (*stats));
    return 0;
}

/*
 * Stores the features supported by 'netdev' into each of '*current',
 * '*advertised', '*supported', and '*peer' that are non-null.  Each value is a
 * bitmap of "enum ofp_port_features" bits, in host byte order.  Returns 0 if
 * successful, otherwise a positive errno value.  On failure, all of the
 * passed-in values are set to 0.
 */
static int
netdev_win_get_features(const struct netdev *netdev_,
                        enum netdev_features *current, uint32_t *advertised,
                        enum netdev_features *supported, uint32_t *peer)
{
    struct netdev_win *netdev = netdev_win_cast(netdev_);

    if (netdev->dev_type == OVSWIN_VPORT_TYPE_INTERNAL) {
        return EOPNOTSUPP;
    }

    if ((netdev->cache_valid & VALID_FEATURES) == 0) {
        netdev_win_refresh(netdev);
    }

    if (netdev->cache_valid & VALID_FEATURES) {
        *current = netdev->current;
        *advertised = netdev->advertised;
        *supported = netdev->supported;
        *peer = netdev->peer;
    } else {
        return EINVAL;
    }

    return 0;
}


static int
netdev_win_set_queue_system(struct netdev *netdev,
                            unsigned int queue_id OVS_UNUSED,
                            const struct smap *details)
{
    struct dpif_windows_vport vport;
    struct ovs_vport_stats vport_stats;
    int error;

    vport.stats = &vport_stats;
    error = dpif_windows_vport_get(netdev_get_name(netdev), &vport);
    if (error == 0) {
        dpif_windows_set_queue(vport.port_no, details);
    }
    return error;
}


static int
netdev_win_get_status(const struct netdev *netdev_, struct smap *smap)
{
    int error = 0;
    struct netdev_win *netdev =
                                netdev_win_cast(netdev_);

    switch (netdev->dev_type) {
    case OVSWIN_VPORT_TYPE_EXTERNAL:
        smap_add(smap, "driver_name", "openvswitch");
        break;
    case OVSWIN_VPORT_TYPE_SYNTHETIC:
    case OVSWIN_VPORT_TYPE_EMULATED:
    case OVSWIN_VPORT_TYPE_INTERNAL:
        smap_add(smap, "driver_name", "openvswitch");
        break;
    default:
        error = EOPNOTSUPP;
    }

    return error;
}

static int
nd_to_iff_flags(enum netdev_flags nd)
{
    int iff = 0;
    if (nd & NETDEV_UP) {
        iff |= IFF_UP;
    }
    if (nd & NETDEV_PROMISC) {
        iff |= IFF_PROMISC;
    }
    return iff;
}

static int
iff_to_nd_flags(int iff)
{
    enum netdev_flags nd = 0;
    if (iff & IFF_UP) {
        nd |= NETDEV_UP;
    }

    if (iff & IFF_PROMISC) {
        nd |= NETDEV_PROMISC;
    }
    return nd;
}


static int
netdev_win_update_flags_system(struct netdev *netdev_,
                               enum netdev_flags off,
                               enum netdev_flags on,
                               enum netdev_flags *old_flagsp)
{
    struct netdev_win *netdev;
    int old_flags, new_flags;
    int error = 0;

    netdev = netdev_win_cast(netdev_);

    old_flags = netdev->ifi_flags;
    *old_flagsp = iff_to_nd_flags(old_flags);
    new_flags = (old_flags & ~nd_to_iff_flags(off)) | nd_to_iff_flags(on);

    /*
     * Set netdev flags
     */
    if (new_flags != old_flags) {
        char *devname = (char *)netdev_get_name(netdev);
        error = netdev_win_set_flag(devname, new_flags);
        if (error) {
            VLOG_WARN_RL(&netdev_win_rl, "Fail to set flag for %s.", devname);
        }
    }
    return error;
}

static int
netdev_win_update_flags_internal(struct netdev *netdev OVS_UNUSED,
                                 enum netdev_flags off OVS_UNUSED,
                                 enum netdev_flags on OVS_UNUSED,
                                 enum netdev_flags *old_flagsp)
{
   *old_flagsp = IFF_UP | IFF_RUNNING | IFF_PROMISC;
   return 0;
}

void
netdev_win_state_notify(char *name, uint16_t status)
{
   /* This is used to update netdev state when kernel notify any state change(mtu,
      mac, link status etc.) */
    struct netdev_win *netdev;
    const struct netdev *dev;

    VLOG_INFO("Event notification: %s, status:%x.", name, status);
    dev = netdev_from_name(name);
    if (dev == NULL) {
        return;
    }
    netdev = netdev_win_cast(dev);

    /* invalidate relevant cache before update changed seq.*/
    netdev->cache_valid &= ~(VALID_CARRIER | VALID_FEATURES | VALID_MTU |
                                 VALID_IFFLAG);
    netdev_win_changed(netdev);
}

static void
netdev_win_changed(struct netdev_win *dev)
{
    dev->change_seq++;
    if (!dev->change_seq) {
        dev->change_seq++;
    }
}


static int
netdev_win_get_dp_mtu(uint32_t dpNo, uint32_t *mtu)
{
   uint32_t dp_no = OVS_DP_NUMBER;
   int error;

   *mtu = 1500;
   return 0;
}


static int
netdev_win_set_flag(char *name, uint32_t flags)
{
    return 0;
}

int
netdev_win_query_port(uint32_t dpNo,
                      const char *name,
                      uint32_t *type,
                      uint32_t *portNo,
                      uint8_t *macAddr)
{
    OVS_VPORT_INFO info;
    OVS_VPORT_GET get;
    int ret;

    memset(&get, 0, sizeof get);

    get.dpNo = OVS_DP_NUMBER;
    get.portNo = 0;

    if (strnlen(name, sizeof (get.name)) >= sizeof (get.name)) {
        return ENODEV;
    }
    ovs_strlcpy(get.name, name, OVSWIN_DEVICE_NAME_MAX_LENGTH);
    ret = dpif_windows_ioctl(OVS_IOCTL_VPORT_GET, &get,
                               sizeof get, &info, sizeof info);
    if (ret < 0) {
        return -ret == ENOENT ? ENODEV : -ret;
    }
    *type = info.type;
    *portNo = info.portNo;
    memcpy(macAddr, info.macAddress, ETH_ADDR_LEN);
    return 0;
}

#define NETDEV_WIN_CLASS(NAME, CONSTRUCT, GET_STATS, SET_QUEUE,    \
                           UPDATE_FLAG)                         \
{                                                               \
    NAME,                                                       \
                                                                \
    netdev_win_init,         /* init */                         \
    netdev_win_run,          /* run */                          \
    netdev_win_wait,         /* wait */                         \
    netdev_win_alloc,                                           \
    CONSTRUCT,                                                  \
    netdev_win_destruct,                                        \
    netdev_win_dealloc,                                         \
    NULL,                   /* get_config */                    \
    NULL,                   /* set_config */                    \
    NULL,                   /* get_tunnel_config */             \
    NULL,                   /* send */                          \
    NULL,                   /* send_wait */                     \
    NULL,                   /* set_etheraddr */                 \
    netdev_win_get_etheraddr,                                   \
    netdev_win_get_mtu,                                         \
    NULL,                   /* set_mtu */                       \
    netdev_win_get_ifindex,                                     \
    netdev_win_get_carrier,                                     \
    netdev_win_get_carrier_resets,                              \
    NULL,                   /* set_miimon_interval */           \
    GET_STATS,                                                  \
    NULL,                   /* set_stats */                     \
    netdev_win_get_features,                                    \
    NULL,                   /* set_advertisements */            \
    NULL,                   /* set_policing */                  \
    NULL,                   /* get_qos_types */                 \
    NULL,                   /* get_qos_capabilities */          \
    NULL,                   /* get_qos */                       \
    NULL,                   /* set_qos */                       \
    NULL,                   /* get_queue */                     \
    SET_QUEUE,                                                  \
    NULL,                   /* delete_queue */                  \
    NULL,                   /* get_queue_stats */               \
    NULL,                   /* queue_dump_start */              \
    NULL,                   /* queue_dump_next */               \
    NULL,                   /* queue_dump_done */               \
    NULL,                   /* dump_queue_stats */              \
    NULL,                   /* get_in4 */                       \
    NULL,                   /* set_in4 */                       \
    NULL,                   /* get_in6 */                       \
    NULL,                   /* add_router */                    \
    NULL,                   /* get_next_hop */                  \
    netdev_win_get_status,                                      \
    NULL,                   /* arp_lookup */                    \
    UPDATE_FLAG,                                                \
    NULL,                   /* rx_alloc */                      \
    NULL,                   /* rx_construct */                  \
    NULL,                   /* rx_destruct */                   \
    NULL,                   /* rx_dealloc */                    \
    NULL,                   /* rx_recv */                       \
    NULL,                   /* rx_wait */                       \
    NULL,                   /* rx_drain */                      \
}

const struct netdev_class netdev_win_class =
    NETDEV_WIN_CLASS(
        "system",
        netdev_win_system_construct,
        netdev_win_get_stats_system,
        netdev_win_set_queue_system,
        netdev_win_update_flags_system);

const struct netdev_class netdev_internal_class =
    NETDEV_WIN_CLASS(
        "internal",
        netdev_win_internal_construct,
        netdev_win_get_stats_internal,
        NULL,
        netdev_win_update_flags_internal);
