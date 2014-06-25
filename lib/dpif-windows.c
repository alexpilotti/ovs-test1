/*
 * Copyright (c) 2014 VMware, Inc.
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

#include <config.h>

#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include "byte-order.h"
#include "openvswitch/types.h"
#include "dpif-provider.h"
#include "netdev-provider.h"
#include "OvsPub.h"
#include "flow.h"
#include "odp-util.h"
#include "ofpbuf.h"
#include "packets.h"
#include "sset.h"
#include "type-props.h"
#include "dpif-windows.h"
#include "poll-loop.h"
#include "netdev-vport.h"
#include "vlog.h"
#include "dynamic-string.h"

VLOG_DEFINE_THIS_MODULE(dpif_windows);

/* Datapath interface for the openvswitch Windows kernel module. */
struct dpif_windows {
    struct dpif dpif;
    uint32_t dp_no;

    struct ovs_mutex upcall_lock;
    struct hmap ports_tbl;
    /* Change notification. */
    struct sset changed_ports;  /* Ports that have changed. */
    bool new_poll;
};

struct dpif_windows_datapath_port {
    struct hmap_node node;
    uint32_t port_num;
    uint32_t type;
    char port_name[OVSWIN_DEVICE_NAME_MAX_LENGTH];
};

enum { MAX_ACTIONS = 65536 };
char *systemType = "system";

static void output_dpif_flow_stats(struct OvsFlowStats *,
                                            struct dpif_flow_stats *);

/* We keep separate handles for packet receive and event handling.
 * They might or might not reside on the same thread. */
/* Global control handle - for the ioctls */
static HANDLE ovs_ctl_device = INVALID_HANDLE_VALUE;

/* handle specifically used for receiving packets from the kernel */
static HANDLE ovs_recv_device = INVALID_HANDLE_VALUE;
static HANDLE ovs_recv_event = NULL;
static OVERLAPPED ovs_recv_overlapping;

/* handle specifically used for port events */
static HANDLE ovs_event_device = INVALID_HANDLE_VALUE;
static HANDLE ovs_event_event = NULL;
static OVERLAPPED ovs_event_overlapping;
long long int ovs_dp_timestamp_set_time;

#define OVS_DP_TIMESTAMP_SET_TIME_INTVL 1000 /* in milliseconds */

/* Socket on the VXLAN port */
#define VXLAN_DST_PORT 4789
static int vxlan_fd = -1;

#define ASSERT_ON_COMPILE(e) \
   do { \
      enum { AssertOnCompileMisused = ((e) ? 1 : -1) }; \
      typedef char AssertOnCompileFailed[AssertOnCompileMisused]; \
   } while (0)

#define OFFSET_OF(type, field) ((uintptr_t)&(((type *)0)->field))


/* Converts the Windows error number to the POSIX errno. */
int
win_error_to_errno(DWORD win_errno)
{
    switch (win_errno) {
    case ERROR_DEV_NOT_EXIST:
        return ENOENT;
    case ERROR_NOT_SUPPORTED:
        return EOPNOTSUPP;
    default:
        break;
    }
    return EINVAL;
}

static struct dpif_windows *
dpif_windows_cast(const struct dpif *dpif)
{
    dpif_assert_class(dpif, &dpif_windows_class);
    return CONTAINER_OF(dpif, struct dpif_windows, dpif);
}

static int
dpif_windows_init(void)
{
    int error = 0;

    if (ovs_ctl_device == INVALID_HANDLE_VALUE) {
        error = dpif_windows_init_handle(&ovs_ctl_device, NULL);
        if (error) {
            return win_error_to_errno(error);
        }
    }

    if (ovs_recv_device == INVALID_HANDLE_VALUE) {
        error = dpif_windows_init_handle(&ovs_recv_device, &ovs_recv_event);
        if (error) {
            return win_error_to_errno(error);
        }
        memset(&ovs_recv_overlapping, 0, sizeof ovs_recv_overlapping);
        ovs_recv_overlapping.hEvent = ovs_recv_event;
    }

    if (ovs_event_device == INVALID_HANDLE_VALUE) {
        error = dpif_windows_init_handle(&ovs_event_device, &ovs_event_event);
        if (error) {
            return win_error_to_errno(error);
        }
        memset(&ovs_event_overlapping, 0, sizeof ovs_event_overlapping);
        ovs_event_overlapping.hEvent = ovs_event_event;
    }

    return error;
}

/*
 * Wrapper for the Windows IoControl function.
 * Return values:
 *   value of reply_len on success.
 *   -(posix error number) on failure.
 *   -E2BIG if reply_len is insufficient. The actual required length will be set
 *   into reply_out_len, if it is not NULL.
 */
static int
dpif_windows_ioctl__(HANDLE handle, uint32_t type, const void *request,
                     size_t request_len, void *reply, size_t reply_len)
{
    int retval;
    int error = 0;
    DWORD bytes;
    DWORD win_error;

    error = dpif_windows_init();
    if (error) {
        return error;
    }

    /*
    * There seems to be a skew between the kernel's version of current time and
    * the userspace's version of current time. The skew was seen to
    * monotonically increase as well.
    *
    * In order to deal with the situation, we periodicatlly pass down the
    * userspace's version of the timestamp to the kernel, and let the kernel
    * calculate the delta. The frequency of this is
    * OVS_DP_TIMESTAMP_SET_TIME_INTVL.
    */
    {
        long long int curtime = time_msec();
        if (curtime - ovs_dp_timestamp_set_time >
            OVS_DP_TIMESTAMP_SET_TIME_INTVL) {
            if (!DeviceIoControl(handle, OVS_IOCTL_DP_TIMESTAMP_SET,
                (LPVOID)&curtime, (DWORD)sizeof curtime,
                NULL, NULL, NULL, NULL)) {
                ovs_assert(FALSE);
            }
        }
    }

    if (!DeviceIoControl(handle, type,
        (LPVOID)request, (DWORD)request_len,
        (LPVOID)reply, (DWORD)reply_len,
        &bytes, NULL)) {
        win_error = GetLastError();
        //TODO don't massage here, return the raw win_error.
        if (win_error == ERROR_MORE_DATA ||
            win_error == ERROR_INSUFFICIENT_BUFFER) {
            error = -E2BIG;
        } else {
            error = -win_error_to_errno(GetLastError());
        }
    } else {
        error = bytes;
    }

    return error;
}

int
dpif_windows_ioctl(uint32_t type, const void *request, size_t request_len,
                   void *reply, size_t reply_len)
{
    return dpif_windows_ioctl__(ovs_ctl_device, type, request, request_len,
                                        reply, reply_len);
}

static int
dpif_windows_init_handle(HANDLE *handle, HANDLE *event)
{
    int error = 0;
    int bytes;
    OVS_VERSION version;

    *handle = CreateFile(
        OVS_DEVICE_PATH,
        GENERIC_READ | GENERIC_WRITE,  //FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ,
        NULL,                          // no SECURITY_ATTRIBUTES structure
        OPEN_EXISTING,                 // No special create flags
        FILE_FLAG_OVERLAPPED,          // overlapping
        NULL);

    if (*handle == INVALID_HANDLE_VALUE) {
        error = GetLastError();
        VLOG_ERR("Failed to open the control device: %ws error %d\n",
                 OVS_DEVICE_PATH, error);
        return error;
    }

    memset(&version, 0, sizeof version);

    error = DeviceIoControl(*handle, OVS_IOCTL_VERSION_GET,
                            NULL, 0,
                            &version, sizeof version,
                            &bytes, NULL);

    if (error == 0 || bytes != sizeof version) {
        error = GetLastError();
        VLOG_ERR("Failed driver version query: %ws error %d\n",
                 OVS_DEVICE_PATH, error);
        goto cleanup;
    }

    if (version.mjrDrvVer != OVS_DRIVER_MAJOR_VER) {
        VLOG_ERR("User/Kernel Driver version mismatch :"
                 "kernel version - %d, user version - %d\n",
                 OVS_DRIVER_MAJOR_VER, version.mjrDrvVer);
        error = ERROR_NOT_SUPPORTED;
        goto cleanup;
    }

    VLOG_DBG("Driver version %u.%u\n", version.mjrDrvVer, version.mnrDrvVer);

    if (event == NULL) {
        /* no events associated with this handle */
        return 0;
    }

    if (*event == NULL) {
        *event = CreateEvent(NULL, FALSE, FALSE, NULL);
    }
    if (*event == NULL) {
        error = GetLastError();
        VLOG_ERR("Failed to create event for %s %u\n", __FUNCTION__, error);
        return error;
    }

    return 0;

cleanup:
    CloseHandle(*handle);
    *handle = INVALID_HANDLE_VALUE;
    return error;
}

int
dpif_windows_dump_numbers(uint32_t command,
                          const void *request, size_t request_len,
                          uint32_t **replyp, size_t *n_replyp)
{
    size_t capacity;

    for (capacity = 64; capacity < 65536; capacity *= 2) {
        uint32_t *reply;
        size_t len;
        int retval;

        len = capacity * sizeof *reply;
        reply = xmalloc(len);

        retval = dpif_windows_ioctl(command, request, request_len, reply, len);
        if (retval >= 0) {
            *replyp = reply;
            *n_replyp = retval / sizeof *reply;
            return 0;
        }
        free(reply);

        if (retval != -E2BIG) {
            return -retval;
        }
    }

    return E2BIG;
}

static int
get_dps(const uint32_t *dp_nos, POVS_DP_INFO gets, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        int retval = dpif_windows_ioctl(OVS_IOCTL_DP_GET,
                                        &dp_nos[i], sizeof dp_nos[i],
                                        &gets[i], sizeof gets[i]);
        if (retval < 0) {
            return -retval;
        }
    }

    return 0;
}

static int
dpif_windows_get_dps(POVS_DP_INFO *getsp, size_t *n_getsp)
{
    int error;

    error = dpif_windows_init();
    if (error) {
        return error;
    }

    for (;;) {
        uint32_t *dp_nos;
        POVS_DP_INFO gets;
        size_t n_dps;

        error = dpif_windows_dump_numbers(OVS_IOCTL_DP_DUMP, NULL, 0,
                                          &dp_nos, &n_dps);
        if (error) {
            return error;
        }

        gets = xmalloc(n_dps * sizeof *gets);
        error = get_dps(dp_nos, gets, n_dps);

        free(dp_nos);
        if (!error) {
            *getsp = gets;
            *n_getsp = n_dps;
        } else {
            free(gets);
        }

        if (error != ENOENT) {
            return error;
        }

        /* Set of datapaths changed.  Try again. */
    }
    return 0;
}

static int
dpif_windows_enumerate(struct sset *all_dps)
{
    POVS_DP_INFO gets;
    size_t n_gets;
    int error;

    error = dpif_windows_get_dps(&gets, &n_gets);
    if (!error) {
        size_t i;

        for (i = 0; i < n_gets; i++) {
            sset_add(all_dps, gets[i].name);
        }
        free(gets);
    }
    return error;
}

static void
dpif_windows_datapath_polling_init(struct dpif_windows *dpif)
{
    OVS_EVENT_SUBSCRIBE event_subscribe;
    int retval;
    int bytes;

    dpif_windows_init();

    event_subscribe.dpNo = OVS_DP_NUMBER;
    event_subscribe.subscribe = 1;
    event_subscribe.mask = OVS_EVENT_MASK_ALL;
    retval = DeviceIoControl(ovs_event_device, OVS_IOCTL_EVENT_SUBSCRIBE, &event_subscribe,
                             sizeof event_subscribe, NULL, 0, &bytes, NULL);

    if (retval == 0) {
        VLOG_ERR("Unable to register for event notifications");
        return;
    }
}

static int
dpif_windows_open(const struct dpif_class *class OVS_UNUSED, const char *name,
                  bool create, struct dpif **dpifp)
{
    POVS_DP_INFO gets;
    size_t n_gets;
    int error;

    error = dpif_windows_get_dps(&gets, &n_gets);
    if (!error) {
        size_t i;

        error = create ? EOPNOTSUPP : ENOENT;
        for (i = 0; i < n_gets; i++) {
            const POVS_DP_INFO get = &gets[i];

            if (!strcmp(get->name, name)) {
                struct dpif_windows *dpif;

                if (create) {
                    error = EEXIST;
                    free(gets);
                    break;
                }

                /* XXX Will be moved to Kernel, must be done here since add port is not always called */
                if (vxlan_fd < 0) {
                   vxlan_fd = inet_open_passive(SOCK_DGRAM, "4789:0.0.0.0", VXLAN_DST_PORT, NULL, 0);
                }

                dpif = xzalloc(sizeof *dpif);
                dpif->dp_no = OVS_DP_NUMBER;
                ovs_mutex_init(&dpif->upcall_lock);
                dpif_init(&dpif->dpif, &dpif_windows_class, get->name,
                          dpif->dp_no, dpif->dp_no);
                *dpifp = &dpif->dpif;

                dpif_windows_datapath_polling_init(dpif);
                dpif->new_poll = true;
                hmap_init(&dpif->ports_tbl);
                sset_init(&dpif->changed_ports);
                free(gets);
                error = 0;
                break;
            }  else {
               VLOG_INFO("Name %s doesn't match: %s", name, get->name);
            }
            free(gets);
        }
    }
    return error;
}

static void
dpif_windows_close(struct dpif *dpif_)
{
    struct dpif_windows *dpif = dpif_windows_cast(dpif_);

    if (vxlan_fd >= 0) {
        closesocket(vxlan_fd);
        vxlan_fd = -1;
    }

    // close(dpif->chrdev_fd);
    sset_destroy(&dpif->changed_ports);
    hmap_destroy(&dpif->ports_tbl);
    ovs_mutex_destroy(&dpif->upcall_lock);
    free(dpif);
}

static int
dpif_windows_get_stats(const struct dpif *dpif_, struct dpif_dp_stats *stats)
{
    struct dpif_windows *dpif = dpif_windows_cast(dpif_);
    OVS_DP_INFO get;
    int retval;

    retval = get_dps(&dpif->dp_no, &get, 1);
    if (retval < 0) {
        return -retval;
    }

    memset(stats, 0, sizeof(*stats));
    stats->n_hit    = get.nHit;
    stats->n_missed = get.nMissed;
    stats->n_lost   = get.nLost;
    stats->n_flows  = get.nFlows;
    return 0;
}

static int
dpif_windows_port_query__(const struct dpif *dpif_ OVS_UNUSED,
                          uint32_t port_no,
                          const char *port_name, struct dpif_port *dpif_port,
                          struct ovs_vport_stats *stats)
{
    OVS_VPORT_INFO info;
    OVS_VPORT_GET get;
    int retval;

    memset(&get, 0, sizeof get);
    get.dpNo = OVS_DP_NUMBER;
    get.portNo = port_no;

    if (port_name) {
        if (strlen(port_name) >= sizeof get.name) {
            return ENODEV;
        }
        strcpy(get.name, port_name);
    }

    retval = dpif_windows_ioctl(OVS_IOCTL_VPORT_GET, &get, sizeof get,
                                &info, sizeof info);

    if (retval < 0) {
        return (-retval == ENOENT ? ENODEV : -retval);
    }

    if (port_name && strncmp(port_name, info.name, strlen(port_name))) {
      return ENODEV;
    }

    if (dpif_port) {
        dpif_port->name = xstrdup(port_name);

        switch (info.type) {
        case OVSWIN_VPORT_TYPE_GRE:
           dpif_port->type = xstrdup("gre");
           break;
        case OVSWIN_VPORT_TYPE_GRE64:
           dpif_port->type = xstrdup("gre64");
           break;
        case OVSWIN_VPORT_TYPE_VXLAN:
           dpif_port->type = xstrdup("vxlan");
           break;
        case OVSWIN_VPORT_TYPE_EXTERNAL:
        case OVSWIN_VPORT_TYPE_INTERNAL:
        case OVSWIN_VPORT_TYPE_SYNTHETIC:
        case OVSWIN_VPORT_TYPE_EMULATED:
           dpif_port->type = xstrdup("system");
           break;

        case OVSWIN_VPORT_TYPE_LOCAL:
        case OVSWIN_VPORT_TYPE_UNKNOWN:
        default:
            VLOG_ERR("Invalid port type: %d", info.type);
            return ENOENT;
        }

        dpif_port->port_no = info.portNo;
    }

    if (stats) {
        stats->rx_packets = info.rxPackets;
        stats->tx_packets = info.txPackets;
        stats->rx_bytes = info.rxBytes;
        stats->tx_bytes = info.txBytes;
        stats->rx_errors = info.rxErrors;
        stats->tx_errors = info.txErrors;
        stats->rx_dropped = info.rxDropped;
        stats->tx_dropped = info.txDropped;
    }

     return 0;
}

static int
dpif_windows_port_add(struct dpif *dpif_, struct netdev *netdev,
                      uint32_t *port_nop)
{
    struct dpif_windows *dpif = dpif_windows_cast(dpif_);
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
    const char *name = netdev_vport_get_dpif_port(netdev,
                                                  namebuf, sizeof namebuf);
    struct dpif_port dpif_port;
    const struct netdev_tunnel_config *tnl_cfg;
    int error;

   /*
    * This API is supposed to pass VPORT_NEW command to the datapath to create
    * a new port. VPORT_NEW ioctl is not implemented in Windows datapath yet.
    * Hence, return failure if the port does not already exist.
    * Returning success will mislead ofproto and bridge
    * into thinking that there now exists this new port in the datapath
    */
    *port_nop = 0;
    error = dpif_windows_port_query__(dpif_, 0, name, &dpif_port, NULL);
    if (error > 0) {
       char *type;
       OVS_VPORT_ADD_REQUEST request;
       OVS_VPORT_INFO reply;

       type = (char *)netdev_get_type(netdev);
       memset(&request, 0, sizeof request);
       memset(&reply, 0, sizeof reply);
       request.dpNo = dpif->dp_no;
       VLOG_INFO("create port type:%s\n", type);

       if (!strcmp(type, "gre")) {
          request.type = OVSWIN_VPORT_TYPE_GRE;
       } else if (!strcmp(type, "gre64")) {
          request.type = OVSWIN_VPORT_TYPE_GRE64;
       } else if (!strcmp(type, "vxlan")) {
          request.type = OVSWIN_VPORT_TYPE_VXLAN;
       } else {
          /*
           * we may add uplink support later
           * when we move away from DVS.
           */
          goto done;
       }
       strcpy(request.name, name);

       tnl_cfg = netdev_get_tunnel_config(netdev);
       if (tnl_cfg && tnl_cfg->dst_port != 0) {
          request.dstPort = ntohs(tnl_cfg->dst_port);
       } else {
          request.dstPort = 0;
       }
       error = dpif_windows_ioctl(OVS_IOCTL_VPORT_ADD, &request,
                                  sizeof request, &reply, sizeof reply);
       if (error >= 0) {
          *port_nop = reply.portNo;
          return 0;
       } else {
          VLOG_INFO("Fail to add port:%s", name);
          return -error;
       }
    } else {
        *port_nop = dpif_port.port_no;
        dpif_port_destroy(&dpif_port);
    }

done:
    return error;
}

static int
dpif_windows_port_del(struct dpif *dpif_ OVS_UNUSED,
                      uint32_t port_no OVS_UNUSED)
{
    struct dpif_windows *dpif = dpif_windows_cast(dpif_);
    OVS_VPORT_DELETE_REQUEST request;
    OVS_VPORT_INFO info;
    OVS_VPORT_GET get;
    int retVal;
    memset(&get, 0, sizeof get);
    get.dpNo = OVS_DP_NUMBER;
    get.portNo = port_no;

    retVal = dpif_windows_ioctl(OVS_IOCTL_VPORT_GET, &get, sizeof get,
                                &info, sizeof info);

    if (retVal == -ENOENT) {
        /* If the port does not exist in the first place, return success */
        return 0;
    } else if (retVal <= 0) {
        return -retVal;
    }

    switch (info.type) {
    case OVSWIN_VPORT_TYPE_GRE:
    case OVSWIN_VPORT_TYPE_GRE64:
    case OVSWIN_VPORT_TYPE_VXLAN:
       break;
    case OVSWIN_VPORT_TYPE_LOCAL:
    case OVSWIN_VPORT_TYPE_EXTERNAL:
    case OVSWIN_VPORT_TYPE_INTERNAL:
    case OVSWIN_VPORT_TYPE_SYNTHETIC:
    case OVSWIN_VPORT_TYPE_EMULATED:
    default:
       return 0;
    }

    memset(&request, 0, sizeof request);
    request.dpNo = dpif->dp_no;
    request.portNo = port_no;

    retVal = dpif_windows_ioctl(OVS_IOCTL_VPORT_DEL, &request, sizeof request,
                                NULL, 0);
    return -retVal;
}

static int
dpif_windows_port_query_by_number(const struct dpif *dpif, uint32_t port_no,
                                  struct dpif_port *dpif_port)
{
    return dpif_windows_port_query__(dpif, port_no, NULL, dpif_port, NULL);
}

static int
dpif_windows_port_query_by_name(const struct dpif *dpif, const char *devname,
                                struct dpif_port *dpif_port)
{
    return dpif_windows_port_query__(dpif, 0, devname, dpif_port, NULL);
}

static uint32_t
dpif_windows_port_get_pid(const struct dpif *dpif OVS_UNUSED,
                          uint32_t port_no, uint32_t hash)
{
    return (port_no != UINT32_MAX) ?  port_no : 0;
}

struct dpif_windows_port_state {
    uint32_t dp_no;

    uint32_t *port_nos;
    size_t n_ports;
    size_t pos;

    OVS_VPORT_INFO info;
};

static int
dpif_windows_port_dump_start(const struct dpif *dpif_, void **statep)
{
    struct dpif_windows *dpif = dpif_windows_cast(dpif_);
    struct dpif_windows_port_state *state;
    int retval;

    *statep = state = xzalloc(sizeof *state);
    state->dp_no = dpif->dp_no;
    retval = dpif_windows_dump_numbers(OVS_IOCTL_VPORT_DUMP,
                                       &dpif->dp_no, sizeof dpif->dp_no,
                                       &state->port_nos, &state->n_ports);
    if (retval < 0) {
        free(state);
        return -retval;
    }

    return 0;
}

static int
dpif_windows_port_dump_next(const struct dpif *dpif OVS_UNUSED, void *state_,
                            struct dpif_port *dpif_port)
{
    struct dpif_windows_port_state *state = state_;

    while (state->pos < state->n_ports) {
        OVS_VPORT_GET get;
        int retval;

        get.dpNo = state->dp_no;
        get.portNo = state->port_nos[state->pos++];
        get.name[0] = '\0';
        retval = dpif_windows_ioctl(OVS_IOCTL_VPORT_GET,
                                    &get, sizeof get,
                                    &state->info, sizeof state->info);
        if (retval > 0) {
            dpif_port->name = state->info.name;
            switch (state->info.type) {
            case OVSWIN_VPORT_TYPE_GRE:
               dpif_port->type = "gre";
               break;
            case OVSWIN_VPORT_TYPE_GRE64:
               dpif_port->type = "gre64";
               break;
            case OVSWIN_VPORT_TYPE_VXLAN:
               dpif_port->type = "vxlan";
               break;
            case OVSWIN_VPORT_TYPE_EXTERNAL:
            case OVSWIN_VPORT_TYPE_INTERNAL:
            case OVSWIN_VPORT_TYPE_SYNTHETIC:
            case OVSWIN_VPORT_TYPE_EMULATED:
               dpif_port->type = "system";
               break;

            case OVSWIN_VPORT_TYPE_LOCAL:
            case OVSWIN_VPORT_TYPE_UNKNOWN:
            default:
                VLOG_ERR("Unknown port type %d", state->info.type);
                return ENOENT;
            }

            dpif_port->port_no = get.portNo;
            return 0;
        } else if (retval == -ENOENT) {
           VLOG_INFO("Positive retval from ioctl, setting port name from state");
            /* Probably the port disappeared from the datapath while we were
             * iterating.  Just skip it, so as not to truncate the list of
             * ports. */
        } else {
            VLOG_INFO("Unknown return value from IOCTL");
            return -retval;
        }
    }

    return EOF;
}

static int
dpif_windows_port_dump_done(const struct dpif *dpif_ OVS_UNUSED, void *state_)
{
    struct dpif_windows_port_state *state = state_;
    free(state->port_nos);
    free(state);
    return 0;
}

int
dpif_windows_port_ext_info(uint32_t port_no, char *name,
                           POVS_VPORT_EXT_INFO ext_info)
{
    OVS_VPORT_GET vport_request;
    int retval;
    int bytes;

    vport_request.dpNo = OVS_DP_NUMBER;
    vport_request.portNo = port_no;
    if (name) {
        strncpy(vport_request.name, name, sizeof vport_request.name);
    } else {
        vport_request.name[0] = '\0';
    }
    retval = DeviceIoControl(ovs_event_device, OVS_IOCTL_VPORT_EXT_INFO,
                             &vport_request, sizeof vport_request,
                             ext_info, sizeof *ext_info,
                             &bytes, NULL);
    return retval;
}

static int
dpif_windows_port_notify(struct dpif_windows *dpif, uint32_t port_no,
                         uint32_t status)
{
    struct dpif_windows_datapath_port *port = NULL;
    OVS_VPORT_EXT_INFO vport_info;
    struct hmap_node *node;
    int retval;

    memset(&vport_info, 0, sizeof vport_info);
    retval = dpif_windows_port_ext_info(port_no, NULL,
                                        &vport_info);
    if (retval == 0) {
        return retval;
    }

    node = hmap_first_with_hash(&dpif->ports_tbl, port_no);
    if (node) {
        ASSIGN_CONTAINER(port, node, node);
        netdev_win_state_notify(port->port_name,
                status ? status : vport_info.status);
     } else {
        port = xmalloc(sizeof *port);
        port->port_num = vport_info.portNo;
        port->type = vport_info.type;
        strncpy(port->port_name, vport_info.name, sizeof port->port_name);
        hmap_insert(&dpif->ports_tbl, &port->node, port_no);
     }
     VLOG_INFO("Port %s status changed\n", port->port_name);
     sset_add(&dpif->changed_ports, port->port_name);

    return retval;
}

#define DPIF_WINDOWS_NUM_PORTS_PER_POLL 32
uint32_t event_status[DPIF_WINDOWS_NUM_PORTS_PER_POLL * 2 + 1];

static void
dpif_windows_poll_datapath(struct dpif_windows *dpif)
{
    OVS_EVENT_POLL event_poll;
    POVS_EVENT_STATUS es;
    int retval;
    int bytes;
    int i;
    struct dpif_windows_datapath_port *port = NULL;
    OVS_VPORT_GET vport_request;
    struct hmap_node *node;
    int dp_no;
    size_t n_ports;
    uint32_t *port_nos;

    event_poll.dpNo = OVS_DP_NUMBER;
    retval = DeviceIoControl(ovs_event_device, OVS_IOCTL_EVENT_POLL,
                             &event_poll, sizeof(event_poll),
                             event_status, sizeof event_status,
                             &bytes, NULL);
    if (retval == 0) {
        VLOG_INFO("Cannot get ioctl event poll\n");
        return;
    }

    es = (POVS_EVENT_STATUS)event_status;
    if (es->numberEntries == 0) {
        return;
    }

    for (i = 0; i < es->numberEntries; i++) {
        if (es->eventEntries[i].portNo == OVS_DEFAULT_PORT_NO) {
            dp_no = OVS_DP_NUMBER;
            retval = dpif_windows_dump_numbers(OVS_IOCTL_VPORT_DUMP,
                                               &dp_no, sizeof dp_no,
                                               &port_nos, &n_ports);
            if (retval < 0) {
                return;
            }

            for (i = 0; i < n_ports; i++) {
                VLOG_INFO("port 0x%x\n", port_nos[i]);
                retval = dpif_windows_port_notify(dpif, port_nos[i], 0);
            }
        } else {
            VLOG_INFO("port 0x%x status %x\n", es->eventEntries[i].portNo,
                      es->eventEntries[i].status);
            if (es->eventEntries[i].status & (OVS_EVENT_DISCONNECT | OVS_EVENT_LINK_DOWN)) {
                node = hmap_first_with_hash(&dpif->ports_tbl, es->eventEntries[i].portNo);
                if (node) {
                    ASSIGN_CONTAINER(port, node, node);
                    VLOG_INFO("Port %s disconnected\n", port->port_name);
                    netdev_win_state_notify(port->port_name, es->eventEntries[i].status);
                    sset_add(&dpif->changed_ports, port->port_name);
                    hmap_remove(&dpif->ports_tbl, &port->node);
                    free(port);
                }
                continue;
            }
            retval = dpif_windows_port_notify(dpif, es->eventEntries[i].portNo,
                                              es->eventEntries[i].status);
        }
    }
}

static int
dpif_windows_port_poll(const struct dpif *dpif_, char **devnamep)
{
    struct dpif_windows *dpif = dpif_windows_cast(dpif_);

    if (dpif->new_poll) {
       dpif_windows_poll_datapath(dpif);
       dpif->new_poll = false;
    }

    if (!sset_is_empty(&dpif->changed_ports)) {
        *devnamep = sset_pop(&dpif->changed_ports);
        return 0;
    } else {
        dpif->new_poll = true;
        return EAGAIN;
    }

    /* NOT REACHED */
    return 0;
}

static void
dpif_windows_port_poll_wait(const struct dpif *dpif_)
{
    struct dpif_windows *dpif = dpif_windows_cast(dpif_);
    OVS_EVENT_POLL event_poll;
    int ret = 0;
    int error;
    int bytes;

    if (ovs_event_overlapping.Internal != STATUS_PENDING) {
        event_poll.dpNo = OVS_DP_NUMBER;
        ret = DeviceIoControl(ovs_event_device, OVS_IOCTL_EVENT_WAIT,
                              &event_poll, sizeof event_poll,
                              NULL, 0, &bytes, &ovs_event_overlapping);
        if (ret == 0) {
            error = GetLastError();
            if (error != ERROR_IO_INCOMPLETE && error != ERROR_IO_PENDING) {
                VLOG_INFO("Wait for datapath failed %u\n", error);
                return;
            }
        } else {
            poll_immediate_wake();
        }
    }

    poll_fd_wait_event(ovs_event_device, ovs_event_event, POLLIN);
}

/* Checks whether 'flow' can be expressed as an OvsFlowKey.  Returns true if it
 * can be, false otherwise. */
static bool
dpif_windows_flow_is_ok(const struct flow *flow)
{
      return flow->pkt_mark == 0;
}

static bool
convert_to_flow_key(const struct flow *src, OvsFlowKey *dst)
{
    if (!dpif_windows_flow_is_ok(src)) {
        return false;
    }

    if (src->tunnel.ip_dst) {
       dst->tunKey.tunnelId = src->tunnel.tun_id;
       dst->tunKey.dst = src->tunnel.ip_dst;
       dst->tunKey.src = src->tunnel.ip_src;
       dst->tunKey.flags = src->tunnel.flags;
       dst->tunKey.tos = src->tunnel.ip_tos;
       dst->tunKey.ttl = src->tunnel.ip_ttl;
       dst->tunKey.pad = 0;
       dst->l2.offset = 0;
    } else {
       dst->tunKey.attr[0] = 0;
       dst->tunKey.attr[1] = 0;
       dst->tunKey.attr[2] = 0;
       dst->l2.offset = sizeof (OvsIPv4TunnelKey);
    }

    /* l2 */
    dst->l2.inPort = src->in_port.odp_port;
    memcpy(dst->l2.dlSrc, src->dl_src, ETH_ADDR_LEN);
    memcpy(dst->l2.dlDst, src->dl_dst, ETH_ADDR_LEN);
    BUILD_ASSERT(OVSWIN_VLAN_CFI == VLAN_CFI);
    BUILD_ASSERT(OVSWIN_DL_TYPE_NONE == FLOW_DL_TYPE_NONE);
    dst->l2.vlanTci = src->vlan_tci;
    dst->l2.dlType = src->dl_type;

    /* l3 + l4 */
    dst->l2.keyLen = OVS_WIN_TUNNEL_KEY_SIZE + OVS_L2_KEY_SIZE - dst->l2.offset;
    switch (ntohs(dst->l2.dlType)) {
    case ETH_TYPE_IP: {
       IpKey *ipKey = &dst->ipKey;
       ipKey->nwSrc = src->nw_src;
       ipKey->nwDst = src->nw_dst;
       ipKey->nwProto = src->nw_proto;
       ipKey->nwTos = src->nw_tos;
       ipKey->nwTtl = src->nw_ttl;
       ipKey->nwFrag = src->nw_frag;
       ipKey->l4.tpSrc = src->tp_src;
       ipKey->l4.tpDst = src->tp_dst;
       }
       dst->l2.keyLen += OVS_IP_KEY_SIZE;
       break;
    case ETH_TYPE_IPV6: {
       Ipv6Key *ipv6Key = &dst->ipv6Key;
       ipv6Key->ipv6Src = src->ipv6_src;
       ipv6Key->ipv6Dst = src->ipv6_dst;
       ipv6Key->nwProto = src->nw_proto;
       ipv6Key->nwTos = src->nw_tos;
       ipv6Key->nwTtl = src->nw_ttl;
       ipv6Key->nwFrag = src->nw_frag;
       ipv6Key->ipv6Label = src->ipv6_label;
       ipv6Key->l4.tpSrc = src->tp_src;
       ipv6Key->l4.tpDst = src->tp_dst;
       ipv6Key->pad = 0;
       if (src->nw_proto == IPPROTO_ICMPV6) {
          Icmp6Key *icmp6Key= &dst->icmp6Key;
          icmp6Key->ndTarget = src->nd_target;
          memcpy(icmp6Key->arpSha, src->arp_sha, ETH_ADDR_LEN);
          memcpy(icmp6Key->arpTha, src->arp_tha, ETH_ADDR_LEN);
          dst->l2.keyLen += OVS_ICMPV6_KEY_SIZE;
       } else {
          dst->l2.keyLen += OVS_IPV6_KEY_SIZE;
       }
       }
       break;
    case ETH_TYPE_ARP:
    case ETH_TYPE_RARP: {
       ArpKey *arpKey = &dst->arpKey;
       arpKey->nwSrc = src->nw_src;
       arpKey->nwDst = src->nw_dst;
       memcpy(arpKey->arpSha, src->arp_sha, ETH_ADDR_LEN);
       memcpy(arpKey->arpTha, src->arp_tha, ETH_ADDR_LEN);
       arpKey->nwProto = src->nw_proto;
       arpKey->pad[0] = 0;
       arpKey->pad[1] = 0;
       arpKey->pad[2] = 0;
       dst->l2.keyLen += OVS_ARP_KEY_SIZE;
       break;
       }
    }
    return true;
}

/* Converts the 'key_len' bytes of OVS_KEY_ATTR_* attributes in 'key' to a flow
 * structure in 'flow'.  Returns true if the translation was perfect, otherwise
 * logs an error and returns false.
 *
 * This does the same work as odp_flow_key_to_flow().  It is suitable for use
 * when we know that 'key' was generated by odp_flow_key_from_flow(), so that
 * anything other than a perfect translation indicates a bug in one of the
 * translation functions. */
static bool
odp_perfect_flow_key_to_flow(const struct nlattr *key, size_t key_len,
                             struct flow *flow)
{

    if (odp_flow_key_to_flow(key, key_len, flow) == ODP_FIT_PERFECT) {
        return true;
    } else {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

        if (!VLOG_DROP_ERR(&rl)) {
            struct ds s;

            ds_init(&s);
            odp_flow_key_format(key, key_len, &s);
            VLOG_ERR("internal error parsing flow key %s", ds_cstr(&s));
            ds_destroy(&s);
        }

        return false;
    }
}

static int
dpif_windows_flow_get(const struct dpif *dpif_,
                      const struct nlattr *key, size_t key_len,
                      struct ofpbuf **actionsp, struct dpif_flow_stats *statsp)
{
    struct dpif_windows *dpif = dpif_windows_cast(dpif_);
    struct flow flow;
    OvsFlowInfo info;
    OvsFlowGetInput getInput;
    OvsFlowGetOutput *getOutput;
    size_t getOpLen;
    size_t actionsLen;
    int retval;

    getInput.dpNo = dpif->dp_no;
    if (!odp_perfect_flow_key_to_flow(key, key_len, &flow)) {
        return EINVAL;
    }
    if (!convert_to_flow_key(&flow, &getInput.key)) {
        return ENOENT;
    }
    actionsLen = MAX_ACTIONS;
    getOpLen = sizeof *getOutput + actionsLen;
    getOutput = xzalloc(getOpLen);

    getInput.getFlags = statsp ? FLOW_GET_STATS : 0;
    getInput.getFlags |= actionsp ? FLOW_GET_ACTIONS : 0;
    getInput.actionsLen = actionsLen;

    retval = dpif_windows_ioctl(OVS_IOCTL_FLOW_GET, &getInput, sizeof getInput,
                                getOutput, getOpLen);
    if (retval < 0) {
        goto done;
    }

    if (actionsp) {
        *actionsp = ofpbuf_clone_data(getOutput->info.actions,
                                      getOutput->info.actionsLen);
    }
    if (statsp) {
        output_dpif_flow_stats(statsp, &getOutput->info.stats);
    }

done:
    if (getOutput) {
        free(getOutput);
    }
    return retval ? -retval : 0;
}

static int
dpif_windows_construct_ovs_flow_put(struct dpif_windows *dpif,
                                    uint32_t flags,
                                    const struct nlattr *keyp,
                                    size_t key_len,
                                    const struct nlattr *actions,
                                    size_t actions_len,
                                    struct dpif_flow_stats *statsp,
                                    OvsFlowPut *put,
                                    struct OvsFlowStats *flowStats)
{
    struct flow flow;

    if (!odp_perfect_flow_key_to_flow(keyp, key_len, &flow)
        || !convert_to_flow_key(&flow, &put->key)) {
        return EINVAL;
    }

    /* Make sure some of the members are word-aligned */
    ASSERT_ON_COMPILE(OFFSET_OF(OvsFlowPut, key) % 4 == 0);
    ASSERT_ON_COMPILE(OFFSET_OF(OvsFlowPut, actions) % 4 == 0);

    put->dpNo = dpif->dp_no;
    put->actionsLen = actions_len;
    put->flags = flags;
    if (actions_len) {
       memcpy(put->actions, actions, actions_len);
    }
    return 0;
}

static int
do_put(struct dpif *dpif_,
       uint32_t flags,
       const struct nlattr *keyp, size_t key_len,
       const struct nlattr *actions, size_t actions_len,
       struct dpif_flow_stats *statsp)
{
    struct dpif_windows *dpif = dpif_windows_cast(dpif_);
    OvsFlowStats stats;
    OvsFlowPut *put;
    int retval = 0;
    size_t putlen = sizeof *put;

    if (actions_len) {
       putlen += actions_len;
    }

    put = xzalloc(putlen);
    retval = dpif_windows_construct_ovs_flow_put(dpif, flags, keyp, key_len,
                                                 actions, actions_len, statsp,
                                                 put, &stats);
    if (retval) {
       retval = -retval;
       goto cleanup;
    }

    retval = dpif_windows_ioctl(OVS_IOCTL_FLOW_PUT, put, putlen,
                                &stats, sizeof(stats));
    if (retval < 0) {
        VLOG_ERR("flow put failed %u\n", retval);
        goto cleanup;
    }

    if (statsp) {
        output_dpif_flow_stats(statsp, &stats);
    }

cleanup:
    free(put);
    return retval < 0 ? -retval : 0;
}

static int
dpif_windows_flow_put(struct dpif *dpif, const struct dpif_flow_put *put)
{
    uint32_t flags;

    flags = 0;
    if (put->flags & DPIF_FP_CREATE) {
        flags |= OVSWIN_FLOW_PUT_CREATE;
    }
    if (put->flags & DPIF_FP_MODIFY) {
        flags |= OVSWIN_FLOW_PUT_MODIFY;
    }
    if (put->flags & DPIF_FP_ZERO_STATS) {
        flags |= OVSWIN_FLOW_PUT_CLEAR;
    }

    return do_put(dpif, flags, put->key, put->key_len,
                  put->actions, put->actions_len, put->stats);
}

static int
dpif_windows_flow_del(struct dpif *dpif, const struct dpif_flow_del *del)
{
    VLOG_INFO("dpif_windows_flow_del\n");
    return do_put(dpif, OVSWIN_FLOW_PUT_DELETE, del->key, del->key_len,
                  NULL, 0, del->stats);
}

static int
dpif_windows_flow_flush(struct dpif *dpif_)
{
    struct dpif_windows *dpif = dpif_windows_cast(dpif_);
    int retval;

    retval = dpif_windows_ioctl(OVS_IOCTL_FLOW_FLUSH, &dpif->dp_no,
                                sizeof dpif->dp_no, NULL, 0);
    return retval < 0 ? -retval : 0;
}

struct dpif_windows_flow_dump {
    struct dpif_flow_dump up;
    int status;
};

static struct dpif_windows_flow_dump *
dpif_windows_flow_dump_cast(struct dpif_flow_dump *dump)
{
    return CONTAINER_OF(dump, struct dpif_windows_flow_dump, up);
}

static struct dpif_flow_dump *
dpif_windows_flow_dump_create(const struct dpif *dpif_)
{
    struct dpif_windows_flow_dump *fdump;

    fdump = xmalloc(sizeof *fdump);
    dpif_flow_dump_init(&fdump->up, dpif_);
    fdump->status = 0;

    return &fdump->up;
}

static int
dpif_windows_flow_dump_destroy(struct dpif_flow_dump *dump_)
{
    int status;
    struct dpif_windows_flow_dump *fdump = dpif_windows_flow_dump_cast(dump_);
    status = fdump->status;
    free(fdump);
    return status;
}

struct dpif_windows_flow_state {
    uint32_t dp_position[2];
    struct ofpbuf key_buf;
    struct ofpbuf flow_buf;
};

struct dpif_windows_flow_dump_thread {
    struct dpif_flow_dump_thread up;
    struct dpif_windows_flow_dump *dump;
    struct dpif_windows_flow_state *state;
};

static struct dpif_flow_dump_thread *
dpif_windows_flow_dump_thread_create(struct dpif_flow_dump *dump_)
{
#define FLOW_DUMP_SIZE 4096
    struct dpif_windows_flow_dump *fdump = dpif_windows_flow_dump_cast(dump_);
    struct dpif_windows_flow_dump_thread *fthread;

    fthread = xmalloc(sizeof *fthread);
    dpif_flow_dump_thread_init(&fthread->up, &fdump->up);
    fthread->dump = fdump;
    fthread->state = xzalloc(sizeof(*fthread->state));
    ofpbuf_init(&fthread->state->key_buf, ODPUTIL_FLOW_KEY_BYTES);
    ofpbuf_init(&fthread->state->flow_buf, FLOW_DUMP_SIZE);

    return &fthread->up;
}

static struct dpif_windows_flow_dump_thread *
dpif_windows_flow_dump_thread_cast(struct dpif_flow_dump_thread *thread)
{
    return CONTAINER_OF(thread, struct dpif_windows_flow_dump_thread, up);
}

static void
dpif_windows_flow_dump_thread_destroy(struct dpif_flow_dump_thread *thread_)
{
    struct dpif_windows_flow_dump_thread *fthread =
                                dpif_windows_flow_dump_thread_cast(thread_);

    ofpbuf_uninit(&fthread->state->flow_buf);
    ofpbuf_uninit(&fthread->state->key_buf);

    free(fthread->state);
    free(fthread);
}

static void
dpif_windows_ovs_flow_key_to_flow(const OvsFlowKey *src, struct flow *dst)
{
    if (src->tunKey.dst) {
       dst->tunnel.tun_id = src->tunKey.tunnelId;
       dst->tunnel.ip_dst = src->tunKey.dst;
       dst->tunnel.ip_src = src->tunKey.src;
       dst->tunnel.flags = src->tunKey.flags;
       dst->tunnel.ip_tos = src->tunKey.tos;
       dst->tunnel.ip_ttl = src->tunKey.ttl;
    } else {
       memset(&dst->tunnel, 0, sizeof (dst->tunnel));
    }

    dst->in_port.odp_port = src->l2.inPort;
    memcpy(dst->dl_src, src->l2.dlSrc, ETH_ADDR_LEN);
    memcpy(dst->dl_dst, src->l2.dlDst, ETH_ADDR_LEN);
    BUILD_ASSERT(OVSWIN_VLAN_CFI == VLAN_CFI);
    BUILD_ASSERT(OVSWIN_DL_TYPE_NONE == FLOW_DL_TYPE_NONE);
    dst->vlan_tci = src->l2.vlanTci;
    dst->dl_type = src->l2.dlType;
    dst->metadata = htonll(0);
    dst->skb_priority = 0;
    dst->pkt_mark = 0;
    memset(dst->regs, 0, sizeof dst->regs);
    memset(&dst->nd_target, 0, sizeof (dst->nd_target));
    memset(dst->arp_sha, 0, sizeof dst->arp_sha);
    memset(dst->arp_tha, 0, sizeof dst->arp_tha);

    switch (ntohs(dst->dl_type)) {
    case ETH_TYPE_IP: {
       const IpKey *ipKey = &src->ipKey;
       dst->nw_src = ipKey->nwSrc;
       dst->nw_dst = ipKey->nwDst;
       dst->nw_proto = ipKey->nwProto;
       dst->nw_tos = ipKey->nwTos;
       dst->nw_ttl = ipKey->nwTtl;
       dst->nw_frag = ipKey->nwFrag;
       dst->tp_src = ipKey->l4.tpSrc;
       dst->tp_dst = ipKey->l4.tpDst;

       dst->ipv6_label = 0;
       memset(&dst->ipv6_src, 0, sizeof (dst->ipv6_src));
       memset(&dst->ipv6_dst, 0, sizeof (dst->ipv6_dst));
    }
       break;
    case ETH_TYPE_IPV6: {
       const Ipv6Key *ipv6Key = &src->ipv6Key;
       dst->ipv6_src = ipv6Key->ipv6Src;
       dst->ipv6_dst = ipv6Key->ipv6Dst;
       dst->nw_proto = ipv6Key->nwProto;
       dst->nw_tos = ipv6Key->nwTos;
       dst->nw_ttl = ipv6Key->nwTtl;
       dst->nw_frag = ipv6Key->nwFrag;
       dst->ipv6_label = ipv6Key->ipv6Label;
       dst->tp_src = ipv6Key->l4.tpSrc;
       dst->tp_dst = ipv6Key->l4.tpDst;

       if (dst->nw_proto == IPPROTO_ICMPV6) {
          const Icmp6Key *icmp6Key= &src->icmp6Key;
          dst->nd_target = icmp6Key->ndTarget;
          memcpy(dst->arp_sha, icmp6Key->arpSha, ETH_ADDR_LEN);
          memcpy(dst->arp_tha, icmp6Key->arpTha, ETH_ADDR_LEN);
       }
       dst->nw_src = 0;
       dst->nw_dst = 0;
    }
       break;
    default:
       dst->ipv6_label = 0;
       memset(&dst->ipv6_src, 0, sizeof (dst->ipv6_src));
       memset(&dst->ipv6_dst, 0, sizeof (dst->ipv6_dst));
       if (dst->dl_type == htons(ETH_TYPE_ARP) ||
           dst->dl_type == htons(ETH_TYPE_RARP)) {
          const ArpKey *arpKey = &src->arpKey;
          dst->nw_src = arpKey->nwSrc;
          dst->nw_dst = arpKey->nwDst;
          dst->nw_proto = arpKey->nwProto;
          memcpy(dst->arp_sha, arpKey->arpSha, ETH_ADDR_LEN);
          memcpy(dst->arp_tha, arpKey->arpTha, ETH_ADDR_LEN);
       } else {
          dst->nw_src = 0;
          dst->nw_dst = 0;
          dst->nw_proto = 0;
       }
       dst->nw_tos = 0;
       dst->nw_ttl = 0;
       dst->nw_frag = 0;
       dst->tp_src = 0;
       dst->tp_dst = 0;
    }
}

static void
dpif_windows_flow_dump_to_dpif_flow(const OvsFlowDumpOutput *out,
                                    struct dpif_flow *upFlow,
                                    struct dpif_windows_flow_state *fstate)
{
    struct flow flow;

    ofpbuf_clear(&fstate->key_buf);
    memset(&flow,0, sizeof(flow));

    /* output flow key */
    dpif_windows_ovs_flow_key_to_flow(&out->flow.key, &flow);
    odp_flow_key_from_flow(&fstate->key_buf, &flow, NULL,
                                            flow.in_port.odp_port, false);
    upFlow->key = ofpbuf_data(&fstate->key_buf);
    upFlow->key_len = ofpbuf_size(&fstate->key_buf);

    /* Wild card flows, not yet supported */
    upFlow->mask = NULL;
    upFlow->mask_len = 0;

    /* output actions */
    upFlow->actions = out->flow.actions;
    upFlow->actions_len = out->flow.actionsLen;

    /* output stats */
    output_dpif_flow_stats(&upFlow->stats, &out->flow.stats);
}

/* Only dumps 1 flow, doesn't batch flows */
static int
dpif_windows_flow_dump_next(struct dpif_flow_dump_thread *thread_,
                            struct dpif_flow *flows, int max_flows)
{
    struct dpif_windows_flow_dump_thread *fthread =
                                dpif_windows_flow_dump_thread_cast(thread_);
    struct dpif_windows *dpif = dpif_windows_cast(fthread->up.dpif);
    struct dpif_windows_flow_state *fstate = fthread->state;
    bool retry = false;
    OvsFlowDumpInput dumpInput;
    OvsFlowDumpOutput *dumpOutput;
    size_t dumpOutputSize;
    int retval;

    ovs_assert(dpif->dp_no == OVS_DP_NUMBER);
    dumpInput.dpNo = dpif->dp_no;
    dumpInput.position[0] = fstate->dp_position[0];
    dumpInput.position[1] = fstate->dp_position[1];
    dumpInput.getFlags = FLOW_GET_KEY | FLOW_GET_STATS | FLOW_GET_ACTIONS;

    for (;;) {
        ofpbuf_clear(&fstate->flow_buf);
        dumpOutput = ofpbuf_base(&fstate->flow_buf);
        dumpOutputSize = fstate->flow_buf.allocated;
        dumpInput.actionsLen = dumpOutputSize - sizeof(OvsFlowDumpOutput);

        retval = dpif_windows_ioctl(OVS_IOCTL_FLOW_DUMP,
                                    &dumpInput, sizeof dumpInput,
                                    dumpOutput, dumpOutputSize);
        if (!retry && retval == -E2BIG) {
            ovs_assert(dumpOutput->n > dumpOutputSize);
            //dumpInput remains same, since we are retrying the flow dump.
            ofpbuf_reinit(&fstate->flow_buf, MIN(dumpOutput->n, 65536));
            retry = true;
            continue;
        } else if (retval < 0) {
            //XXX does this need to be atomic?
            fthread->dump->status = -retval;
            return 0;
        } else if (dumpOutput->n == 0) {
            //No more flows to dump.
            return 0;
        }
        break;
    }

    fstate->dp_position[0] = dumpOutput->position[0];
    fstate->dp_position[1] = dumpOutput->position[1];

    dpif_windows_flow_dump_to_dpif_flow(&dumpOutput, &flows[0], fstate);

    ovs_assert(dumpOutput->n == 1);
    return dumpOutput->n;
}

static int
dpif_execute_to_packetexecute(struct dpif_windows *dpif,
                              struct dpif_execute *execute,
                              OvsPacketExecute *exe)
{
    struct flow flow;

    exe->dpNo = dpif->dp_no;
    memcpy(exe->packetBuf, ofpbuf_data(execute->packet),
           ofpbuf_size(execute->packet));
    exe->packetLen = ofpbuf_size(execute->packet);
    exe->inPort = execute->md.in_port.odp_port;
    memcpy((char *)&exe->actions + exe->packetLen, execute->actions,
           execute->actions_len);
    exe->actionsLen = execute->actions_len;
    return 0;
}

static int
dpif_windows_execute(struct dpif *dpif_, const struct dpif_execute *execute)
{
    struct dpif_windows *dpif = dpif_windows_cast(dpif_);
    OvsPacketExecute *exe;
    int retval;
    uint32_t executeLen = sizeof(*exe) + ofpbuf_size(execute->packet) +
                          execute->actions_len;

    exe = malloc(executeLen);
    if (exe == NULL) {
        return -1;
    }

    retval = dpif_execute_to_packetexecute(dpif,
                                           (struct dpif_execute *)execute,
                                           exe);
    if (retval) {
       free(exe);
       return EINVAL;
    }

    retval = dpif_windows_ioctl(OVS_IOCTL_DATAPATH_EXECUTE, exe, executeLen,
                                NULL, 0);
    free(exe);

    return retval < 0 ? -retval : 0;
}

static int
dpif_windows_subscribe(uint32_t queueId)
{
    uint32_t queue = queueId;
    int retval;

    retval = dpif_windows_ioctl__(ovs_recv_device, OVS_IOCTL_DATAPATH_SUBSCRIBE, &queue,
                                 sizeof queue, NULL, 0);
    if (retval < 0) {
        VLOG_ERR("Fail to subscribe to queue: %u, errno: %d-%s", queueId,
                 errno, ovs_strerror(errno));
    }
    return (retval < 0)? -errno : 0;
}

#define DPIF_DEFAULT_QUEUE_ID   1
static int
dpif_windows_recv_set(struct dpif *dpif_, bool enable)
{
    static int error = -1;

    if (error == 0 || !enable) {
        return error;
    }

    /*
     * since the channels are shared between dpifs, it will
     * not be destroyed when enable is false.
     *
     * XXX: We are going with one descriptor model for both control and datapath
     * in DPIF since it is lesser code to write. We could easily change the
     * model to do separate descriptors by updating dpif_windows_ioctl() and
     * ovs_recv_fd.
     */
    if ((error = dpif_windows_subscribe(DPIF_DEFAULT_QUEUE_ID)) != 0) {
        return error;
    }

    memset(&ovs_recv_overlapping, 0, sizeof(ovs_recv_overlapping));
    ovs_recv_overlapping.hEvent = ovs_recv_event;

    return 0;
}

static int
dpif_windows_handlers_set(struct dpif *dpif, uint32_t n_handlers)
{
    // NOT IMPLEMENTED.
    return 0;
}

static int
dpif_windows_recv(struct dpif *dpif_ OVS_UNUSED,
                  uint32_t handler_id OVS_UNUSED,
                  struct dpif_upcall *upcall,
                  struct ofpbuf *buf)
{
    int rc;
    struct ofpbuf key;
    uint8_t packetBuffer[2048];
    OVERLAPPED olp;
    uint8_t *buf_packet;
    struct nlattr *reply_user_attr, *buf_user_attr;
    uint32_t packet_len;

    if (!buf || !ofpbuf_base(buf)) {
        return EINVAL;
    }

    /*
     * We use the ofpbuf as follows:
     * 1. First ODP_UTIL_FLOW_KEY_BYTES (256) are used for flow key
     * 2. Variable number of bytes to store userdata as nlattr
     * 3. Remaining buffer is used for packet.
     */
    if (ofpbuf_size(buf) <=
        (sizeof(struct odputil_keybuf) + sizeof (struct nlattr))) {
        ofpbuf_uninit(buf);
        ofpbuf_init(buf, 2048);
    }
    ofpbuf_use(&key, ofpbuf_base(buf), sizeof(struct odputil_keybuf));

    memset(&olp, 0, sizeof (olp));
    rc = dpif_windows_ioctl__(ovs_recv_device, OVS_IOCTL_DATAPATH_READ, NULL, 0,
                             packetBuffer, sizeof packetBuffer, &olp);
    if (rc < 0) {
        VLOG_INFO("Read packet failed with error: %d", -rc);
        return -rc;
    }

    if (rc > 0) {
        POVS_PACKET_INFO reply = (POVS_PACKET_INFO)packetBuffer;
        struct flow flow;
        uint32_t reply_user_attr_len;
        uint32_t buf_user_attr_len;

        /* There's data to read */
        if (reply->userDataLen == 0) {
            reply_user_attr = NULL;
            reply_user_attr_len = 0;
        } else {
            reply_user_attr = (struct nlattr *)&reply->data;
            reply_user_attr_len = reply_user_attr->nla_len;
        }

        if (buf->allocated <= sizeof(struct odputil_keybuf) +
                              reply_user_attr_len + reply->packetLen) {
            ofpbuf_reinit(buf, sizeof(struct odputil_keybuf) +
                               reply_user_attr_len + reply->packetLen);
        }

        ofpbuf_use(&key, ofpbuf_base(buf), sizeof(struct odputil_keybuf));

        buf_packet = (uint8_t *)ofpbuf_base(buf) + sizeof(struct odputil_keybuf);
        packet_len = reply_user_attr_len + reply->packetLen;
        if (reply_user_attr_len != 0) {
            buf_user_attr = (struct nlattr *)buf_packet;
            memcpy(buf_user_attr, reply_user_attr, reply_user_attr->nla_len);
            buf_user_attr_len = buf_user_attr->nla_len;
        } else {
            buf_user_attr = NULL;
            buf_user_attr_len = 0;
        }

        /*
         * XXX: copy the user attributes, either using reply->data or by
         * walking the netlink chain.
         */
        buf_packet += buf_user_attr_len;
        buf->frame = (uint8_t *)buf_packet;
        memcpy(buf->frame, ((char *)&reply->data) + reply_user_attr_len,
               reply->packetLen);

        ofpbuf_set_data(buf, buf->frame);
        /* This size includes the user data in nlattr. */
        ofpbuf_set_size(buf, packet_len);
        upcall->type = reply->cmd == OVS_PACKET_CMD_ACTION ?
                       DPIF_UC_ACTION : DPIF_UC_MISS;

        ofpbuf_use_stub(&upcall->packet, buf->frame, reply->packetLen);
        ofpbuf_set_size(&upcall->packet, reply->packetLen);

        upcall->userdata = buf_user_attr;
        flow_extract(buf, NULL, &flow);
        flow.in_port.odp_port = reply->inPort;

        if (reply->tunnelKey.dst) {
            flow.tunnel.tun_id = reply->tunnelKey.tunnelId;
            flow.tunnel.ip_src = reply->tunnelKey.src;
            flow.tunnel.ip_dst = reply->tunnelKey.dst;
            flow.tunnel.flags = reply->tunnelKey.flags;
            flow.tunnel.ip_tos = reply->tunnelKey.tos;
            flow.tunnel.ip_ttl = reply->tunnelKey.ttl;
        }
        odp_flow_key_from_flow(&key, &flow, NULL, flow.in_port.odp_port, false);
        upcall->key = ofpbuf_data(&key);
        upcall->key_len = ofpbuf_size(&key);

        VLOG_DBG("port %u: %s packt recvd with proto %u, pkt length %u.\n",
              flow.in_port.odp_port, dpif_upcall_type_to_string(upcall->type),
              flow.nw_proto, reply->packetLen);
        return 0;
    }

    return EAGAIN;
}

static void
dpif_windows_recv_wait(struct dpif *dpif_, uint32_t handler_id)
{
    struct dpif_windows *dpif = dpif_windows_cast(dpif_);
    int ret = 0;
    int error;
    int bytes;

    if (ovs_recv_overlapping.Internal != STATUS_PENDING) {
        ret = DeviceIoControl(ovs_recv_device, OVS_IOCTL_DATAPATH_WAIT, NULL, 0,
                              NULL, 0, &bytes, &ovs_recv_overlapping);
        if (ret == 0) {
            error = GetLastError();
            if (error != ERROR_IO_INCOMPLETE && error != ERROR_IO_PENDING) {
                VLOG_INFO("Wait for datapath failed\n");
                return;
            }
        } else {
            poll_immediate_wake();
        }
    }

    poll_fd_wait_event(ovs_recv_device, ovs_recv_event, POLLIN);
}

const struct dpif_class dpif_windows_class = {
    "system",
    dpif_windows_enumerate,
    NULL,                               /* port_open_type */
    dpif_windows_open,
    dpif_windows_close,
    NULL,                              /* destroy */
    NULL,
    NULL,
    dpif_windows_get_stats,
    dpif_windows_port_add,
    dpif_windows_port_del,
    dpif_windows_port_query_by_number,
    dpif_windows_port_query_by_name,
    dpif_windows_port_get_pid,
    dpif_windows_port_dump_start,
    dpif_windows_port_dump_next,
    dpif_windows_port_dump_done,
    dpif_windows_port_poll,
    dpif_windows_port_poll_wait,
    dpif_windows_flow_get,
    dpif_windows_flow_put,
    dpif_windows_flow_del,
    dpif_windows_flow_flush,
    dpif_windows_flow_dump_create,
    dpif_windows_flow_dump_destroy,
    dpif_windows_flow_dump_thread_create,
    dpif_windows_flow_dump_thread_destroy,
    dpif_windows_flow_dump_next,
    dpif_windows_execute,
    NULL,                               /* operate - dpif_windows_operate */
    dpif_windows_recv_set,
    dpif_windows_handlers_set,
    NULL,                               /* dpif_windows_queue_to_priority */
    dpif_windows_recv,
    dpif_windows_recv_wait,
    NULL,                               /* purge - dpif_windows_recv_purge */
};

// Used by netdev

/* Executes 'request' in the kernel datapath.  If the command fails, returns a
 * positive errno value.  Otherwise, if 'reply' and 'bufp' are null, returns 0
 * without doing anything else.  If 'reply' and 'bufp' are nonnull, then the
 * result of the command is expected to be an ovs_vport also, which is decoded
 * and stored in '*reply' and '*bufp'.  The caller must free '*bufp' when the
 * reply is no longer needed ('reply' will contain pointers into '*bufp'). */
int
dpif_windows_vport_get(const char *name, struct dpif_windows_vport *reply)
{
    struct dpif_port dummy_dpif_port;
    int error;

    error = dpif_windows_port_query__(NULL, 0, name, &dummy_dpif_port, reply->stats);
    if (error == 0) {
       reply->port_no = dummy_dpif_port.port_no;
       dpif_port_destroy(&dummy_dpif_port);
    }
    return error;
}

void
dpif_windows_set_queue(uint32_t port_no, const struct smap *details)
{
    //NOT IMPLEMENTED
}

static void
output_dpif_flow_stats(struct dpif_flow_stats *dst, struct OvsFlowStats *src)
{
    dst->n_packets = src->packetCount;
    dst->n_bytes = src->byteCount;
    dst->used = src->used;
    dst->tcp_flags = src->tcpFlags;
}
