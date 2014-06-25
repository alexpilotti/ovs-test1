/*
 * Copyright (c) 2010, 2011 Nicira, Inc.
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

#ifndef DPIF_WINDOWS_H
#define DPIF_WINDOWS_H 1

#include <stdint.h>

struct ofpbuf;

struct dpif_windows_vport {
    /* Generic Netlink header. */
    uint8_t cmd;

    /* ovs_vport header. */
    int dp_ifindex;
    uint32_t port_no;                      /* UINT32_MAX if unknown. */
    enum ovs_vport_type type;

    /* Attributes.
     *
     * The 'stats' member points to 64-bit data that might only be aligned on
     * 32-bit boundaries, so use get_unaligned_u64() to access its values.
     */
    const char *name;                      /* OVS_VPORT_ATTR_NAME. */
    const uint32_t *upcall_pid;            /* OVS_VPORT_ATTR_UPCALL_PID. */
    const struct ovs_vport_stats *stats;   /* OVS_VPORT_ATTR_STATS. */
    const struct nlattr *options;          /* OVS_VPORT_ATTR_OPTIONS. */
    size_t options_len;
};

int dpif_windows_port_ext_info(uint32_t port_no, char *name,
                               POVS_VPORT_EXT_INFO ext_info);
int dpif_windows_vport_get(const char *name, struct dpif_windows_vport *reply);

int dpif_windows_ioctl(uint32_t,
                       const void *request, size_t request_len,
                       void *reply, size_t reply_len);
void netdev_win_state_notify(char *name, uint16_t status);
void dpif_windows_set_queue(uint32_t port_no, const struct smap *details);
int dpif_windows_dump_numbers(uint32_t command,
                              const void *request, size_t request_len,
                              uint32_t **replyp, size_t *n_replyp);
#endif /* dpif-windows.h */
