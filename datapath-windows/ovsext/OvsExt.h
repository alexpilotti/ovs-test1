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

#ifndef __OVS_EXT_H_
#define __OVS_EXT_H_ 1

typedef union _OVS_PACKET_HDR_INFO OVS_PACKET_HDR_INFO;

/*
 * Data structures and utility functions to help manage a list of packets to be
 * completed (dropped).
 */
typedef struct OvsCompletionList {
    PNET_BUFFER_LIST dropNbl;
    PNET_BUFFER_LIST *dropNblNext;
    PSX_SWITCH_OBJECT sxSwitch;
    ULONG sendCompleteFlags;
} OvsCompletionList;

VOID OvsInitCompletionList(OvsCompletionList *completionList,
                           PSX_SWITCH_OBJECT sxSwitch,
                           ULONG sendCompleteFlags);
VOID OvsAddPktCompletionList(OvsCompletionList *completionList,
                             BOOLEAN incoming,
                             NDIS_SWITCH_PORT_ID sourcePort,
                             PNET_BUFFER_LIST netBufferList,
                             UINT32 netBufferListCount,
                             PNDIS_STRING filterReason);

/*
 * XXX: This may not fit exactly in OvsExt.h. Consider moving this to something
 * like OvsInt.h in the future.
 */
NDIS_STATUS OvsActionsExecute(POVS_SWITCH_CONTEXT switchContext,
                            OvsCompletionList *completionList,
                            PNET_BUFFER_LIST curNbl, UINT32 srcVportNo,
                            ULONG sendFlags, OvsFlowKey *key, UINT64 *hash,
                            OVS_PACKET_HDR_INFO *layers,
                            const struct nlattr *actions, int actionsLen);

VOID OvsLookupFlowOutput(POVS_SWITCH_CONTEXT switchContext,
                         VOID *compList, PNET_BUFFER_LIST curNbl);

#endif /* __OVS_EXT_H_ */
