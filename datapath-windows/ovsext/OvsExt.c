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


/*
 * This file contains the implementation of the datapath/forwarding
 * functionality of the OVS.
 */

#include "precomp.h"
#include "OvsIoctl.h"
#include "OvsSwitch.h"
#include "OvsVport.h"
#include "OvsNetProto.h"
#include "OvsUser.h"
#include "OvsExt.h"
#include "OvsFlow.h"
#include "OvsEvent.h"
#include "OvsUser.h"

/* Due to an imported header file */
#pragma warning( disable:4505 )

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_DISPATCH
#include "OvsDebug.h"

UCHAR SxExtMajorNdisVersion = NDIS_FILTER_MAJOR_VERSION;
UCHAR SxExtMinorNdisVersion = NDIS_FILTER_MINOR_VERSION;
PWCHAR SxExtFriendlyName = L"VMWare OVS Extension";
PWCHAR SxExtUniqueName = L"{f6e4f759-fd07-4def-8c35-14d09103b6b2}";
PWCHAR SxExtServiceName = L"OVSExt";
ULONG SxExtAllocationTag = OVS_MEMORY_TAG;
ULONG SxExtOidRequestId = 'ISVO';

// {f6e4f759-fd07-4def-8c35-14d09103b6b2}

const GUID OVSExtGuid = {
    0xf6e4f759,
    0xfd07,
    0x4def,
    {0x8c, 0x35, 0x14, 0xd0, 0x91, 0x03, 0xb6, 0xb2}
    };

VOID OvsFinalizeCompletionList(OvsCompletionList *completionList);

/* Initialize OVS switch extension */
NDIS_STATUS
SxExtInitialize(NDIS_HANDLE sxDriverHandle)
{
    return OvsCreateDeviceObject(sxDriverHandle);
}


/* Un-initialize OVS switch extension */
VOID
SxExtUninitialize()
{
    OvsDeleteDeviceObject();
}


/*
 * --------------------------------------------------------------------------
 * Data structures and utility functions to help manage a list of packets to be
 * completed (dropped).
 * --------------------------------------------------------------------------
 */
__inline VOID
OvsInitCompletionList(OvsCompletionList *completionList,
                      PSX_SWITCH_OBJECT sxSwitch,
                      ULONG sendCompleteFlags)
{
    ASSERT(completionList);
    completionList->dropNbl = NULL;
    completionList->dropNblNext = &completionList->dropNbl;
    completionList->sxSwitch = sxSwitch;
    completionList->sendCompleteFlags = sendCompleteFlags;
}

/* Utility function to be used to complete an NBL. */
__inline VOID
OvsAddPktCompletionList(OvsCompletionList *completionList,
                        BOOLEAN incoming,
                        NDIS_SWITCH_PORT_ID sourcePort,
                        PNET_BUFFER_LIST netBufferList,
                        UINT32 netBufferListCount,
                        PNDIS_STRING filterReason)
{
    POVS_BUFFER_CONTEXT ctx;

    /* XXX: we handle one NBL at a time */
    ASSERT(netBufferList->Next == NULL);

    /* Make sure it has a context */
    ctx = (POVS_BUFFER_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(netBufferList);
    ASSERT(ctx && ctx->magic == OVS_CTX_MAGIC);

    completionList->sxSwitch->NdisSwitchHandlers.ReportFilteredNetBufferLists(
        completionList->sxSwitch->NdisSwitchContext, &SxExtensionGuid,
        &SxExtensionFriendlyName, sourcePort,
        incoming ? NDIS_SWITCH_REPORT_FILTERED_NBL_FLAGS_IS_INCOMING : 0,
        netBufferListCount, netBufferList, filterReason);

    *completionList->dropNblNext = netBufferList;
    completionList->dropNblNext = &netBufferList->Next;
    ASSERT(completionList->dropNbl);
}

/*
 * --------------------------------------------------------------------------
 * The function sets the destination lists of the NBLs forwarded
 * through the switch.
 * The extension only set destinations for NBLs originated from the External NIC,
 * Internal NIC, or NICs with MAC Policy set.
 * The extension determines the source by searching for the source
 * MAC address in the NIC list.
 *
 * The extension sets destinations by looking at the destination MAC address.
 * If the destination MAC address is a multicast or broadcast address,
 * the extension broadcasts the NBL to all ports, except the source.
 * If the destination MAC is a VM, the extension sets the VM as the destitation.
 * Otherwise the extension sets the External port as the destination.
 *
 * The function sets the destination lists of the NBLs forwarded
 * through the switch.
 *
 * The extension consults with a flow based policy managed by user mode OVS.
 * --------------------------------------------------------------------------
 */
VOID
SxExtStartNetBufferListsIngress(PSX_SWITCH_OBJECT sxSwitch,
                   NDIS_HANDLE extensionContext,
                   PNET_BUFFER_LIST NetBufferLists,
                   ULONG SendFlags)
{
    POVS_SWITCH_CONTEXT switchContext = (POVS_SWITCH_CONTEXT)extensionContext;
    NDIS_SWITCH_PORT_ID sourcePort = 0;
    NDIS_SWITCH_NIC_INDEX sourceIndex = 0;
    PNDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO fwdDetail;
    PNET_BUFFER_LIST curNbl = NULL, nextNbl = NULL;
    ULONG sendCompleteFlags = 0;
    UCHAR dispatch;
    LOCK_STATE_EX lockState, dpLockState;
    NDIS_STATUS status;
    NDIS_STRING filterReason;
    LIST_ENTRY missedPackets;
    UINT32 num = 0;
    OvsCompletionList completionList;

    dispatch = NDIS_TEST_SEND_FLAG(SendFlags, NDIS_SEND_FLAGS_DISPATCH_LEVEL) ?
               NDIS_RWL_AT_DISPATCH_LEVEL : 0;
    sendCompleteFlags |= (dispatch == NDIS_RWL_AT_DISPATCH_LEVEL) ?
                         NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL : 0;
    SendFlags |= NDIS_SEND_FLAGS_SWITCH_DESTINATION_GROUP;

    InitializeListHead(&missedPackets);
    OvsInitCompletionList(&completionList, sxSwitch, sendCompleteFlags);

    for (curNbl = NetBufferLists; curNbl != NULL; curNbl = nextNbl) {
        POVS_VPORT_ENTRY vport;
        UINT32 portNo;
        OVS_DATAPATH *datapath = &switchContext->datapath;
        OVS_PACKET_HDR_INFO layers;
        OvsFlowKey key;
        UINT64 hash;
        PNET_BUFFER curNb;

        nextNbl = curNbl->Next;
        curNbl->Next = NULL;

        fwdDetail = NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(curNbl);

        /* Ethernet Header is a guaranteed safe access. */
        curNb = NET_BUFFER_LIST_FIRST_NB(curNbl);
        if (curNb->Next != NULL) {
            /* XXX: This case is not handled yet. */
            ASSERT(FALSE);
        } else {
            POVS_BUFFER_CONTEXT ctx;
            OvsFlow *flow;

            fwdDetail = NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(curNbl);
            sourcePort = fwdDetail->SourcePortId;
            sourceIndex = (NDIS_SWITCH_NIC_INDEX)fwdDetail->SourceNicIndex;

            /*
             * Take the DispatchLock so none of the VPORTs disconnect while we're setting
             * destination ports.
             *
             * XXX: acquire/release the dispatch lock for a "batch" of packets rather
             * than for each packet.
             */
            NdisAcquireRWLockRead(switchContext->dispatchLock, &lockState, dispatch);

            ctx = OvsInitExternalNBLContext(switchContext, curNbl,
                    sourcePort == switchContext->externalPortId);
            if (ctx == NULL) {
                RtlInitUnicodeString(&filterReason, L"cannot allocate context");

                SxLibCompleteNetBufferListsIngress(sxSwitch, curNbl,
                                           SendFlags);
                NdisReleaseRWLock(switchContext->dispatchLock, &lockState);
                continue;
            }

            vport = OvsFindVportByPortIdAndNicIndex(switchContext, sourcePort,
                                                    sourceIndex);
            if (vport == NULL || vport->ovsState != OVS_STATE_CONNECTED) {
                RtlInitUnicodeString(&filterReason,
                    L"OVS-Cannot forward packet from unknown source port");
                goto dropit;
            } else {
                portNo = vport->portNo;
            }

            vport->stats.rxPackets++;
            vport->stats.rxBytes += NET_BUFFER_DATA_LENGTH(curNb);

            status = OvsExtractFlow(curNbl, vport->portNo, &key, &layers, NULL);
            if (status != NDIS_STATUS_SUCCESS) {
                RtlInitUnicodeString(&filterReason, L"OVS-Flow extract failed");
                goto dropit;
            }

            /* Lock the flowtable for the duration of accessing the flow */
            ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
            OvsAcquireDatapathRead(datapath, &dpLockState,
                                   NDIS_RWL_AT_DISPATCH_LEVEL);

            flow = OvsLookupFlow(datapath, &key, &hash, FALSE);
            if (flow) {
                OvsFlowUsed(flow, curNbl, &layers);
                datapath->hits++;
                /*
                 * If successful, OvsActionsExecute() consumes the NBL. Otherwise,
                 * it adds it to the completionList. No need to check the return
                 * value.
                 */
                OvsActionsExecute(switchContext, &completionList, curNbl,
                                portNo, SendFlags, &key, &hash, &layers,
                                flow->actions, flow->actionsLen);
                OvsReleaseDatapath(datapath, &dpLockState);
                NdisReleaseRWLock(switchContext->dispatchLock, &lockState);
                continue;
            } else {
                OvsReleaseDatapath(datapath, &dpLockState);

                datapath->misses++;
                status = OvsCreateAndAddPackets(OVS_DEFAULT_PACKET_QUEUE,
                                                NULL, 0, OVS_PACKET_CMD_MISS,
                                                portNo,
                                                key.tunKey.dst != 0 ?
                                                (OvsIPv4TunnelKey *)&key.tunKey :
                                                NULL, curNbl,
                                                sourcePort ==
                                                switchContext->externalPortId,
                                                &layers, switchContext,
                                                &missedPackets, &num);
                if (status == NDIS_STATUS_SUCCESS) {
                    /* Complete the packet since it was copied to user buffer. */
                    RtlInitUnicodeString(&filterReason,
                        L"OVS-Dropped since packet was copied to userspace");
                } else {
                    RtlInitUnicodeString(&filterReason,
                        L"OVS-Dropped due to failure to queue to userspace");
                }
                goto dropit;
            }

dropit:
            OvsAddPktCompletionList(&completionList, TRUE, sourcePort, curNbl, 0,
                                    &filterReason);
            NdisReleaseRWLock(switchContext->dispatchLock, &lockState);
        }
    }

    /* Queue the missed packets */
    OvsQueuePackets(OVS_DEFAULT_PACKET_QUEUE, &missedPackets, num);
    OvsFinalizeCompletionList(&completionList);
}


/* Utility function to send NBL on the egress path */
_Use_decl_annotations_
VOID
SxExtStartNetBufferListsEgress(PSX_SWITCH_OBJECT sxSwitch,
                  NDIS_HANDLE ExtensionContext,
                  PNET_BUFFER_LIST NetBufferLists,
                  ULONG NumberOfNetBufferLists,
                  ULONG ReceiveFlags)
{
    UNREFERENCED_PARAMETER(ExtensionContext);

    SxLibSendNetBufferListsEgress(sxSwitch,
                                  NetBufferLists,
                                  NumberOfNetBufferLists,
                                  ReceiveFlags);
}


/* Complete the egress NBL */
_Use_decl_annotations_
VOID
SxExtStartCompleteNetBufferListsEgress(PSX_SWITCH_OBJECT sxSwitch,
                     NDIS_HANDLE ExtensionContext,
                     PNET_BUFFER_LIST NetBufferLists,
                     ULONG ReturnFlags)
{
    UNREFERENCED_PARAMETER(ExtensionContext);

    SxLibCompleteNetBufferListsEgress(sxSwitch,
                                      NetBufferLists,
                                      ReturnFlags);
}

/* Complete the ingress NBL */
_Use_decl_annotations_
VOID
SxExtStartCompleteNetBufferListsIngress(PSX_SWITCH_OBJECT Switch,
                      NDIS_HANDLE ExtensionContext,
                      PNET_BUFFER_LIST NetBufferLists,
                      ULONG SendCompleteFlags)
{
    POVS_SWITCH_CONTEXT switchContext = ExtensionContext;
    PNET_BUFFER_LIST curNbl = NULL, nextNbl = NULL;
    OvsCompletionList newList;

    newList.dropNbl = NULL;
    newList.dropNblNext = &newList.dropNbl;

    for (curNbl = NetBufferLists; curNbl != NULL; curNbl = nextNbl) {
        nextNbl = curNbl->Next;
        curNbl->Next = NULL;

        curNbl = OvsCompleteNBL(switchContext, curNbl, TRUE);
        if (curNbl != NULL) {
            *newList.dropNblNext = curNbl;
            newList.dropNblNext = &curNbl->Next;
        }
    }

    /* Now return everything that needs to goto the upper layer */
    if (newList.dropNbl != NULL) {
        SxLibCompleteNetBufferListsIngress(Switch, newList.dropNbl,
                                           SendCompleteFlags);
    }
}

VOID
OvsFinalizeCompletionList(OvsCompletionList *completionList)
{
    if (completionList->dropNbl != NULL) {
        SxExtStartCompleteNetBufferListsIngress(completionList->sxSwitch,
                completionList->sxSwitch->ExtensionContext,
                completionList->dropNbl, completionList->sendCompleteFlags);
        completionList->dropNbl = NULL;
        completionList->dropNblNext = &completionList->dropNbl;
    }
}
