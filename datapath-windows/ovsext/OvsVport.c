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

#include "precomp.h"
#include "lib/jhash.h"
#include "OvsIoctl.h"
#include "OvsSwitch.h"
#include "OvsVport.h"
#include "OvsEvent.h"
#include "OvsUser.h"
#include "OvsVxlan.h"
#include "OvsIpHelper.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_VPORT
#include "OvsDebug.h"

#define VPORT_ENTER(_nic) \
    OVS_LOG_TRACE("<= PortId: %x, NicIndex: %d", _nic->PortId, _nic->NicIndex)

#define VPORT_EXIT(_nic) \
    OVS_LOG_TRACE("=> PortId: %x, NicIndex: %d", _nic->PortId, _nic->NicIndex)

extern POVS_SWITCH_CONTEXT ovsSwitchContext;
extern PNDIS_SPIN_LOCK ovsCtrlLock;

/* NOTE: All API's prefixed with SxExt are kept the same so that the base code
 * remains unchanged.
 */

static UINT32 OvsGetVportNo(POVS_SWITCH_CONTEXT switchContext, UINT32 nicIndex,
                            OVS_VPORT_TYPE ovsType);
static POVS_VPORT_ENTRY OvsAllocateVport(VOID);
static VOID OvsInitVportWithPortParam(POVS_VPORT_ENTRY vport,
                PNDIS_SWITCH_PORT_PARAMETERS portParam);
static VOID OvsInitVportWithNicParam(POVS_SWITCH_CONTEXT switchContext,
                POVS_VPORT_ENTRY vport, PNDIS_SWITCH_NIC_PARAMETERS nicParam);
static VOID OvsInitPhysNicVport(POVS_VPORT_ENTRY vport, POVS_VPORT_ENTRY
                virtVport, UINT32 nicIndex);
static VOID OvsInitPhysNicVport(POVS_VPORT_ENTRY vport, POVS_VPORT_ENTRY
                virtVport, UINT32 nicIndex);
static NDIS_STATUS OvsInitVportCommon(POVS_SWITCH_CONTEXT switchContext,
                POVS_VPORT_ENTRY vport);
static VOID OvsRemoveAndDeleteVport(POVS_SWITCH_CONTEXT switchContext,
                POVS_VPORT_ENTRY vport);


_Use_decl_annotations_
NDIS_STATUS
SxExtCreatePort(PSX_SWITCH_OBJECT sxSwitch,
                NDIS_HANDLE extensionContext,
                PNDIS_SWITCH_PORT_PARAMETERS portParam)
{
    POVS_SWITCH_CONTEXT switchContext = (POVS_SWITCH_CONTEXT)extensionContext;
    POVS_VPORT_ENTRY vport;
    LOCK_STATE_EX lockState;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;


    OVS_LOG_TRACE("==> sxSwitch: %p, swicthContext%p, Create port: portId: %x",
                  sxSwitch, switchContext, (UINT32)portParam->PortId);

    NdisAcquireRWLockWrite(switchContext->dispatchLock, &lockState, 0);
    vport = OvsFindVportByPortIdAndNicIndex(switchContext,
                                            portParam->PortId, 0);
    if (vport != NULL) {
        status = STATUS_DATA_NOT_ACCEPTED;
        goto create_port_done;
    }
    vport = (POVS_VPORT_ENTRY)OvsAllocateVport();
    if (vport == NULL) {
        status = NDIS_STATUS_RESOURCES;
        goto create_port_done;
    }
    OvsInitVportWithPortParam(vport, portParam);
    OvsInitVportCommon(switchContext, vport);

create_port_done:
    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);
    OVS_LOG_TRACE("<== Create port:%x status: %#x", portParam->PortId, status);
    return status;
}

_Use_decl_annotations_
VOID
SxExtUpdatePort(PSX_SWITCH_OBJECT sxSwitch,
                NDIS_HANDLE extensionContext,
                PNDIS_SWITCH_PORT_PARAMETERS portParam)
{
    POVS_SWITCH_CONTEXT switchContext = (POVS_SWITCH_CONTEXT)extensionContext;
    POVS_VPORT_ENTRY vport;
    LOCK_STATE_EX lockState;

    UNREFERENCED_PARAMETER(sxSwitch);

    OVS_LOG_TRACE("==> sxSwitch:%p switchContext:%p, Switch Port Update: %x",
                  sxSwitch, switchContext, portParam->PortId);

    NdisAcquireRWLockWrite(switchContext->dispatchLock, &lockState, 0);
    vport = OvsFindVportByPortIdAndNicIndex(switchContext,
                                            portParam->PortId, 0);
    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);
    OVS_LOG_WARN("<== Vport to be updated:%p, portId: %x",
                 vport, (UINT32)portParam->PortId);
}

_Use_decl_annotations_
VOID
SxExtTeardownPort(PSX_SWITCH_OBJECT sxSwitch,
                  NDIS_HANDLE extensionContext,
                  PNDIS_SWITCH_PORT_PARAMETERS portParam)
{
    POVS_SWITCH_CONTEXT switchContext = (POVS_SWITCH_CONTEXT)extensionContext;
    POVS_VPORT_ENTRY vport;
    LOCK_STATE_EX lockState;

    OVS_LOG_TRACE("==> sxSwitch:%p switchContext:%p, Switch Port tear down: %x",
                  sxSwitch, switchContext, portParam->PortId);

    NdisAcquireRWLockWrite(switchContext->dispatchLock, &lockState, 0);
    vport = OvsFindVportByPortIdAndNicIndex(switchContext,
                                            portParam->PortId, 0);
    if (vport) {
        /* add assertion here
         */
        vport->portState = NdisSwitchPortStateTeardown;
        vport->ovsState = OVS_STATE_PORT_TEAR_DOWN;
    }
    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);

    OVS_LOG_TRACE("<== vport: %p teardown, portID:%x", vport,
                  portParam->PortId);
}



_Use_decl_annotations_
VOID
SxExtDeletePort(PSX_SWITCH_OBJECT sxSwitch,
                NDIS_HANDLE extensionContext,
                PNDIS_SWITCH_PORT_PARAMETERS portParam)
{
    POVS_SWITCH_CONTEXT switchContext = (POVS_SWITCH_CONTEXT)extensionContext;
    POVS_VPORT_ENTRY vport;
    LOCK_STATE_EX lockState;

    OVS_LOG_TRACE("==> sxSwitch:%p switchContext:%p, Switch Port delete: %x",
                  sxSwitch, switchContext, portParam->PortId);

    NdisAcquireRWLockWrite(switchContext->dispatchLock, &lockState, 0);
    vport = OvsFindVportByPortIdAndNicIndex(switchContext,
                                            portParam->PortId, 0);
    if (vport) {
        OvsRemoveAndDeleteVport(switchContext, vport);
    }
    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);
    OVS_LOG_TRACE("<== vport: %p deleted, portID: %x", vport,
                  portParam->PortId);
}



_Use_decl_annotations_
NDIS_STATUS
SxExtCreateNic(PSX_SWITCH_OBJECT sxSwitch,
               NDIS_HANDLE extensionContext,
               PNDIS_SWITCH_NIC_PARAMETERS nicParam)
{
    POVS_SWITCH_CONTEXT switchContext = (POVS_SWITCH_CONTEXT)extensionContext;
    POVS_VPORT_ENTRY vport;
    UINT32 portNo = 0;
    UINT32 event = 0;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    LOCK_STATE_EX lockState;

    OVS_LOG_TRACE("==> sxSwitch:%p switchContext:%p, nic create: %x-%x",
                  sxSwitch, switchContext, nicParam->PortId);

    VPORT_ENTER(nicParam);
    /*
     * Wait for lists to be initialized.
     */
    while (!switchContext->isActivated && !switchContext->isActivateFailed) {
        NdisMSleep(100);
    }
    if (!switchContext->isActivated) {
        /*
         * XXX shall we fail here ?
         */
        VPORT_EXIT(nicParam);
        return NDIS_STATUS_SUCCESS;
    }

    NdisAcquireRWLockWrite(switchContext->dispatchLock, &lockState, 0);
    vport = OvsFindVportByPortIdAndNicIndex(switchContext, nicParam->PortId, 0);
    if (vport == NULL) {
        OVS_LOG_ERROR("Create NIC without Switch Port,"
                      " PortId: %x, NicIndex: %d",
                      nicParam->PortId, nicParam->NicIndex);
        status = NDIS_STATUS_INVALID_PARAMETER;
        goto add_nic_done;
    }

    if (nicParam->NicType == NdisSwitchNicTypeExternal &&
        nicParam->NicIndex != 0) {
        POVS_VPORT_ENTRY virtVport =
            (POVS_VPORT_ENTRY)switchContext->externalVport;
        vport = (POVS_VPORT_ENTRY)OvsAllocateVport();
        if (vport == NULL) {
            status = NDIS_STATUS_RESOURCES;
            goto add_nic_done;
        }
        OvsInitPhysNicVport(vport, virtVport, nicParam->NicIndex);
        status = OvsInitVportCommon(switchContext, vport);
        if (status != NDIS_STATUS_SUCCESS) {
            OvsFreeMemory(vport);
            goto add_nic_done;
        }
    }
    OvsInitVportWithNicParam(switchContext, vport, nicParam);
    portNo = vport->portNo;
    if (vport->ovsState == OVS_STATE_CONNECTED) {
        event = OVS_EVENT_CONNECT | OVS_EVENT_LINK_UP;
    } else if (vport->ovsState == OVS_STATE_NIC_CREATED) {
        event = OVS_EVENT_CONNECT;
    }

add_nic_done:
    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);
    if (portNo && event) {
        OvsPostEvent(portNo, event);
    }
    VPORT_EXIT(nicParam);
    return status;
}


/* Mark already created NIC as connected. */
_Use_decl_annotations_
VOID
SxExtConnectNic(PSX_SWITCH_OBJECT sxSwitch,
                NDIS_HANDLE extensionContext,
                PNDIS_SWITCH_NIC_PARAMETERS nicParam)
{
    POVS_SWITCH_CONTEXT switchContext = (POVS_SWITCH_CONTEXT)extensionContext;
    LOCK_STATE_EX lockState;
    POVS_VPORT_ENTRY vport;
    UINT32 portNo = 0;

    UNREFERENCED_PARAMETER(sxSwitch);
    VPORT_ENTER(nicParam);

    //
    // Wait for lists to be initialized.
    //
    while (!switchContext->isActivated && !switchContext->isActivateFailed) {
        NdisMSleep(100);
    }
    if (!switchContext->isActivated) {
        VPORT_EXIT(nicParam);
        return;
    }

    NdisAcquireRWLockWrite(switchContext->dispatchLock, &lockState, 0);
    vport = OvsFindVportByPortIdAndNicIndex(switchContext,
                                            nicParam->PortId,
                                            nicParam->NicIndex);
    if (vport) {
        vport->ovsState = OVS_STATE_CONNECTED;
        vport->nicState = NdisSwitchNicStateConnected;
        portNo = vport->portNo;
    }
    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);
    if (portNo) {
        OvsPostEvent(portNo, OVS_EVENT_LINK_UP);
    }
    if (nicParam->NicType == NdisSwitchNicTypeInternal) {
        OvsInternalAdapterUp(portNo, &nicParam->NetCfgInstanceId);
    }
    VPORT_EXIT(nicParam);
}


_Use_decl_annotations_
VOID
SxExtUpdateNic(PSX_SWITCH_OBJECT sxSwitch,
               NDIS_HANDLE extensionContext,
               PNDIS_SWITCH_NIC_PARAMETERS nicParam)
{
    POVS_SWITCH_CONTEXT switchContext = (POVS_SWITCH_CONTEXT)extensionContext;
    POVS_VPORT_ENTRY vport;
    LOCK_STATE_EX lockState;

    UINT32 status = 0, portNo = 0;
    UNREFERENCED_PARAMETER(sxSwitch);

    VPORT_ENTER(nicParam);
    /*
     * Wait for lists to be initialized.
     */
    while (!switchContext->isActivated && !switchContext->isActivateFailed) {
        NdisMSleep(100);
    }
    if (!switchContext->isActivated) {
        VPORT_EXIT(nicParam);
        return;
    }

    NdisAcquireRWLockWrite(switchContext->dispatchLock, &lockState, 0);
    vport = OvsFindVportByPortIdAndNicIndex(switchContext,
                                            nicParam->PortId,
                                            nicParam->NicIndex);
    if (vport == NULL) {
        goto update_nic_done;
    }
    switch (nicParam->NicType) {
    case NdisSwitchNicTypeExternal:
    case NdisSwitchNicTypeInternal:
        RtlCopyMemory(&vport->netCfgInstanceId, &nicParam->NetCfgInstanceId,
                      sizeof (GUID));
        break;
    case NdisSwitchNicTypeSynthetic:
    case NdisSwitchNicTypeEmulated:
        if (!RtlEqualMemory(vport->vmMacAddress, nicParam->VMMacAddress,
                           sizeof (vport->vmMacAddress))) {
            status |= OVS_EVENT_MAC_CHANGE;
            RtlCopyMemory(vport->vmMacAddress, nicParam->VMMacAddress,
                          sizeof (vport->vmMacAddress));
        }
        break;
    default:
        ASSERT(0);
    }
    if (!RtlEqualMemory(vport->permMacAddress, nicParam->PermanentMacAddress,
                        sizeof (vport->permMacAddress))) {
        RtlCopyMemory(vport->permMacAddress, nicParam->PermanentMacAddress,
                      sizeof (vport->permMacAddress));
        status |= OVS_EVENT_MAC_CHANGE;
    }
    if (!RtlEqualMemory(vport->currMacAddress, nicParam->CurrentMacAddress,
                        sizeof (vport->currMacAddress))) {
        RtlCopyMemory(vport->currMacAddress, nicParam->CurrentMacAddress,
                      sizeof (vport->currMacAddress));
        status |= OVS_EVENT_MAC_CHANGE;
    }

    if (vport->mtu != nicParam->MTU) {
        vport->mtu = nicParam->MTU;
        status |= OVS_EVENT_MTU_CHANGE;
    }
    vport->numaNodeId = nicParam->NumaNodeId;
    portNo = vport->portNo;

    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);
    if (status && portNo) {
        OvsPostEvent(portNo, status);
    }
update_nic_done:
    VPORT_EXIT(nicParam);
}


_Use_decl_annotations_
VOID
SxExtDisconnectNic(PSX_SWITCH_OBJECT sxSwitch,
                   NDIS_HANDLE extensionContext,
                   PNDIS_SWITCH_NIC_PARAMETERS nicParam)
{
    POVS_SWITCH_CONTEXT switchContext = (POVS_SWITCH_CONTEXT)extensionContext;

    POVS_VPORT_ENTRY vport;
    UINT32 portNo = 0;
    LOCK_STATE_EX lockState;
    BOOLEAN isInternalPort = FALSE;

    UNREFERENCED_PARAMETER(sxSwitch);
    VPORT_ENTER(nicParam);

    /*
     * Wait for lists to be initialized.
     */
    while (!switchContext->isActivated && !switchContext->isActivateFailed) {
        NdisMSleep(100);
    }
    if (!switchContext->isActivated) {
        VPORT_EXIT(nicParam);
        return;
    }

    NdisAcquireRWLockWrite(switchContext->dispatchLock, &lockState, 0);
    vport = OvsFindVportByPortIdAndNicIndex(switchContext,
                                            nicParam->PortId,
                                            nicParam->NicIndex);
    if (vport) {
        vport->nicState = NdisSwitchNicStateDisconnected;
        vport->ovsState = OVS_STATE_NIC_CREATED;
        portNo = vport->portNo;
        if (vport->ovsType == OVSWIN_VPORT_TYPE_INTERNAL) {
            isInternalPort = TRUE;
        }
    }
    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);
    if (portNo) {
        OvsPostEvent(portNo, OVS_EVENT_LINK_DOWN);
    }
    if (isInternalPort) {
        OvsInternalAdapterDown();
    }
    VPORT_EXIT(nicParam);
}


_Use_decl_annotations_
VOID
SxExtDeleteNic(PSX_SWITCH_OBJECT sxSwitch,
               NDIS_HANDLE extensionContext,
               PNDIS_SWITCH_NIC_PARAMETERS nicParam)
{
    POVS_SWITCH_CONTEXT switchContext = (POVS_SWITCH_CONTEXT)extensionContext;
    LOCK_STATE_EX lockState;
    POVS_VPORT_ENTRY vport;
    UINT32 portNo = 0;

    UNREFERENCED_PARAMETER(sxSwitch);

    VPORT_ENTER(nicParam);
    /*
     * Wait for lists to be initialized.
     */
    while (!switchContext->isActivated && !switchContext->isActivateFailed) {
        NdisMSleep(100);
    }
    if (!switchContext->isActivated) {
        VPORT_EXIT(nicParam);
        return;
    }

    NdisAcquireRWLockWrite(switchContext->dispatchLock, &lockState, 0);
    vport = OvsFindVportByPortIdAndNicIndex(switchContext,
                                            nicParam->PortId,
                                            nicParam->NicIndex);
    if (vport) {
        portNo = vport->portNo;
        if (vport->portType == NdisSwitchPortTypeExternal &&
            vport->nicIndex != 0) {
            OvsRemoveAndDeleteVport(switchContext, vport);
        }
        vport->nicState = NdisSwitchNicStateUnknown;
        vport->ovsState = OVS_STATE_PORT_CREATED;
    }

    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);
    if (portNo) {
        OvsPostEvent(portNo, OVS_EVENT_DISCONNECT);
    }
    VPORT_EXIT(nicParam);
}


_Use_decl_annotations_
NDIS_STATUS
SxExtSaveNic(PSX_SWITCH_OBJECT sxSwitch,
             NDIS_HANDLE extensionContext,
             PNDIS_SWITCH_NIC_SAVE_STATE saveState,
             PULONG bytesWritten,
             PULONG bytesNeeded)
{
    UNREFERENCED_PARAMETER(sxSwitch);
    UNREFERENCED_PARAMETER(extensionContext);
    UNREFERENCED_PARAMETER(saveState);
    /*
     * XXX  need to support it later for vMotion Support
     */

    *bytesWritten = 0;
    *bytesNeeded = 0;
    OVS_LOG_TRACE("Save Context, to be implemented");
    return NDIS_STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
SxExtSaveNicComplete(PSX_SWITCH_OBJECT sxSwitch,
                     NDIS_HANDLE extensionContext,
                     PNDIS_SWITCH_NIC_SAVE_STATE saveState)
{
    UNREFERENCED_PARAMETER(sxSwitch);
    UNREFERENCED_PARAMETER(extensionContext);
    UNREFERENCED_PARAMETER(saveState);
    /*
     * XXX need to support it later to support vMotion
     */
    OVS_LOG_TRACE("Save Context Complete, to be implemented");
}


_Use_decl_annotations_
NDIS_STATUS
SxExtNicRestore(PSX_SWITCH_OBJECT sxSwitch,
                NDIS_HANDLE extensionContext,
                PNDIS_SWITCH_NIC_SAVE_STATE saveState,
                PULONG bytesRestored)
{
    UNREFERENCED_PARAMETER(sxSwitch);
    UNREFERENCED_PARAMETER(extensionContext);
    UNREFERENCED_PARAMETER(saveState);

    *bytesRestored = 0;
    /*
     * XXX need to support it later to support vMotion
     */
    OVS_LOG_TRACE("Restore Context, to be implemented");
    return NDIS_STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
SxExtNicRestoreComplete(PSX_SWITCH_OBJECT sxSwitch,
                        NDIS_HANDLE extensionContext,
                        PNDIS_SWITCH_NIC_SAVE_STATE saveState)
{
    UNREFERENCED_PARAMETER(sxSwitch);
    UNREFERENCED_PARAMETER(extensionContext);
    UNREFERENCED_PARAMETER(saveState);
    /*
     * XXX need to support it later to support vMotion
     */
    OVS_LOG_TRACE("Restore Context Complete, to be implemented");
}

/*
 * --------------------------------------------------------------------------
 * The only NIC request this extension cares about is
 * OID_NIC_SWITCH_ALLOCATE_VF. We must fail all VF allocations so that traffic
 * flows through the extension and we can enforce policy.
 * --------------------------------------------------------------------------
 */
_Use_decl_annotations_
NDIS_STATUS
SxExtProcessNicRequest(PSX_SWITCH_OBJECT sxSwitch,
                       NDIS_HANDLE extensionContext,
                       PNDIS_OID_REQUEST oidRequest,
                       PNDIS_SWITCH_PORT_ID sourcePortId,
                       PNDIS_SWITCH_NIC_INDEX sourceNicIndex,
                       PNDIS_SWITCH_PORT_ID destinationPortId,
                       PNDIS_SWITCH_NIC_INDEX destinationNicIndex)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(sxSwitch);
    UNREFERENCED_PARAMETER(extensionContext);
    /*
     * Do not allow VF allocations, as all VM traffic must flow
     * through our extension.
     */
    OVS_LOG_TRACE("=> SrcPortId: %x, SrcNicIndex: %d, DstPortId: %x, "
                  "DstNicIndex: %d", *sourcePortId, *sourceNicIndex,
                  *destinationPortId, *destinationNicIndex);

    if (oidRequest->RequestType == NdisRequestSetInformation &&
        oidRequest->DATA.SET_INFORMATION.Oid == OID_NIC_SWITCH_ALLOCATE_VF) {
        OVS_LOG_INFO("Request to allocate VF");
        status = NDIS_STATUS_FAILURE;
    }

    OVS_LOG_TRACE("<= SrcPortId: %x, SrcNicIndex: %d, DstPortId: %x, "
                  "DstNicIndex: %d", *sourcePortId, *sourceNicIndex,
                  *destinationPortId, *destinationNicIndex);

    return status;
}


/*
 * --------------------------------------------------------------------------
 * This function will never be called because we do not redirect or edit any
 * NIC requests.
 * --------------------------------------------------------------------------
 */
_Use_decl_annotations_
NDIS_STATUS
SxExtProcessNicRequestComplete(PSX_SWITCH_OBJECT sxSwitch,
                               NDIS_HANDLE extensionContext,
                               PNDIS_OID_REQUEST oidRequest,
                               NDIS_SWITCH_PORT_ID sourcePortId,
                               NDIS_SWITCH_NIC_INDEX sourceNicIndex,
                               NDIS_SWITCH_PORT_ID destinationPortId,
                               NDIS_SWITCH_NIC_INDEX destinationNicIndex,
                               NDIS_STATUS status)
{
    UNREFERENCED_PARAMETER(sxSwitch);
    UNREFERENCED_PARAMETER(extensionContext);
    UNREFERENCED_PARAMETER(oidRequest);
    UNREFERENCED_PARAMETER(sourcePortId);
    UNREFERENCED_PARAMETER(sourceNicIndex);
    UNREFERENCED_PARAMETER(destinationPortId);
    UNREFERENCED_PARAMETER(destinationNicIndex);
    UNREFERENCED_PARAMETER(status);

    /*
     * This function should never be called as we don't set any
     * source/destination info in SxExtProcessNicRequest.
     */
    ASSERT(FALSE);
    OVS_LOG_TRACE("SrcPortId: %x, SrcNicIndex: %d, DstPortId: %x, "
                  "DstNicIndex: %d status: %#x", sourcePortId, sourceNicIndex,
                  destinationPortId, destinationNicIndex, status);

    return status;
}


_Use_decl_annotations_
NDIS_STATUS
SxExtProcessNicStatus(PSX_SWITCH_OBJECT sxSwitch,
                      NDIS_HANDLE extensionContext,
                      PNDIS_STATUS_INDICATION statusIndication,
                      NDIS_SWITCH_PORT_ID sourcePortId,
                      NDIS_SWITCH_NIC_INDEX sourceNicIndex)
{
    UNREFERENCED_PARAMETER(sxSwitch);
    UNREFERENCED_PARAMETER(extensionContext);
    UNREFERENCED_PARAMETER(statusIndication);
    UNREFERENCED_PARAMETER(sourcePortId);
    UNREFERENCED_PARAMETER(sourceNicIndex);
    /*
     * XXX to be implemeneted as necessary
     */
    OVS_LOG_TRACE("SrcPortId: %x, SrcNicIndex: %d",
                  sourcePortId, sourceNicIndex);
    return NDIS_STATUS_SUCCESS;
}

/*
 * New API's implemented by the extension.
 */

POVS_VPORT_ENTRY
OvsFindVportByPortNo(POVS_SWITCH_CONTEXT switchContext,
                     UINT32 portNo)
{
    if (OVS_VPORT_INDEX(portNo) < OVS_MAX_VPORT_ARRAY_SIZE) {
        if (OVS_IS_VPORT_ENTRY_NULL(switchContext, OVS_VPORT_INDEX(portNo))) {
            return NULL;
        } else {
            POVS_VPORT_ENTRY vport;
            vport = (POVS_VPORT_ENTRY)
                     switchContext->vportArray[OVS_VPORT_INDEX(portNo)];
            return vport->portNo == portNo ? vport : NULL;
        }
    }
    return NULL;
}


POVS_VPORT_ENTRY
OvsFindVportByOvsName(POVS_SWITCH_CONTEXT switchContext,
                      CHAR *name,
                      UINT32 length)
{
    POVS_VPORT_ENTRY vport;
    PLIST_ENTRY head, link;
    UINT32 hash = jhash_bytes((const VOID *)name, length, OVS_HASH_BASIS);
    head = &(switchContext->nameHashArray[hash & OVS_VPORT_MASK]);
    LIST_FORALL(head, link) {
        vport = CONTAINING_RECORD(link, OVS_VPORT_ENTRY, nameLink);
        if (vport->ovsNameLen == length &&
            RtlEqualMemory(name, vport->ovsName, length)) {
            return vport;
        }
    }
    return NULL;
}

POVS_VPORT_ENTRY
OvsFindVportByPortIdAndNicIndex(POVS_SWITCH_CONTEXT switchContext,
                                NDIS_SWITCH_PORT_ID portId,
                                NDIS_SWITCH_NIC_INDEX index)
{
    if (portId == switchContext->externalPortId) {
        if (index == 0) {
            return (POVS_VPORT_ENTRY)switchContext->externalVport;
        } else if (index > OVS_MAX_PHYS_ADAPTERS) {
            return NULL;
        }
        if (OVS_IS_VPORT_ENTRY_NULL(switchContext,
                                    index + OVS_EXTERNAL_VPORT_START)) {
           return NULL;
        } else {
           return (POVS_VPORT_ENTRY)switchContext->vportArray[
                            index + OVS_EXTERNAL_VPORT_START];
        }
    } else if (switchContext->internalPortId == portId) {
        return (POVS_VPORT_ENTRY)switchContext->internalVport;
    } else {
        PLIST_ENTRY head, link;
        POVS_VPORT_ENTRY vport;
        UINT32 hash;
        hash = jhash_words((UINT32 *)&portId, 1, OVS_HASH_BASIS);
        head = &(switchContext->portHashArray[hash & OVS_VPORT_MASK]);
        LIST_FORALL(head, link) {
            vport = CONTAINING_RECORD(link, OVS_VPORT_ENTRY, portLink);
            if (portId == vport->portId && index == vport->nicIndex) {
                return vport;
            }
        }
        return NULL;
    }
}

static UINT32
OvsGetVportNo(POVS_SWITCH_CONTEXT switchContext,
              UINT32 nicIndex,
              OVS_VPORT_TYPE ovsType)
{
    UINT32 index = 0xffffff, i = 0;
    UINT64 gen;

    switch (ovsType) {
    case OVSWIN_VPORT_TYPE_EXTERNAL:
        if (nicIndex == 0) {
            return 0;  // not a valid portNo
        } else if (nicIndex > OVS_MAX_PHYS_ADAPTERS) {
            return 0;
        } else {
            index = nicIndex + OVS_EXTERNAL_VPORT_START;
        }
        break;
    case OVSWIN_VPORT_TYPE_INTERNAL:
        index = OVS_INTERNAL_VPORT_DEFAULT_INDEX;
        break;
    case OVSWIN_VPORT_TYPE_SYNTHETIC:
    case OVSWIN_VPORT_TYPE_EMULATED:
        index = switchContext->lastPortIndex + 1;
        if (index == OVS_MAX_VPORT_ARRAY_SIZE) {
            index = OVS_VM_VPORT_START;
        }
        while (!OVS_IS_VPORT_ENTRY_NULL(switchContext, index) &&
               i < (OVS_MAX_VPORT_ARRAY_SIZE - OVS_VM_VPORT_START)) {
            index++;
            i++;
            if (index == OVS_MAX_VPORT_ARRAY_SIZE) {
                index = OVS_VM_VPORT_START;
            }
        }
        if (i == (OVS_MAX_VPORT_ARRAY_SIZE - OVS_VM_VPORT_START)) {
            return 0; // not available
        }
        switchContext->lastPortIndex = index;
        break;
    case OVSWIN_VPORT_TYPE_GRE:
        index = OVS_GRE_VPORT_INDEX;
        break;
    case OVSWIN_VPORT_TYPE_GRE64:
        index = OVS_GRE64_VPORT_INDEX;
        break;
    case OVSWIN_VPORT_TYPE_VXLAN:
        index = OVS_VXLAN_VPORT_INDEX;
        break;
    case OVSWIN_VPORT_TYPE_LOCAL:
    default:
        ASSERT(0);
    }
    if (index > OVS_MAX_VPORT_ARRAY_SIZE) {
        return 0;
    }
    gen = (UINT64)switchContext->vportArray[index];
    if (gen > 0xff) {
        return 0;
    } else if (gen == 0) {
        gen++;
    }
    return OVS_VPORT_PORT_NO(index, (UINT32)gen);
}


static POVS_VPORT_ENTRY
OvsAllocateVport(VOID)
{
    POVS_VPORT_ENTRY vport;
    vport = (POVS_VPORT_ENTRY)OvsAllocateMemory(sizeof (OVS_VPORT_ENTRY));
    if (vport == NULL) {
        return NULL;
    }
    NdisZeroMemory(vport, sizeof (OVS_VPORT_ENTRY));
    vport->ovsState = OVS_STATE_UNKNOWN;
    return vport;
}

static VOID
OvsInitVportWithPortParam(POVS_VPORT_ENTRY vport,
                          PNDIS_SWITCH_PORT_PARAMETERS portParam)
{
    vport->isValidationPort = portParam->IsValidationPort;
    vport->portType = portParam->PortType;
    vport->portState = portParam->PortState;
    vport->portId = portParam->PortId;
    vport->nicState = NdisSwitchNicStateUnknown;

    switch (vport->portType) {
    case NdisSwitchPortTypeExternal:
        vport->ovsType = OVSWIN_VPORT_TYPE_EXTERNAL;
        break;
    case NdisSwitchPortTypeInternal:
        vport->ovsType = OVSWIN_VPORT_TYPE_INTERNAL;
        break;
    case NdisSwitchPortTypeSynthetic:
        vport->ovsType = OVSWIN_VPORT_TYPE_SYNTHETIC;
        break;
    case NdisSwitchPortTypeEmulated:
        vport->ovsType = OVSWIN_VPORT_TYPE_EMULATED;
        break;
    }
    RtlCopyMemory(&vport->portName, &portParam->PortName,
                  sizeof (NDIS_SWITCH_PORT_NAME));
    switch (vport->portState) {
    case NdisSwitchPortStateCreated:
        vport->ovsState = OVS_STATE_PORT_CREATED;
        break;
    case NdisSwitchPortStateTeardown:
        vport->ovsState = OVS_STATE_PORT_TEAR_DOWN;
        break;
    case NdisSwitchPortStateDeleted:
        vport->ovsState = OVS_STATE_PORT_DELETED;
        break;
    }
}


static VOID
OvsInitVportWithNicParam(POVS_SWITCH_CONTEXT switchContext,
                         POVS_VPORT_ENTRY vport,
                         PNDIS_SWITCH_NIC_PARAMETERS nicParam)
{
    ASSERT(vport->portId == nicParam->PortId);
    ASSERT(vport->ovsState == OVS_STATE_PORT_CREATED);

    UNREFERENCED_PARAMETER(switchContext);

    RtlCopyMemory(vport->permMacAddress, nicParam->PermanentMacAddress,
                  sizeof (nicParam->PermanentMacAddress));
    RtlCopyMemory(vport->currMacAddress, nicParam->CurrentMacAddress,
                  sizeof (nicParam->CurrentMacAddress));

    if (nicParam->NicType == NdisSwitchNicTypeSynthetic ||
        nicParam->NicType == NdisSwitchNicTypeEmulated) {
        RtlCopyMemory(vport->vmMacAddress, nicParam->VMMacAddress,
                      sizeof (nicParam->VMMacAddress));
        RtlCopyMemory(&vport->vmName, &nicParam->VmName,
                      sizeof (nicParam->VmName));
    } else {
        RtlCopyMemory(&vport->netCfgInstanceId, &nicParam->NetCfgInstanceId,
                      sizeof (nicParam->NetCfgInstanceId));
    }
    RtlCopyMemory(&vport->nicName, &nicParam->NicName,
                  sizeof (nicParam->NicName));
    vport->mtu = nicParam->MTU;
    vport->nicState = nicParam->NicState;
    vport->nicIndex = nicParam->NicIndex;
    vport->numaNodeId = nicParam->NumaNodeId;

    switch (vport->nicState) {
    case NdisSwitchNicStateCreated:
        vport->ovsState = OVS_STATE_NIC_CREATED;
        break;
    case NdisSwitchNicStateConnected:
        vport->ovsState = OVS_STATE_CONNECTED;
        break;
    case NdisSwitchNicStateDisconnected:
        vport->ovsState = OVS_STATE_NIC_CREATED;
        break;
    case NdisSwitchNicStateDeleted:
        vport->ovsState = OVS_STATE_PORT_CREATED;
        break;
    }
}

static VOID
OvsInitPhysNicVport(POVS_VPORT_ENTRY vport,
                    POVS_VPORT_ENTRY virtVport,
                    UINT32 nicIndex)
{
    vport->isValidationPort = virtVport->isValidationPort;
    vport->portType = virtVport->portType;
    vport->portState = virtVport->portState;
    vport->portId = virtVport->portId;
    vport->nicState = NdisSwitchNicStateUnknown;
    vport->ovsType = OVSWIN_VPORT_TYPE_EXTERNAL;
    vport->nicIndex = (NDIS_SWITCH_NIC_INDEX)nicIndex;
    RtlCopyMemory(&vport->portName, &virtVport->portName,
                  sizeof (NDIS_SWITCH_PORT_NAME));
    vport->ovsState = OVS_STATE_PORT_CREATED;
}
static NDIS_STATUS
OvsInitVportCommon(POVS_SWITCH_CONTEXT switchContext,
POVS_VPORT_ENTRY vport)
{
    UINT32 hash;
    size_t len;
    if (vport->portType != NdisSwitchPortTypeExternal ||
        vport->nicIndex != 0) {
        vport->portNo = OvsGetVportNo(switchContext, vport->nicIndex,
            vport->ovsType);
        if (vport->portNo == 0) {
            return NDIS_STATUS_RESOURCES;
        }
        ASSERT(OVS_IS_VPORT_ENTRY_NULL(switchContext,
            OVS_VPORT_INDEX(vport->portNo)));

        switchContext->vportArray[OVS_VPORT_INDEX(vport->portNo)] = vport;
    }
    switch (vport->portType) {
    case NdisSwitchPortTypeExternal:
        if (vport->nicIndex == 0) {
            switchContext->externalPortId = vport->portId;
            switchContext->externalVport = vport;
            RtlStringCbPrintfA(vport->ovsName, OVS_MAX_PORT_NAME_LENGTH - 1,
                "external.virtualAdapter");
        }
        else {
            switchContext->numPhysicalNics++;
            RtlStringCbPrintfA(vport->ovsName, OVS_MAX_PORT_NAME_LENGTH - 1,
                "external.%lu", (UINT32)vport->nicIndex);
        }
        break;
    case NdisSwitchPortTypeInternal:
        switchContext->internalPortId = vport->portId;
        switchContext->internalVport = vport;
        RtlStringCbPrintfA(vport->ovsName, OVS_MAX_PORT_NAME_LENGTH - 1,
            "internal");
        break;
    case NdisSwitchPortTypeSynthetic:
        RtlStringCbPrintfA(vport->ovsName, OVS_MAX_PORT_NAME_LENGTH - 1,
            "vmNICSyn.%lx", vport->portNo);
        break;
    case NdisSwitchPortTypeEmulated:
        RtlStringCbPrintfA(vport->ovsName, OVS_MAX_PORT_NAME_LENGTH - 1,
            "vmNICEmu.%lx", vport->portNo);
        break;
    }
    StringCbLengthA(vport->ovsName, OVS_MAX_PORT_NAME_LENGTH - 1, &len);
    vport->ovsNameLen = (UINT32)len;
    if (vport->portType == NdisSwitchPortTypeExternal &&
        vport->nicIndex == 0) {
        return NDIS_STATUS_SUCCESS;
    }
    hash = jhash_bytes(vport->ovsName, vport->ovsNameLen, OVS_HASH_BASIS);
    InsertHeadList(&switchContext->nameHashArray[hash & OVS_VPORT_MASK],
        &vport->nameLink);
    hash = jhash_words(&vport->portId, 1, OVS_HASH_BASIS);
    InsertHeadList(&switchContext->portHashArray[hash & OVS_VPORT_MASK],
        &vport->portLink);
    switchContext->numVports++;
    return NDIS_STATUS_SUCCESS;
}


static VOID
OvsRemoveAndDeleteVport(POVS_SWITCH_CONTEXT switchContext,
                        POVS_VPORT_ENTRY vport)
{
    UINT64 gen = vport->portNo >> 24;
    switch (vport->ovsType) {
    case OVSWIN_VPORT_TYPE_EXTERNAL:
        if (vport->nicIndex == 0) {
            ASSERT(switchContext->numPhysicalNics == 0);
            switchContext->externalPortId = 0;
            switchContext->externalVport = NULL;
            OvsFreeMemory(vport);
            return;
        } else {
            ASSERT(switchContext->numPhysicalNics);
            switchContext->numPhysicalNics--;
        }
        break;
    case OVSWIN_VPORT_TYPE_INTERNAL:
        switchContext->internalPortId = 0;
        switchContext->internalVport = NULL;
        OvsInternalAdapterDown();
        break;
    case OVSWIN_VPORT_TYPE_VXLAN:
        OvsCleanupVxlanTunnel(vport);
        break;
    case OVSWIN_VPORT_TYPE_GRE:
    case OVSWIN_VPORT_TYPE_GRE64:
        break;
    case OVSWIN_VPORT_TYPE_EMULATED:
    case OVSWIN_VPORT_TYPE_SYNTHETIC:
    default:
        break;
    }

    RemoveEntryList(&vport->nameLink);
    RemoveEntryList(&vport->portLink);
    gen = (gen + 1) & 0xff;
    switchContext->vportArray[OVS_VPORT_INDEX(vport->portNo)] =
                     (PVOID)(UINT64)gen;
    switchContext->numVports--;
    OvsFreeMemory(vport);
}


NDIS_STATUS
OvsAddConfiguredSwitchPorts(PSX_SWITCH_OBJECT sxSwitch,
                            POVS_SWITCH_CONTEXT switchContext)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    ULONG arrIndex;
    PNDIS_SWITCH_PORT_PARAMETERS portParam;
    PNDIS_SWITCH_PORT_ARRAY portArray = NULL;
    POVS_VPORT_ENTRY vport;

    OVS_LOG_TRACE("==> sxSwitch: %p, switchContext:%p",
                  sxSwitch, switchContext);

    status = SxLibGetPortArrayUnsafe(sxSwitch, &portArray);

    if (status != NDIS_STATUS_SUCCESS) {
        goto cleanup;
    }

    for (arrIndex = 0; arrIndex < portArray->NumElements; arrIndex++) {
         portParam = NDIS_SWITCH_PORT_AT_ARRAY_INDEX(portArray, arrIndex);
         vport = (POVS_VPORT_ENTRY)OvsAllocateVport();
         if (vport == NULL) {
             status = NDIS_STATUS_RESOURCES;
             goto cleanup;
         }
         OvsInitVportWithPortParam(vport, portParam);
         status = OvsInitVportCommon(switchContext, vport);
         if (status != NDIS_STATUS_SUCCESS) {
             OvsFreeMemory(vport);
             goto cleanup;
         }
    }
cleanup:
    if (status != NDIS_STATUS_SUCCESS) {
        OvsClearAllSwitchVports(sxSwitch, switchContext);
    }

    if (portArray != NULL) {
        ExFreePoolWithTag(portArray, SxExtAllocationTag);
    }
    OVS_LOG_TRACE("<== status: %x", status);
    return status;
}


NDIS_STATUS
OvsInitConfiguredSwitchNics(PSX_SWITCH_OBJECT sxSwitch,
                            POVS_SWITCH_CONTEXT switchContext)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    PNDIS_SWITCH_NIC_ARRAY nicArray = NULL;
    ULONG arrIndex;
    PNDIS_SWITCH_NIC_PARAMETERS nicParam;
    PNDIS_SWITCH_PORT_PROPERTY_ENUM_PARAMETERS portPropertyParameters = NULL;
    PNDIS_SWITCH_PORT_PROPERTY_ENUM_INFO portPropertyInfo = NULL;
    PNDIS_SWITCH_PORT_PROPERTY_VLAN vlanProperty;
    POVS_VPORT_ENTRY vport;

    OVS_LOG_TRACE("==> sxSwitch: %p, switchContext: %p",
                  sxSwitch, switchContext);
    /*
     * Now, get NIC list.
     */
    status = SxLibGetNicArrayUnsafe(sxSwitch, &nicArray);
    if (status != NDIS_STATUS_SUCCESS) {
        goto Cleanup;
    }
    for (arrIndex = 0; arrIndex < nicArray->NumElements; ++arrIndex) {

        nicParam = NDIS_SWITCH_NIC_AT_ARRAY_INDEX(nicArray, arrIndex);

        status = sxSwitch->NdisSwitchHandlers.ReferenceSwitchPort(
                                        sxSwitch->NdisSwitchContext,
                                        nicParam->PortId);
        //
        // Get VLAN Port property to ensure no VLAN set.
        //
        status = SxLibGetPortPropertyUnsafe(sxSwitch,
                                            nicParam->PortId,
                                            NdisSwitchPortPropertyTypeVlan,
                                            NULL,
                                            &portPropertyParameters);

        if (status != NDIS_STATUS_SUCCESS) {
            status = NDIS_STATUS_RESOURCES;
            goto Cleanup;
        }

        portPropertyInfo =
            NDIS_SWITCH_PORT_PROPERTY_ENUM_PARAMETERS_GET_FIRST_INFO(
                                    portPropertyParameters);

        //
        // Should always get back v1 or later. It is safe to access the v1
        // version of the structure if newer property is retrieved.
        //
        ASSERT(portPropertyInfo->PropertyVersion >=
               NDIS_SWITCH_PORT_PROPERTY_VLAN_REVISION_1);

        vlanProperty = (PNDIS_SWITCH_PORT_PROPERTY_VLAN)
                NDIS_SWITCH_PORT_PROPERTY_ENUM_INFO_GET_PROPERTY(
                                     portPropertyInfo);

        //
        // Real production code should support VLAN,
        // and not fail SxExtRestartSwitch.
        //
        if (vlanProperty->OperationMode != NdisSwitchPortVlanModeAccess ||
            vlanProperty->VlanProperties.AccessVlanId != 0) {
            status = NDIS_STATUS_FAILURE;
            ExFreePoolWithTag(portPropertyParameters, SxExtAllocationTag);
            goto Cleanup;
        }

        status = sxSwitch->NdisSwitchHandlers.DereferenceSwitchPort(
                                        sxSwitch->NdisSwitchContext,
                                        nicParam->PortId);

        ASSERT(status == NDIS_STATUS_SUCCESS);

        //
        // If a VF is assigned to a NIC, then the traffic
        // flows through the VF and not the switch. This means
        // we have to revoke the VF to enforce our policy.
        //
        if (nicParam->VFAssigned) {
            status = sxSwitch->NdisSwitchHandlers.ReferenceSwitchNic(
                                        sxSwitch->NdisSwitchContext,
                                        nicParam->PortId,
                                        nicParam->NicIndex);

            ASSERT(status == NDIS_STATUS_SUCCESS);

            SxLibRevokeVfUnsafe(sxSwitch, nicParam->PortId);

            status = sxSwitch->NdisSwitchHandlers.DereferenceSwitchNic(
                                        sxSwitch->NdisSwitchContext,
                                        nicParam->PortId,
                                        nicParam->NicIndex);

            ASSERT(status == NDIS_STATUS_SUCCESS);
        }
        if (nicParam->NicType == NdisSwitchNicTypeExternal &&
            nicParam->NicIndex != 0) {
            POVS_VPORT_ENTRY virtVport =
                   (POVS_VPORT_ENTRY)switchContext->externalVport;
            vport = OvsAllocateVport();
            if (vport) {
                OvsInitPhysNicVport(vport, virtVport, nicParam->NicIndex);
                status = OvsInitVportCommon(switchContext, vport);
                if (status != NDIS_STATUS_SUCCESS) {
                    OvsFreeMemory(vport);
                    vport = NULL;
                }
            }
        } else {
            vport = OvsFindVportByPortIdAndNicIndex(switchContext,
                                                    nicParam->PortId,
                                                    nicParam->NicIndex);
        }
        if (vport == NULL) {
            OVS_LOG_ERROR("Fail to allocate vport");
            ExFreePoolWithTag(portPropertyParameters, SxExtAllocationTag);
            continue;
        }
        OvsInitVportWithNicParam(switchContext, vport, nicParam);
        if (nicParam->NicType == NdisSwitchNicTypeInternal) {
            OvsInternalAdapterUp(vport->portNo, &nicParam->NetCfgInstanceId);
        }
        ExFreePoolWithTag(portPropertyParameters, SxExtAllocationTag);
    }
Cleanup:

    if (nicArray != NULL) {
        ExFreePoolWithTag(nicArray, SxExtAllocationTag);
    }
    OVS_LOG_TRACE("<== status: %x", status);
    return status;
}

VOID
OvsClearAllSwitchVports(PSX_SWITCH_OBJECT sxSwitch,
                       POVS_SWITCH_CONTEXT switchContext)
{
    UINT32 i;
    UNREFERENCED_PARAMETER(sxSwitch);

    for (i = 0; i < OVS_MAX_VPORT_ARRAY_SIZE; i++) {
        if (!OVS_IS_VPORT_ENTRY_NULL(switchContext, i)) {
            OvsRemoveAndDeleteVport(switchContext,
                       (POVS_VPORT_ENTRY)switchContext->vportArray[i]);
        }
    }
    if (switchContext->externalVport) {
        OvsRemoveAndDeleteVport(switchContext,
                        (POVS_VPORT_ENTRY)switchContext->externalVport);
    }
}

NTSTATUS
OvsDumpVportIoctl(PVOID inputBuffer,
                  UINT32 inputLength,
                  PVOID outputBuffer,
                  UINT32 outputLength,
                  UINT32 *replyLen)
{
    UINT32 numVports, count;
    UINT32 dpNo, i;
    UINT32 *outPtr;
    POVS_VPORT_ENTRY vport;
    LOCK_STATE_EX lockState;

    if (inputLength < sizeof (UINT32)) {
        return STATUS_INVALID_PARAMETER;
    }
    dpNo = *(UINT32 *)inputBuffer;

    NdisAcquireSpinLock(ovsCtrlLock);
    if (ovsSwitchContext == NULL ||
        ovsSwitchContext->dpNo != dpNo) {
        NdisReleaseSpinLock(ovsCtrlLock);
        return STATUS_INVALID_PARAMETER;
    }
    /*
     * We should hold SwitchContext RW lock
     */

    NdisAcquireRWLockRead(ovsSwitchContext->dispatchLock, &lockState,
                          NDIS_RWL_AT_DISPATCH_LEVEL);
    numVports = outputLength/sizeof (UINT32);
    numVports = MIN(ovsSwitchContext->numVports, numVports);
    outPtr = (UINT32 *)outputBuffer;
    for (i = 0, count = 0;
         i < OVS_MAX_VPORT_ARRAY_SIZE && count < numVports; i++) {
        vport = (POVS_VPORT_ENTRY)ovsSwitchContext->vportArray[i];
        if (OVS_IS_VPORT_ENTRY_NULL(ovsSwitchContext, i)) {
            continue;
        }
        if (vport->ovsState == OVS_STATE_CONNECTED ||
            vport->ovsState == OVS_STATE_NIC_CREATED) {
            *outPtr = vport->portNo;
            outPtr++;
            count++;
        }
    }
    NdisReleaseRWLock(ovsSwitchContext->dispatchLock, &lockState);
    NdisReleaseSpinLock(ovsCtrlLock);
    *replyLen = count * sizeof (UINT32);
    return STATUS_SUCCESS;
}


NTSTATUS
OvsGetVportIoctl(PVOID inputBuffer,
                 UINT32 inputLength,
                 PVOID outputBuffer,
                 UINT32 outputLength,
                 UINT32 *replyLen)
{
    UINT32 dpNo;
    POVS_VPORT_GET get;
    POVS_VPORT_INFO info;
    POVS_VPORT_ENTRY vport;
    size_t len;
    LOCK_STATE_EX lockState;

    if (inputLength < sizeof (OVS_VPORT_GET) ||
        outputLength < sizeof (OVS_VPORT_INFO)) {
        return STATUS_INVALID_PARAMETER;
    }
    get = (POVS_VPORT_GET)inputBuffer;
    dpNo = get->dpNo;
    info = (POVS_VPORT_INFO)outputBuffer;
    RtlZeroMemory(info, sizeof (POVS_VPORT_INFO));

    NdisAcquireSpinLock(ovsCtrlLock);
    if (ovsSwitchContext == NULL ||
        ovsSwitchContext->dpNo != dpNo) {
        NdisReleaseSpinLock(ovsCtrlLock);
        return STATUS_INVALID_PARAMETER;
    }

    NdisAcquireRWLockRead(ovsSwitchContext->dispatchLock, &lockState,
                          NDIS_RWL_AT_DISPATCH_LEVEL);
    if (get->portNo == 0) {
        StringCbLengthA(get->name, OVS_MAX_PORT_NAME_LENGTH - 1, &len);
        vport = OvsFindVportByOvsName(ovsSwitchContext, get->name, (UINT32)len);
    } else {
        vport = OvsFindVportByPortNo(ovsSwitchContext, get->portNo);
    }
    if (vport == NULL || (vport->ovsState != OVS_STATE_CONNECTED &&
                          vport->ovsState != OVS_STATE_NIC_CREATED)) {
        NdisReleaseRWLock(ovsSwitchContext->dispatchLock, &lockState);
        NdisReleaseSpinLock(ovsCtrlLock);
        /*
         * XXX Change to NO DEVICE
         */
        return STATUS_DEVICE_DOES_NOT_EXIST;
    }
    info->dpNo = dpNo;
    info->portNo = vport->portNo;
    info->type = vport->ovsType;
    RtlCopyMemory(info->macAddress, vport->permMacAddress,
                  sizeof (vport->permMacAddress));
    RtlCopyMemory(info->name, vport->ovsName, vport->ovsNameLen + 1);

    info->rxPackets = vport->stats.rxPackets;
    info->rxBytes = vport->stats.rxBytes;
    info->txPackets = vport->stats.txPackets;
    info->txBytes = vport->stats.txBytes;
    info->rxErrors = vport->errStats.rxErrors;
    info->txErrors = vport->errStats.txErrors;
    info->rxDropped = vport->errStats.rxDropped;
    info->txDropped = vport->errStats.txDropped;

    NdisReleaseRWLock(ovsSwitchContext->dispatchLock, &lockState);
    NdisReleaseSpinLock(ovsCtrlLock);
    *replyLen = sizeof (OVS_VPORT_INFO);
    return STATUS_SUCCESS;
}


NTSTATUS
OvsInitTunnelVport(POVS_VPORT_ENTRY vport,
                   POVS_VPORT_ADD_REQUEST addReq)
{
    size_t len;
    NTSTATUS status = STATUS_SUCCESS;

    vport->isValidationPort = FALSE;
    vport->ovsType = addReq->type;
    vport->ovsState = OVS_STATE_PORT_CREATED;
    RtlCopyMemory(vport->ovsName, addReq->name, OVS_MAX_PORT_NAME_LENGTH);
    vport->ovsName[OVS_MAX_PORT_NAME_LENGTH - 1] = 0;
    StringCbLengthA(vport->ovsName, OVS_MAX_PORT_NAME_LENGTH - 1, &len);
    vport->ovsNameLen = (UINT32)len;
    switch (addReq->type) {
    case OVSWIN_VPORT_TYPE_GRE:
        break;
    case OVSWIN_VPORT_TYPE_GRE64:
        break;
    case OVSWIN_VPORT_TYPE_VXLAN:
        status = OvsInitVxlanTunnel(vport, addReq);
        break;
    default:
        ASSERT(0);
    }
    return status;
}

NTSTATUS
OvsAddVportIoctl(PVOID inputBuffer,
                 UINT32 inputLength,
                 PVOID outputBuffer,
                 UINT32 outputLength,
                 UINT32 *replyLen)
{
    NTSTATUS status = STATUS_SUCCESS;
    POVS_VPORT_INFO vportInfo;
    POVS_VPORT_ADD_REQUEST addReq;
    POVS_VPORT_ENTRY vport;
    LOCK_STATE_EX lockState;
    UINT32 index;
    UINT32 portNo;

    OVS_LOG_TRACE("==> inpputLength: %u, outputLength: %u",
                  inputLength, outputLength);
    if (inputLength < sizeof (OVS_VPORT_ADD_REQUEST) ||
        outputLength < sizeof (OVS_VPORT_INFO)) {
        status = STATUS_INVALID_PARAMETER;
        goto vport_add_done;
    }
    addReq = (POVS_VPORT_ADD_REQUEST)inputBuffer;
    addReq->name[OVS_MAX_PORT_NAME_LENGTH - 1] = 0;

    switch (addReq->type) {
    case OVSWIN_VPORT_TYPE_GRE:
        index = OVS_GRE_VPORT_INDEX;
        break;
    case OVSWIN_VPORT_TYPE_GRE64:
        index = OVS_GRE64_VPORT_INDEX;
        break;
    case OVSWIN_VPORT_TYPE_VXLAN:
        index = OVS_VXLAN_VPORT_INDEX;
        break;
    default:
        status = STATUS_NOT_SUPPORTED;
        goto vport_add_done;
    }

    vport = (POVS_VPORT_ENTRY)OvsAllocateVport();
    if (vport == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto vport_add_done;
    }

    NdisAcquireSpinLock(ovsCtrlLock);
    if (ovsSwitchContext == NULL ||
        ovsSwitchContext->dpNo != addReq->dpNo) {
        NdisReleaseSpinLock(ovsCtrlLock);
        status = STATUS_INVALID_PARAMETER;
        OvsFreeMemory(vport);
        goto vport_add_done;
    }
    NdisAcquireRWLockRead(ovsSwitchContext->dispatchLock, &lockState,
                          NDIS_RWL_AT_DISPATCH_LEVEL);
    if (!OVS_IS_VPORT_ENTRY_NULL(ovsSwitchContext, index)) {
        status = STATUS_DEVICE_BUSY;
        NdisReleaseRWLock(ovsSwitchContext->dispatchLock, &lockState);
        NdisReleaseSpinLock(ovsCtrlLock);
        OvsFreeMemory(vport);
        goto vport_add_done;
    }

    status = OvsInitTunnelVport(vport, addReq);
    if (status != STATUS_SUCCESS) {
        NdisReleaseRWLock(ovsSwitchContext->dispatchLock, &lockState);
        NdisReleaseSpinLock(ovsCtrlLock);
        OvsFreeMemory(vport);
        goto vport_add_done;
    }

    status = OvsInitVportCommon(ovsSwitchContext, vport);
    ASSERT(status == NDIS_STATUS_SUCCESS);

    vport->ovsState = OVS_STATE_CONNECTED;
    vport->nicState = NdisSwitchNicStateConnected;

    vportInfo = (POVS_VPORT_INFO)outputBuffer;

    RtlZeroMemory(vportInfo, sizeof (POVS_VPORT_INFO));
    vportInfo->dpNo = ovsSwitchContext->dpNo;
    vportInfo->portNo = vport->portNo;
    vportInfo->type = vport->ovsType;
    RtlCopyMemory(vportInfo->name, vport->ovsName, vport->ovsNameLen + 1);
    portNo = vport->portNo;

    NdisReleaseRWLock(ovsSwitchContext->dispatchLock, &lockState);
    NdisReleaseSpinLock(ovsCtrlLock);
    OvsPostEvent(portNo, OVS_EVENT_CONNECT | OVS_EVENT_LINK_UP);
    *replyLen = sizeof (OVS_VPORT_INFO);
    status = STATUS_SUCCESS;
vport_add_done:
    OVS_LOG_TRACE("<== byteReturned: %u, status: %x",
                  *replyLen, status);
    return status;
}

NTSTATUS
OvsDelVportIoctl(PVOID inputBuffer,
                 UINT32 inputLength,
                 UINT32 *replyLen)
{
    NTSTATUS status = STATUS_SUCCESS;
    POVS_VPORT_DELETE_REQUEST delReq;
    LOCK_STATE_EX lockState;
    POVS_VPORT_ENTRY vport;
    size_t len;
    UINT32 portNo = 0;

    OVS_LOG_TRACE("==> inpputLength: %u", inputLength);

    if (inputLength < sizeof (OVS_VPORT_DELETE_REQUEST)) {
        status = STATUS_INVALID_PARAMETER;
        goto vport_del_done;
    }
    delReq = (POVS_VPORT_DELETE_REQUEST)inputBuffer;

    NdisAcquireSpinLock(ovsCtrlLock);
    if (ovsSwitchContext == NULL ||
        ovsSwitchContext->dpNo != delReq->dpNo) {
        NdisReleaseSpinLock(ovsCtrlLock);
        status = STATUS_INVALID_PARAMETER;
        goto vport_del_done;
    }
    NdisAcquireRWLockRead(ovsSwitchContext->dispatchLock, &lockState,
                          NDIS_RWL_AT_DISPATCH_LEVEL);
    if (delReq->portNo == 0) {
        StringCbLengthA(delReq->name, OVS_MAX_PORT_NAME_LENGTH - 1, &len);
        vport = OvsFindVportByOvsName(ovsSwitchContext, delReq->name,
                                      (UINT32)len);
    } else {
        vport = OvsFindVportByPortNo(ovsSwitchContext, delReq->portNo);
    }
    if (vport) {
        OVS_LOG_INFO("delete vport: %s, portNo: %x", vport->ovsName,
                     vport->portNo);
        portNo = vport->portNo;
        OvsRemoveAndDeleteVport(ovsSwitchContext, vport);
    } else {
        status = STATUS_DEVICE_DOES_NOT_EXIST;
    }
    NdisReleaseRWLock(ovsSwitchContext->dispatchLock, &lockState);
    NdisReleaseSpinLock(ovsCtrlLock);
    if (portNo) {
        OvsPostEvent(portNo, OVS_EVENT_DISCONNECT | OVS_EVENT_LINK_DOWN);
    }
vport_del_done:
    OVS_LOG_TRACE("<== byteReturned: %u, status: %x",
                  *replyLen, status);
    return status;
}

NTSTATUS
OvsConvertIfCountedStrToAnsiStr(PIF_COUNTED_STRING wStr,
                                CHAR *str,
                                UINT16 maxStrLen)
{
    ANSI_STRING astr;
    UNICODE_STRING ustr;
    NTSTATUS status;
    UINT32 size;

    ustr.Buffer = wStr->String;
    ustr.Length = wStr->Length;
    ustr.MaximumLength = IF_MAX_STRING_SIZE;

    astr.Buffer = str;
    astr.MaximumLength = maxStrLen;
    astr.Length = 0;

    size = RtlUnicodeStringToAnsiSize(&ustr);
    if (size > maxStrLen) {
        return STATUS_BUFFER_OVERFLOW;
    }

    status = RtlUnicodeStringToAnsiString(&astr, &ustr, FALSE);

    ASSERT(status == STATUS_SUCCESS);
    if (status != STATUS_SUCCESS) {
        return status;
    }
    ASSERT(astr.Length <= maxStrLen);
    str[astr.Length] = 0;
    return STATUS_SUCCESS;
}


NTSTATUS
OvsGetExtInfoIoctl(PVOID inputBuffer,
                     UINT32 inputLength,
                     PVOID outputBuffer,
                     UINT32 outputLength,
                     UINT32 *replyLen)
{
    POVS_VPORT_GET get;
    POVS_VPORT_EXT_INFO info;
    POVS_VPORT_ENTRY vport;
    size_t len;
    LOCK_STATE_EX lockState;
    NTSTATUS status = STATUS_SUCCESS;
    NDIS_SWITCH_NIC_NAME nicName;
    NDIS_VM_NAME vmName;
    BOOLEAN doConvert = FALSE;

    OVS_LOG_TRACE("==> inpputLength: %u, outputLength: %u",
                  inputLength, outputLength);

    if (inputLength < sizeof (OVS_VPORT_GET) ||
        outputLength < sizeof (OVS_VPORT_EXT_INFO)) {
        status = STATUS_INVALID_PARAMETER;
        goto ext_info_done;
    }
    get = (POVS_VPORT_GET)inputBuffer;
    info = (POVS_VPORT_EXT_INFO)outputBuffer;
    RtlZeroMemory(info, sizeof (POVS_VPORT_EXT_INFO));

    NdisAcquireSpinLock(ovsCtrlLock);
    if (ovsSwitchContext == NULL ||
        ovsSwitchContext->dpNo != get->dpNo) {
        NdisReleaseSpinLock(ovsCtrlLock);
        status = STATUS_INVALID_PARAMETER;
        goto ext_info_done;
    }
    NdisAcquireRWLockRead(ovsSwitchContext->dispatchLock, &lockState,
                          NDIS_RWL_AT_DISPATCH_LEVEL);
    if (get->portNo == 0) {
        StringCbLengthA(get->name, OVS_MAX_PORT_NAME_LENGTH - 1, &len);
        vport = OvsFindVportByOvsName(ovsSwitchContext, get->name,
                                      (UINT32)len);
    } else {
        vport = OvsFindVportByPortNo(ovsSwitchContext, get->portNo);
    }
    if (vport == NULL || (vport->ovsState != OVS_STATE_CONNECTED &&
                          vport->ovsState != OVS_STATE_NIC_CREATED)) {
        NdisReleaseRWLock(ovsSwitchContext->dispatchLock, &lockState);
        NdisReleaseSpinLock(ovsCtrlLock);
        if (get->portNo) {
            OVS_LOG_WARN("vport %u does not exist any more", get->portNo);
        } else {
            OVS_LOG_WARN("vport %s does not exist any more", get->name);
        }
        status = STATUS_DEVICE_DOES_NOT_EXIST;
        goto ext_info_done;
    }
    info->dpNo = get->dpNo;
    info->portNo = vport->portNo;
    RtlCopyMemory(info->macAddress, vport->currMacAddress,
                  sizeof (vport->currMacAddress));
    RtlCopyMemory(info->permMACAddress, vport->permMacAddress,
                  sizeof (vport->permMacAddress));
    if (vport->ovsType == OVSWIN_VPORT_TYPE_SYNTHETIC ||
        vport->ovsType == OVSWIN_VPORT_TYPE_EMULATED) {
        RtlCopyMemory(info->vmMACAddress, vport->vmMacAddress,
                      sizeof (vport->vmMacAddress));
    }
    info->nicIndex = vport->nicIndex;
    info->portId = vport->portId;
    info->type = vport->ovsType;
    info->mtu = vport->mtu;
    /*
     * TO be revisit XXX
     */
    if (vport->ovsState == OVS_STATE_NIC_CREATED) {
       info->status = OVS_EVENT_CONNECT | OVS_EVENT_LINK_DOWN;
    } else if (vport->ovsState == OVS_STATE_CONNECTED) {
       info->status = OVS_EVENT_CONNECT | OVS_EVENT_LINK_UP;
    } else {
       info->status = OVS_EVENT_DISCONNECT;
    }
    if ((info->type == OVSWIN_VPORT_TYPE_SYNTHETIC ||
         info->type == OVSWIN_VPORT_TYPE_EMULATED) &&
        (vport->ovsState == OVS_STATE_NIC_CREATED  ||
         vport->ovsState == OVS_STATE_CONNECTED)) {
        RtlCopyMemory(&vmName, &vport->vmName, sizeof (NDIS_VM_NAME));
        RtlCopyMemory(&nicName, &vport->nicName, sizeof
                      (NDIS_SWITCH_NIC_NAME));
        doConvert = TRUE;
    } else {
        info->vmUUID[0] = 0;
        info->vifUUID[0] = 0;
    }

    RtlCopyMemory(info->name, vport->ovsName, vport->ovsNameLen + 1);
    NdisReleaseRWLock(ovsSwitchContext->dispatchLock, &lockState);
    NdisReleaseSpinLock(ovsCtrlLock);
    if (doConvert) {
        status = OvsConvertIfCountedStrToAnsiStr(&vmName,
                                                 info->vmUUID,
                                                 OVS_MAX_VM_UUID_LEN);
        if (status != STATUS_SUCCESS) {
            OVS_LOG_INFO("Fail to convert VM name.");
            info->vmUUID[0] = 0;
        }

        status = OvsConvertIfCountedStrToAnsiStr(&nicName,
                                                 info->vifUUID,
                                                 OVS_MAX_VIF_UUID_LEN);
        if (status != STATUS_SUCCESS) {
            OVS_LOG_INFO("Fail to convert nic name");
            info->vifUUID[0] = 0;
        }
        /*
         * for now ignore status
         */
        status = STATUS_SUCCESS;
    }
    *replyLen = sizeof (OVS_VPORT_EXT_INFO);

ext_info_done:
    OVS_LOG_TRACE("<== byteReturned: %u, status: %x",
                  *replyLen, status);
    return status;
}
