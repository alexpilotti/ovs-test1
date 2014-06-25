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
 * This file contains the implementation of the management functionality of the
 * OVS.
 */

#include "precomp.h"

#include "OvsIoctl.h"
#include "OvsSwitch.h"
#include "OvsVport.h"
#include "OvsEvent.h"
#include "OvsFlow.h"
#include "OvsIpHelper.h"
#include "OvsExt.h"
#include "OvsTunnelIntf.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_SWITCH
#include "OvsDebug.h"

POVS_SWITCH_CONTEXT ovsSwitchContext;
BOOLEAN ovsInAttach;
extern PNDIS_SPIN_LOCK ovsCtrlLock;
extern NDIS_HANDLE ovsDriverHandle;
extern NDIS_HANDLE SxDriverObject;

/*
 * NOTE: Keeping the names SxExtCreateSwitch, SxExtDeleteSwitch,
 * SxExtActivateSwitch, SxExtRestartSwitch & SxExtPauseSwitch unchanged so
 * that the base code doesn't need to change.
 */

static NDIS_STATUS OvsInitSwitchContext(PSX_SWITCH_OBJECT sxSwitch,
                   POVS_SWITCH_CONTEXT switchContext);
static VOID OvsDeleteSwitchContext(POVS_SWITCH_CONTEXT switchContext);
static NDIS_STATUS OvsActivateSwitch(_In_ PSX_SWITCH_OBJECT sxSwitch,
                  _In_ POVS_SWITCH_CONTEXT switchContext,
                  _In_ PNDIS_SWITCH_PARAMETERS switchParam);

/*
 * --------------------------------------------------------------------------
 *  This function allocated the switch context, and initializes its necessary
 *  members.
 * --------------------------------------------------------------------------
 */
_Use_decl_annotations_
NDIS_STATUS
SxExtCreateSwitch(PSX_SWITCH_OBJECT sxSwitch,
                  PNDIS_HANDLE *extensionContext)
{
    NDIS_STATUS status;
    POVS_SWITCH_CONTEXT switchContext;

    OVS_LOG_TRACE("==> Create switch object, sxSwitch:%p",
                  sxSwitch);

    if (ovsDriverHandle == NULL) {
        OVS_LOG_TRACE("==> Fail to load OVS driver");
        ASSERT(FALSE);
        return NDIS_STATUS_FAILURE;
    }

    NdisAcquireSpinLock(ovsCtrlLock);
    if (ovsSwitchContext) {
        NdisReleaseSpinLock(ovsCtrlLock);
        OVS_LOG_TRACE("==> Fail to create OVS Switch, only one datapath is"
                      "supported, %p.", sxSwitch);
        return NDIS_STATUS_FAILURE;
    }
    if (ovsInAttach) {
        NdisReleaseSpinLock(ovsCtrlLock);
        /* for now, just fail the request.
         */
        OVS_LOG_TRACE("==> Fail to create OVS Switch, since another attach"
                      "instance is in attach process. %p.", sxSwitch);
        return NDIS_STATUS_FAILURE;
    }
    ovsInAttach = TRUE;
    NdisReleaseSpinLock(ovsCtrlLock);

    status = OvsInitIpHelper(sxSwitch->NdisFilterHandle);

    if (status != STATUS_SUCCESS) {
        goto create_switch_done;
    }

    switchContext = (POVS_SWITCH_CONTEXT)
             OvsAllocateMemory(sizeof(OVS_SWITCH_CONTEXT));

    if (switchContext == NULL) {
        OvsCleanupIpHelper();
        status = NDIS_STATUS_RESOURCES;
        goto create_switch_done;
    }
    status = OvsInitSwitchContext(sxSwitch, switchContext);

    if (status != NDIS_STATUS_SUCCESS) {
        OvsCleanupIpHelper();
        OvsFreeMemory(switchContext);
        ovsSwitchContext = NULL;
        goto create_switch_done;
    } else {
        *extensionContext = (PNDIS_HANDLE)switchContext;
        ovsSwitchContext = switchContext;
    }

    status = OvsTunnelFilterInitialize(SxDriverObject);

    if (status != NDIS_STATUS_SUCCESS) {
        OvsCleanupIpHelper();
        OvsFreeMemory(switchContext);
        ovsSwitchContext = NULL;
        *extensionContext = NULL;
    }

create_switch_done:
    ovsInAttach = FALSE;
    OVS_LOG_TRACE("<== switchContext: %p status: %#lx",
                  ovsSwitchContext, status);
    return status;
}

/*
 * --------------------------------------------------------------------------
 *  This function deletes the switch by freeing all memory previously allocated.
 *  XXX need synchronization with other path.
 * --------------------------------------------------------------------------
 */
_Use_decl_annotations_
VOID
SxExtDeleteSwitch(PSX_SWITCH_OBJECT sxSwitch,
                  NDIS_HANDLE extensionContext)
{
    POVS_SWITCH_CONTEXT switchContext = (POVS_SWITCH_CONTEXT)extensionContext;
    UINT32 dpNo = switchContext->dpNo;

    OVS_LOG_TRACE("==> sxSwitch %p, switchContext:%p", sxSwitch,
                  switchContext);

    OvsTunnelFilterUninitialize(SxDriverObject);

    OvsClearAllSwitchVports(sxSwitch, switchContext);
    /*
     * Need synchronization with user space access
     */
    OvsDeleteSwitchContext(switchContext);
    ovsSwitchContext = NULL;
    OvsCleanupIpHelper();
    OVS_LOG_TRACE("<== deleted switch %p  dpNo: %d", switchContext, dpNo);
}


_Use_decl_annotations_
VOID
SxExtActivateSwitch(PSX_SWITCH_OBJECT sxSwitch,
                    NDIS_HANDLE extensionContext)
{
    POVS_SWITCH_CONTEXT switchContext = (POVS_SWITCH_CONTEXT)extensionContext;
    NDIS_SWITCH_PARAMETERS switchParameters;
    NDIS_STATUS status;

    OVS_LOG_TRACE("==> switchContext:%p, dpNo", switchContext,
                  switchContext->dpNo);

    status =  SxLibGetSwitchParametersUnsafe(sxSwitch, &switchParameters);
    ASSERT(switchContext->isActivated == FALSE);

    if (status != NDIS_STATUS_SUCCESS) {
        switchContext->isActivateFailed = TRUE;
    } else {
        status = OvsActivateSwitch(sxSwitch, switchContext, &switchParameters);
        if (status != NDIS_STATUS_SUCCESS) {
            switchContext->isActivateFailed = TRUE;
        }
    }

    OVS_LOG_TRACE("<== dpNo: %d, isActivated: %s", switchContext->dpNo,
                  (switchContext->isActivated ? "TRUE" : "FALSE"));
}

/*
 * --------------------------------------------------------------------------
 *  This function initializes the switch if it is the first restart. First it
 *  queries all of the MAC addresses set as custom switch policy to allow sends
 *  from, and adds tme to the property list.
 *  Then it queries the NIC list and verifies it can support all of the NICs
 *  currently connected to the switch, and adds the NICs to the NIC list.
 * --------------------------------------------------------------------------
 */
_Use_decl_annotations_
NDIS_STATUS
SxExtRestartSwitch(PSX_SWITCH_OBJECT sxSwitch,
                   NDIS_HANDLE extensionContext)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    POVS_SWITCH_CONTEXT switchContext = (POVS_SWITCH_CONTEXT)extensionContext;
    NDIS_SWITCH_PARAMETERS switchParameters;

    OVS_LOG_TRACE("==> restart switch :%p, dpNo: %d", switchContext,
                  switchContext->dpNo);

    if (!switchContext->isActivated && !switchContext->isActivateFailed) {
        status = SxLibGetSwitchParametersUnsafe(sxSwitch, &switchParameters);

        if (status != NDIS_STATUS_SUCCESS) {
            switchContext->isActivateFailed = TRUE;
            goto Cleanup;
        }

        if (switchParameters.IsActive) {
            status = OvsActivateSwitch(sxSwitch, switchContext,
                                       &switchParameters);

            if (status != NDIS_STATUS_SUCCESS) {
                OVS_LOG_WARN("Fail to activate switch, dpNo:%d",
                             switchContext->dpNo);
                goto Cleanup;
            }
        }
    }
    if (switchContext->isActivated) {
        switchContext->isPaused = FALSE;
    }

Cleanup:
    OVS_LOG_TRACE("<== Restart switch:%p, dpNo: %d, status: %#x",
                  switchContext, switchContext->dpNo, status);
    return status;
}


_Use_decl_annotations_
VOID
SxExtPauseSwitch(PSX_SWITCH_OBJECT sxSwitch,
                 NDIS_HANDLE extensionContext)
{
    POVS_SWITCH_CONTEXT switchContext = (POVS_SWITCH_CONTEXT)extensionContext;
    UNREFERENCED_PARAMETER(sxSwitch);
    if (switchContext->isActivated) {
        ASSERT(!switchContext->isPaused);
        switchContext->isPaused = TRUE;
    }
    OVS_LOG_TRACE("Switch paused, dpNo:%d", switchContext->dpNo);
}

/*
 * New Interfaces added to the Switch implementation.
 */

static NDIS_STATUS
OvsInitSwitchContext(PSX_SWITCH_OBJECT sxSwitch,
                     POVS_SWITCH_CONTEXT switchContext)
{
    int i;
    NTSTATUS status;
    OVS_LOG_TRACE("==>sxSwitch: %p, switchContext: %p",
                  sxSwitch, switchContext);

    NdisZeroMemory(switchContext, sizeof(OVS_SWITCH_CONTEXT));

    switchContext->dispatchLock =
             NdisAllocateRWLock(sxSwitch->NdisFilterHandle);

    switchContext->vportArray = (PVOID *)OvsAllocateMemory(sizeof (PVOID) *
                                                  OVS_MAX_VPORT_ARRAY_SIZE);
    switchContext->nameHashArray = (PLIST_ENTRY)
         OvsAllocateMemory(sizeof (LIST_ENTRY) * OVS_MAX_VPORT_ARRAY_SIZE);
    switchContext->portHashArray = (PLIST_ENTRY)
       OvsAllocateMemory(sizeof (LIST_ENTRY) * OVS_MAX_VPORT_ARRAY_SIZE);
    switchContext->sxSwitch = sxSwitch;
    status = OvsAllocateFlowTable(&switchContext->datapath, sxSwitch);

    if (status == NDIS_STATUS_SUCCESS) {
        status = OvsInitBufferPool(switchContext, sxSwitch->NdisFilterHandle);
    }
    if (status != NDIS_STATUS_SUCCESS ||
        switchContext->dispatchLock == NULL ||
        switchContext->vportArray == NULL ||
        switchContext->nameHashArray == NULL ||
        switchContext->portHashArray == NULL) {
        if (switchContext->dispatchLock) {
            NdisFreeRWLock(switchContext->dispatchLock);
        }
        if (switchContext->vportArray) {
            OvsFreeMemory(switchContext->vportArray);
        }
        if (switchContext->nameHashArray) {
            OvsFreeMemory(switchContext->nameHashArray);
        }
        if (switchContext->portHashArray) {
            OvsFreeMemory(switchContext->portHashArray);
        }
        OvsDeleteFlowTable(&switchContext->datapath);
        OvsCleanupBufferPool(switchContext);

        OVS_LOG_TRACE("<== Fail to init switchContext");
        return NDIS_STATUS_RESOURCES;
    }

    for (i = 0; i < OVS_MAX_VPORT_ARRAY_SIZE; i++) {
        InitializeListHead(&switchContext->nameHashArray[i]);
    }
    for (i = 0; i < OVS_MAX_VPORT_ARRAY_SIZE; i++) {
        InitializeListHead(&switchContext->portHashArray[i]);
    }
    NdisZeroMemory(switchContext->vportArray,
                   sizeof (PVOID) * OVS_MAX_VPORT_ARRAY_SIZE);

    switchContext->isActivated = FALSE;
    switchContext->isActivateFailed = FALSE;
    switchContext->isPaused = TRUE;
    switchContext->dpNo = OVS_DP_NUMBER;
    switchContext->lastPortIndex = OVS_MAX_VPORT_ARRAY_SIZE -1;
    ovsTimeIncrementPerTick = KeQueryTimeIncrement() / 10000;
    OVS_LOG_TRACE("<== Succesfully initialize switchContext: %p",
                  switchContext);
    return NDIS_STATUS_SUCCESS;
}

static VOID
OvsDeleteSwitchContext(POVS_SWITCH_CONTEXT switchContext)
{
    OVS_LOG_TRACE("==> Delete switchContext:%p",
                  switchContext);

    /*
     * We need to do cleanup for
     * tunnel port here.
     */
    ASSERT(switchContext->numVports == 0);
    ASSERT(switchContext->isPaused);



    NdisFreeRWLock(switchContext->dispatchLock);
    OvsFreeMemory(switchContext->nameHashArray);
    OvsFreeMemory(switchContext->portHashArray);
    OvsFreeMemory(switchContext->vportArray);
    OvsDeleteFlowTable(&switchContext->datapath);
    OvsCleanupBufferPool(switchContext);
    OvsFreeMemory(switchContext);
    OVS_LOG_TRACE("<== Delete switchContext: %p", switchContext);
}

static NDIS_STATUS
OvsActivateSwitch(_In_ PSX_SWITCH_OBJECT sxSwitch,
                  _In_ POVS_SWITCH_CONTEXT switchContext,
                  _In_ PNDIS_SWITCH_PARAMETERS switchParam)
{
    NDIS_STATUS status;
    UNREFERENCED_PARAMETER(switchParam);

    ASSERT(!switchContext->isActivated);

    OVS_LOG_TRACE("==> activate switch %p, dpNo: %ld",
                  switchContext, switchContext->dpNo);

    status = OvsAddConfiguredSwitchPorts(sxSwitch, switchContext);

    if (status != NDIS_STATUS_SUCCESS) {
        OVS_LOG_WARN("Fail to add configured switch ports");
        goto Cleanup;

    }
    status = OvsInitConfiguredSwitchNics(sxSwitch, switchContext);

    if (status != NDIS_STATUS_SUCCESS) {
        OVS_LOG_WARN("Fail to add configured vports");
        OvsClearAllSwitchVports(sxSwitch, switchContext);
        goto Cleanup;
    }
    switchContext->isActivated = TRUE;
    OvsPostEvent(OVS_DEFAULT_PORT_NO, OVS_DEFAULT_EVENT_STATUS);

Cleanup:
    OVS_LOG_TRACE("<== activate switch:%p, isActivated: %s, status = %lx",
                  switchContext,
                  (switchContext->isActivated ? "TRUE" : "FALSE"), status);
    return status;
}

PVOID
OvsGetVportFromIndex(UINT16 index)
{
    if (index < OVS_MAX_VPORT_ARRAY_SIZE &&
            !OVS_IS_VPORT_ENTRY_NULL(ovsSwitchContext, index)) {
        return ovsSwitchContext->vportArray[index];
    }
    return NULL;
}

PVOID
OvsGetExternalVport()
{
    return ovsSwitchContext->externalVport;
}
