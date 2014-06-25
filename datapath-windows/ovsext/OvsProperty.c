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

#include "OvsSwitch.h"
#include "OvsVport.h"
#include "OvsEvent.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_OTHERS
#include "OvsDebug.h"


/*
 * --------------------------------------------------------------------------
 *  This extension enforces one custom switch policy. The function verifies the
 *  switch property is our MAC policy and then adds it to the property list.
 * --------------------------------------------------------------------------
 */
_Use_decl_annotations_
NDIS_STATUS
SxExtAddSwitchProperty(PSX_SWITCH_OBJECT sxSwitch,
                       NDIS_HANDLE extensionContext,
                       PNDIS_SWITCH_PROPERTY_PARAMETERS switchProperty)
{
    NDIS_STATUS status = NDIS_STATUS_NOT_SUPPORTED;
    PNDIS_SWITCH_PROPERTY_CUSTOM customPolicy;
    POVS_SWITCH_CONTEXT switchContext = (POVS_SWITCH_CONTEXT)extensionContext;

    UNREFERENCED_PARAMETER(sxSwitch);

    if (switchProperty->PropertyType != NdisSwitchPropertyTypeCustom) {
        goto Cleanup;
    }
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
        return NDIS_STATUS_SUCCESS;
    }


    customPolicy = (PNDIS_SWITCH_PROPERTY_CUSTOM)
         NDIS_SWITCH_PROPERTY_PARAMETERS_GET_PROPERTY(switchProperty);
Cleanup:
    return status;
}

/*
 * --------------------------------------------------------------------------
 *  This extension enforces one custom switch policy, but does not allow updates
 *  for that policy.
 * --------------------------------------------------------------------------
 */
_Use_decl_annotations_
NDIS_STATUS
SxExtUpdateSwitchProperty(PSX_SWITCH_OBJECT sxSwitch,
                          NDIS_HANDLE extensionContext,
                          PNDIS_SWITCH_PROPERTY_PARAMETERS switchProperty)
{
    NDIS_STATUS status = NDIS_STATUS_NOT_SUPPORTED;

    UNREFERENCED_PARAMETER(sxSwitch);
    UNREFERENCED_PARAMETER(extensionContext);

    if (switchProperty->PropertyType != NdisSwitchPropertyTypeCustom) {
        goto Cleanup;
    }

    status = NDIS_STATUS_DATA_NOT_ACCEPTED;

Cleanup:
    return status;
}

_Use_decl_annotations_
BOOLEAN
SxExtDeleteSwitchProperty(PSX_SWITCH_OBJECT sxSwitch,
                          NDIS_HANDLE extensionContext,
                          PNDIS_SWITCH_PROPERTY_DELETE_PARAMETERS switchProperty)
{
    POVS_SWITCH_CONTEXT switchContext = (POVS_SWITCH_CONTEXT)extensionContext;

    UNREFERENCED_PARAMETER(sxSwitch);

    if (switchProperty->PropertyType != NdisSwitchPropertyTypeCustom) {
        goto Cleanup;
    }

    /*
     * Wait for lists to be initialized.
     */
    while (!switchContext->isActivated && !switchContext->isActivateFailed) {
        NdisMSleep(100);
    }
    if (!switchContext->isActivated) {
        return TRUE;
    }

Cleanup:
    return TRUE;
}


_Use_decl_annotations_
NDIS_STATUS
SxExtAddPortProperty(PSX_SWITCH_OBJECT sxSwitch,
                     NDIS_HANDLE extensionContext,
                     PNDIS_SWITCH_PORT_PROPERTY_PARAMETERS portProperty)
{
    NDIS_STATUS status = NDIS_STATUS_NOT_SUPPORTED;

    UNREFERENCED_PARAMETER(sxSwitch);
    UNREFERENCED_PARAMETER(extensionContext);

    switch(portProperty->PropertyType) {
    case NdisSwitchPortPropertyTypeCustom:
         //
         // No Custom Port Properties.
         //
         break;

     case NdisSwitchPortPropertyTypeSecurity:
         //
         // This extension does need to look at security policy, pass it down.
         // An extension must always pass through Hyper-V security policy.
         //
         break;

     case NdisSwitchPortPropertyTypeVlan:
         //
         // Forwarding extensions must either enforce VLAN, or fail
         // setting VLAN policy.
         // This extension does not enforce VLAN.
         //
         status = NDIS_STATUS_DATA_NOT_ACCEPTED;
         break;

     case NdisSwitchPortPropertyTypeProfile:
         //
         // No Processing of Port Profile.
         //
         break;
    }

    return status;
}

_Use_decl_annotations_
NDIS_STATUS
SxExtUpdatePortProperty(PSX_SWITCH_OBJECT sxSwitch,
                        NDIS_HANDLE extensionContext,
                        PNDIS_SWITCH_PORT_PROPERTY_PARAMETERS portProperty)
{
    NDIS_STATUS status = NDIS_STATUS_NOT_SUPPORTED;

    UNREFERENCED_PARAMETER(sxSwitch);
    UNREFERENCED_PARAMETER(extensionContext);

    switch(portProperty->PropertyType) {
    case NdisSwitchPortPropertyTypeCustom:
         //
         // No Custom Port Properties.
         //
         break;

    case NdisSwitchPortPropertyTypeSecurity:
         //
         // This extension does need to look at security policy, pass it down.
         // An extension must always pass through Hyper-V security policy.
         //
         break;

    case NdisSwitchPortPropertyTypeVlan:
         //
         // Forwarding extensions must either enforce VLAN, or fail
         // setting VLAN policy.
         // This extension does not enforce VLAN.
         //
         status = NDIS_STATUS_DATA_NOT_ACCEPTED;
         break;

    case NdisSwitchPortPropertyTypeProfile:
         //
         // No Processing of Port Profile.
         //
        break;
    }

    return status;
}

_Use_decl_annotations_
BOOLEAN
SxExtDeletePortProperty(PSX_SWITCH_OBJECT sxSwitch,
                        NDIS_HANDLE extensionContext,
                        PNDIS_SWITCH_PORT_PROPERTY_DELETE_PARAMETERS portProperty)
{
    BOOLEAN Delete = FALSE;

    UNREFERENCED_PARAMETER(sxSwitch);
    UNREFERENCED_PARAMETER(extensionContext);

    switch(portProperty->PropertyType) {
    case NdisSwitchPortPropertyTypeCustom:
        //
        // No Custom Port Properties.
        //
        break;

    case NdisSwitchPortPropertyTypeSecurity:
        //
        // This extension does need to look at security policy, pass it down.
        // An extension must always pass through Hyper-V security policy.
        //
        break;

    case NdisSwitchPortPropertyTypeVlan:
        //
        // Forwarding extensions must either enforce VLAN, or fail
        // setting VLAN policy.
        // This extension does not enforce VLAN.
        //
        /*
         * XXX
         */
        Delete = TRUE;
        break;

    case NdisSwitchPortPropertyTypeProfile:
        //
        // No Processing of Port Profile.
        //
        break;
    }

    return Delete;
}


/*
 * --------------------------------------------------------------------------
 *  This extension reports the status of its custom MAC policy by returning the
 *  list of PortId's currently allowing sends.
 * --------------------------------------------------------------------------
 */
_Use_decl_annotations_
BOOLEAN
SxExtQuerySwitchFeatureStatus(PSX_SWITCH_OBJECT sxSwitch,
                              NDIS_HANDLE extensionContext,
                              PNDIS_SWITCH_FEATURE_STATUS_PARAMETERS switchFeatureStatus,
                              PULONG bytesNeeded)
{
    POVS_SWITCH_CONTEXT switchContext = (POVS_SWITCH_CONTEXT)extensionContext;
    LOCK_STATE_EX lockState;
    BOOLEAN lockHeld = FALSE;

    UNREFERENCED_PARAMETER(sxSwitch);
    UNREFERENCED_PARAMETER(bytesNeeded);

    if (switchFeatureStatus->FeatureStatusType !=
        NdisSwitchFeatureStatusTypeCustom) {
        goto Cleanup;
    }
    /*
     * Wait for lists to be initialized.
     */
    while (!switchContext->isActivated && !switchContext->isActivateFailed) {
        NdisMSleep(100);
    }
    if (!switchContext->isActivated) {
        return FALSE;
    }

    NdisAcquireRWLockRead(switchContext->dispatchLock, &lockState, 0);
    lockHeld = TRUE;

Cleanup:
    if (lockHeld) {
        NdisReleaseRWLock(switchContext->dispatchLock, &lockState);
    }

    return FALSE;
}

_Use_decl_annotations_
BOOLEAN
SxExtQueryPortFeatureStatus(PSX_SWITCH_OBJECT sxSwitch,
                            NDIS_HANDLE extensionContext,
                            PNDIS_SWITCH_PORT_FEATURE_STATUS_PARAMETERS portFeatureStatus,
                            PULONG bytesNeeded)
{
    UNREFERENCED_PARAMETER(sxSwitch);
    UNREFERENCED_PARAMETER(extensionContext);
    UNREFERENCED_PARAMETER(portFeatureStatus);
    UNREFERENCED_PARAMETER(bytesNeeded);
    return FALSE;
}
