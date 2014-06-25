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
#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_OTHERS

#include "OvsDebug.h"

extern NDIS_HANDLE ovsDriverHandle;

VOID *
OvsAllocateMemory(size_t size)
{
    OVS_VERIFY_IRQL_LE(DISPATCH_LEVEL);
    return NdisAllocateMemoryWithTagPriority(ovsDriverHandle,
        (UINT32)size, OVS_MEMORY_TAG, NormalPoolPriority);
}

VOID *
OvsAllocateAlignedMemory(size_t size, UINT16 align)
{
    OVS_VERIFY_IRQL_LE(DISPATCH_LEVEL);
    if ((align == 8) || (align == 16)) {
        /*
         * XXX: NdisAllocateMemory*() functions don't talk anything about
         * alignment. Hence using ExAllocatePool*();
         */
        return (VOID *)ExAllocatePoolWithTagPriority(NonPagedPool, size,
                                                     OVS_MEMORY_TAG,
                                                     NormalPoolPriority);
    } else {
        return NULL;
    }
}

VOID
OvsFreeMemory(VOID *ptr)
{
    ASSERT(ptr);
    NdisFreeMemoryWithTagPriority(ovsDriverHandle, ptr, OVS_MEMORY_TAG);
}

VOID
OvsFreeAlignedMemory(VOID *ptr)
{
    ASSERT(ptr);
    ExFreePoolWithTag(ptr, OVS_MEMORY_TAG);
}

VOID
OvsAppendList(PLIST_ENTRY dst, PLIST_ENTRY src)
{
    PLIST_ENTRY srcFirst, srcLast, dstLast;
    if (IsListEmpty(src)) {
        return;
    }
    srcFirst = src->Flink;
    srcLast = src->Blink;
    dstLast = dst->Blink;

    dstLast->Flink = srcFirst;
    srcFirst->Blink = dstLast;

    srcLast->Flink = dst;
    dst->Blink = srcLast;

    src->Flink = src;
    src->Blink = src;
}
