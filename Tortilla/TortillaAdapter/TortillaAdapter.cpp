/*!
    @file       TortillaAdapter.cpp
    @author     Cameron Gutman (cameron@crowdstrike.com)
    @brief      Tortilla Client v1.0 Beta
 
    @details    This product is produced independently from the Tor(r)
                anonymity software and carries no guarantee from The Tor
                Project about quality, suitability or anything else.
 
                See LICENSE.txt file in top level directory for details.
 
    @copyright  CrowdStrike, Inc. Copyright (c) 2013.  All rights reserved.
*/

#define NDIS_MINIPORT_DRIVER 1
#define NDIS51_MINIPORT 1
#define NDIS_WDM 1

#include <ntifs.h>
#include <wdm.h>
extern "C"
{
#include <ndis.h>

extern POBJECT_TYPE NTSYSAPI *MmSectionObjectType;

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
  ObCloseHandle(
    __in HANDLE Handle,
    __in KPROCESSOR_MODE PreviousMode
    );
#endif
}

#ifndef Add2Ptr
#define Add2Ptr(P,I) ((PVOID)((PUCHAR)(P) + (I)))
#endif

#define MAX_PACKET_SIZE             1514
#define ETHERNET_HEADER_SIZE        14
#define ETHERNET_ADDRESS_SIZE       6
#define MAX_PENDING_WRITES          32

#define TORTILLA_TAG 'troT'

// TACO TACO TACO (7A:C0:7A:C0:7A:C0) for Tortilla's MAC address
#define TORTILLA_PERM_MAC "\x7A\xC0\x7A\xC0\x7A\xC0"

const UCHAR s_VendorId[3] = {0xFF, 0xFF, 0xFF};
const CHAR s_VendorDescription[] = "CrowdStrike Tortilla Driver";
const USHORT s_DriverVersion = 0x0500;
const ULONG s_VendorDriverVersion = 0x00000001;

const UNICODE_STRING s_TortillaDirName = RTL_CONSTANT_STRING(L"\\Tortilla");
const UNICODE_STRING s_TortillaEventName = RTL_CONSTANT_STRING(L"\\Tortilla\\TortillaEvent");
const UNICODE_STRING s_ToTortillaWritingEventName = RTL_CONSTANT_STRING(L"\\Tortilla\\ToTortillaWritingEvent");
const UNICODE_STRING s_ToTortillaWrittenEventName = RTL_CONSTANT_STRING(L"\\Tortilla\\ToTortillaWrittenEvent");
const UNICODE_STRING s_ToTortillaSectionName = RTL_CONSTANT_STRING(L"\\Tortilla\\ToTortillaFileMapping");
const UNICODE_STRING s_FromTortillaWritingEventName = RTL_CONSTANT_STRING(L"\\Tortilla\\FromTortillaWritingEvent");
const UNICODE_STRING s_FromTortillaWrittenEventName = RTL_CONSTANT_STRING(L"\\Tortilla\\FromTortillaWrittenEvent");
const UNICODE_STRING s_FromTortillaSectionName = RTL_CONSTANT_STRING(L"\\Tortilla\\FromTortillaFileMapping");

const ULONG s_SupportedOids[] =
{
    OID_GEN_MAC_OPTIONS,
    OID_GEN_SUPPORTED_LIST,
    OID_GEN_HARDWARE_STATUS,
    OID_GEN_MEDIA_CONNECT_STATUS,
    OID_GEN_MEDIA_SUPPORTED,
    OID_GEN_MEDIA_IN_USE,
    OID_GEN_MAXIMUM_LOOKAHEAD,
    OID_GEN_MAXIMUM_FRAME_SIZE,
    OID_GEN_LINK_SPEED,
    OID_GEN_TRANSMIT_BUFFER_SPACE,
    OID_GEN_RECEIVE_BUFFER_SPACE,
    OID_GEN_MAXIMUM_TOTAL_SIZE,
    OID_GEN_TRANSMIT_BLOCK_SIZE,
    OID_GEN_RECEIVE_BLOCK_SIZE,
    OID_GEN_VENDOR_ID,
    OID_GEN_VENDOR_DESCRIPTION,
    OID_GEN_CURRENT_PACKET_FILTER,
    OID_GEN_CURRENT_LOOKAHEAD,
    OID_GEN_DRIVER_VERSION,
    OID_GEN_MAXIMUM_SEND_PACKETS,
    OID_GEN_VENDOR_DRIVER_VERSION,
    OID_GEN_XMIT_OK,
    OID_GEN_RCV_OK,
    OID_802_3_PERMANENT_ADDRESS,
    OID_802_3_CURRENT_ADDRESS,
    OID_802_3_MAXIMUM_LIST_SIZE,
    OID_GEN_RCV_ERROR,
    OID_GEN_RCV_NO_BUFFER,
    OID_GEN_XMIT_ERROR
};

typedef struct _MINIPORT_ADAPTER_CONTEXT
{
    NDIS_HANDLE MiniportAdapterHandle;
    ULONG PacketFilter;
    ULONG MaximumTotalPacketSize;
    ULONG MaximumPacketDataSize;
    ULONG PacketFiltersSupported;
    UCHAR NicPermanentAddress[ETHERNET_ADDRESS_SIZE];
    UCHAR NicCurrentAddress[ETHERNET_ADDRESS_SIZE];

    NDIS_MEDIA_STATE CurrentMediaState;
    ULONG CurrentXmitCount;
    ULONG LastXmitCount;

    ULONG NFramesXmitOk;
    ULONG NFramesRecvOk;

    HANDLE EventHandle;

    KEVENT SendQueueNotEmptyEvent;
    LIST_ENTRY SendQueueHead;
    NDIS_SPIN_LOCK SendQueueLock;

    NDIS_SPIN_LOCK Lock;
    KEVENT MiniportHaltingEvent;

    HANDLE RxThreadHandle;
    HANDLE TxThreadHandle;

    PRKEVENT ToTortillaWritingEvent;
    HANDLE ToTortillaWritingEventHandle;
    PRKEVENT ToTortillaWrittenEvent;
    HANDLE ToTortillaWrittenEventHandle;

    PRKEVENT FromTortillaWritingEvent;
    HANDLE FromTortillaWritingEventHandle;
    PRKEVENT FromTortillaWrittenEvent;
    HANDLE FromTortillaWrittenEventHandle;

    HANDLE ToTortillaSectionHandle;
    PVOID ToTortillaSection;
    PVOID ToTortillaView;

    HANDLE FromTortillaSectionHandle;
    PVOID FromTortillaSection;
    PVOID FromTortillaView;

    HANDLE DirectoryHandle;

    ULONG PendingWrites;
} MINIPORT_ADAPTER_CONTEXT, *PMINIPORT_ADAPTER_CONTEXT;

typedef struct _WRITE_ENTRY
{
    PNDIS_PACKET Packet;
    LIST_ENTRY ListEntry;
} WRITE_ENTRY, *PWRITE_ENTRY;

typedef struct _PACKET_DESCRIPTOR
{
    ULONG PacketLength;
    UCHAR LinkHeader[ETHERNET_HEADER_SIZE];
    UCHAR PacketData[1];
} PACKET_DESCRIPTOR, *PPACKET_DESCRIPTOR;

VOID
CleanUp(
    _In_ PMINIPORT_ADAPTER_CONTEXT pMac)
{
    PWRITE_ENTRY WriteEntry;

    // Signal the halting event and wait for the threads to die before cleaning up
    KeSetEvent(&pMac->MiniportHaltingEvent, IO_NETWORK_INCREMENT, FALSE);

    if (pMac->RxThreadHandle != NULL)
    {
        NT_VERIFY(NT_SUCCESS(ZwWaitForSingleObject(pMac->RxThreadHandle, FALSE, NULL)));
        ObCloseHandle(pMac->RxThreadHandle, KernelMode);
    }

    if (pMac->TxThreadHandle != NULL)
    {
        NT_VERIFY(NT_SUCCESS(ZwWaitForSingleObject(pMac->TxThreadHandle, FALSE, NULL)));
        ObCloseHandle(pMac->TxThreadHandle, KernelMode);
    }

    // Rundown the send queue
    while (!IsListEmpty(&pMac->SendQueueHead))
    {
        WriteEntry = CONTAINING_RECORD(RemoveHeadList(&pMac->SendQueueHead),
                                                      WRITE_ENTRY,
                                                      ListEntry);

        NdisMSendComplete(pMac->MiniportAdapterHandle, WriteEntry->Packet, NDIS_STATUS_FAILURE);

        NdisFreeMemory(WriteEntry, 0, 0);
    }

    if (pMac->EventHandle != NULL)
    {
        ObCloseHandle(pMac->EventHandle, KernelMode);
    }

    if (pMac->ToTortillaSectionHandle != NULL)
    {
        NT_ASSERT(pMac->ToTortillaSection != NULL);
        NT_ASSERT(pMac->ToTortillaView != NULL);

        MmUnmapViewInSystemSpace(pMac->ToTortillaView);
        ObDereferenceObject(pMac->ToTortillaSection);
        ObCloseHandle(pMac->ToTortillaSectionHandle, KernelMode);
    }

    if (pMac->FromTortillaSectionHandle != NULL)
    {
        NT_ASSERT(pMac->FromTortillaSection != NULL);
        NT_ASSERT(pMac->FromTortillaView != NULL);

        MmUnmapViewInSystemSpace(pMac->FromTortillaView);
        ObDereferenceObject(pMac->FromTortillaSection);
        ObCloseHandle(pMac->FromTortillaSection, KernelMode);
    }

    if (pMac->ToTortillaWrittenEventHandle != NULL)
    {
        NT_ASSERT(pMac->ToTortillaWrittenEvent != NULL);

        ObDereferenceObject(pMac->ToTortillaWrittenEvent);
        ObCloseHandle(pMac->ToTortillaWrittenEventHandle, KernelMode);
    }

    if (pMac->ToTortillaWritingEventHandle != NULL)
    {
        NT_ASSERT(pMac->ToTortillaWritingEvent != NULL);

        ObDereferenceObject(pMac->ToTortillaWritingEvent);
        ObCloseHandle(pMac->ToTortillaWritingEventHandle, KernelMode);
    }

    if (pMac->FromTortillaWrittenEventHandle != NULL)
    {
        NT_ASSERT(pMac->FromTortillaWrittenEvent != NULL);

        ObDereferenceObject(pMac->FromTortillaWrittenEvent);
        ObCloseHandle(pMac->FromTortillaWrittenEventHandle, KernelMode);
    }

    if (pMac->FromTortillaWritingEventHandle != NULL)
    {
        NT_ASSERT(pMac->FromTortillaWritingEvent != NULL);

        ObDereferenceObject(pMac->FromTortillaWritingEvent);
        ObCloseHandle(pMac->FromTortillaWritingEventHandle, KernelMode);
    }

    if (pMac->DirectoryHandle != NULL)
    {
        ObCloseHandle(pMac->DirectoryHandle, KernelMode);
    }

    NdisFreeSpinLock(&pMac->SendQueueLock);
    NdisFreeSpinLock(&pMac->Lock);

    NdisFreeMemory(
        pMac,
        sizeof(*pMac),
        0);
}

VOID
MiniportHalt(
    _In_  NDIS_HANDLE MiniportAdapterContext)
{
    PMINIPORT_ADAPTER_CONTEXT pMac = (PMINIPORT_ADAPTER_CONTEXT)MiniportAdapterContext;

    NT_ASSERT(pMac->RxThreadHandle != NULL);
    NT_ASSERT(pMac->TxThreadHandle != NULL);

    // Cleanup the miniport state
    CleanUp(pMac);
}

KSTART_ROUTINE RxThreadFunction;
VOID
RxThreadFunction(
    _In_ PVOID StartContext)
{
    NTSTATUS Status;
    PVOID WaitObjects[2];
    PPACKET_DESCRIPTOR Packet;
    ULONG PacketLength;

    PMINIPORT_ADAPTER_CONTEXT pMac = (PMINIPORT_ADAPTER_CONTEXT) StartContext;

    // This thread does not depend on any arbitrarily mutable state. It does
    // depend on state modified in MiniportInitialize and MiniportHalt, but it
    // correctly synchronizes with those so the follow code can execute without
    // holding a lock.

    WaitObjects[0] = pMac->FromTortillaWrittenEvent;
    WaitObjects[1] = &pMac->MiniportHaltingEvent;
    for(;;)
    {
        Status = KeWaitForMultipleObjects(
            RTL_NUMBER_OF(WaitObjects),
            WaitObjects,
            WaitAny,
            Executive,
            KernelMode,
            FALSE,
            NULL,
            NULL);
        NT_ASSERT((Status == STATUS_WAIT_0) || (Status == STATUS_WAIT_1));
        if (Status == STATUS_WAIT_0)
        {
            // There's a packet to read
            Packet = (PPACKET_DESCRIPTOR)pMac->FromTortillaView;

            // We capture this part of the descriptor to avoid a malicious user-mode component
            // pulling a fast one on us and changing this after we validated it
            PacketLength = *(volatile ULONG*)&Packet->PacketLength;
            if (PacketLength <= ETHERNET_HEADER_SIZE)
            {
                goto next;
            }

            if (PacketLength > pMac->MaximumTotalPacketSize)
            {
                goto next;
            }

            if (pMac->PacketFilter != 0)
            {
                // Only indicate packets if the protocol wants them
                NdisMEthIndicateReceive(pMac->MiniportAdapterHandle,
                    NULL,
                    (PCHAR)&Packet->LinkHeader[0],
                    ETHERNET_HEADER_SIZE,
                    (PVOID)&Packet->PacketData[0],
                    PacketLength - ETHERNET_HEADER_SIZE,
                    PacketLength - ETHERNET_HEADER_SIZE);

                NdisMEthIndicateReceiveComplete(pMac->MiniportAdapterHandle);
                pMac->NFramesRecvOk++;
            }

		next:
            KeSetEvent(pMac->FromTortillaWritingEvent, IO_NETWORK_INCREMENT, FALSE);
        }
        else if (Status == STATUS_WAIT_1)
        {
            // We need to terminate the thread because we're halting now
            break;
        }
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS
CreateNamedEvent(
    _In_ PCUNICODE_STRING EventName,
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ EVENT_TYPE EventType,
    _In_ BOOLEAN InitialState,
    _Out_ PRKEVENT* Event,
    _Out_ PHANDLE Handle)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    NTSTATUS Status;

    InitializeObjectAttributes(&ObjectAttributes,
                               const_cast<PUNICODE_STRING>(EventName),
                               OBJ_KERNEL_HANDLE | OBJ_OPENIF,
                               NULL,
                               SecurityDescriptor);

    Status = ZwCreateEvent(Handle,
                           EVENT_ALL_ACCESS,
                           &ObjectAttributes,
                           EventType,
                           InitialState);
    if (!NT_SUCCESS(Status))
    {
        goto exit;
    }

    Status = ObReferenceObjectByHandle(*Handle,
                                       EVENT_ALL_ACCESS,
                                       *ExEventObjectType,
                                       KernelMode,
                                       (PVOID*)Event,
                                       NULL);
    if (!NT_SUCCESS(Status))
    {
        ObCloseHandle(*Handle, KernelMode);
        goto exit;
    }

    // We need to make sure it's in the state expected.
    // This may not be the case if we opened an existing event.
    if (InitialState != FALSE)
    {
        KeSetEvent(*Event, IO_NO_INCREMENT, FALSE);
    }
    else
    {
        KeClearEvent(*Event);
    }

exit:
    if (!NT_SUCCESS(Status))
    {
        *Handle = NULL;
        *Event = NULL;
    }
    return Status;
}

NTSTATUS
CreateNamedSectionWithView(
    _In_ PCUNICODE_STRING SectionName,
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ ULONG Size,
    _Out_ PHANDLE Handle,
    _Out_ PVOID* Section,
    _Out_ PVOID* View)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    LARGE_INTEGER MaximumSize;
    SIZE_T ViewSize;
    NTSTATUS Status;

    InitializeObjectAttributes(&ObjectAttributes,
                               const_cast<PUNICODE_STRING>(SectionName),
                               OBJ_KERNEL_HANDLE | OBJ_OPENIF,
                               NULL,
                               SecurityDescriptor);

    MaximumSize.QuadPart = Size;
    Status = ZwCreateSection(Handle,
                             SECTION_ALL_ACCESS,
                             &ObjectAttributes,
                             &MaximumSize,
                             PAGE_READWRITE,
                             SEC_COMMIT,
                             NULL);
    if (!NT_SUCCESS(Status))
    {
        goto exit;
    }

    Status = ObReferenceObjectByHandle(*Handle,
                                       SECTION_ALL_ACCESS,
                                       *MmSectionObjectType,
                                       KernelMode,
                                       Section,
                                       NULL);
    if (!NT_SUCCESS(Status))
    {
        ObCloseHandle(*Handle, KernelMode);
        goto exit;
    }

    ViewSize = 0;
    Status = MmMapViewInSystemSpace(*Section,
                                    View,
                                    &ViewSize);
    if (!NT_SUCCESS(Status))
    {
        ObDereferenceObject(*Section);
        ObCloseHandle(*Handle, KernelMode);
        goto exit;
    }

exit:
    if (!NT_SUCCESS(Status))
    {
        *Handle = NULL;
        *Section = NULL;
        *View = NULL;
    }
    return Status;
}

VOID
DestroySecurityDescriptorData(
    _In_opt_ PACL AclEvent,
    _In_opt_ PACL AclFileMapping,
    _In_opt_ PACL AclDir)
{
    if (AclEvent != NULL)
    {
        NdisFreeMemory(AclEvent,
                       0,
                       0);
    }

    if (AclFileMapping != NULL)
    {
        NdisFreeMemory(AclFileMapping,
                       0,
                       0);
    }

    if (AclDir != NULL)
    {
        NdisFreeMemory(AclDir,
                       0,
                       0);
    }
}

NDIS_STATUS
CreateSecurityDescriptorData(
    _Out_ PACL *AclEvent,
    _Out_ PACL *AclFileMapping,
    _Out_ PACL *AclDir,
    _Out_ PSECURITY_DESCRIPTOR SecurityDescriptorEvent,
    _Out_ PSECURITY_DESCRIPTOR SecurityDescriptorFileMapping,
    _Out_ PSECURITY_DESCRIPTOR SecurityDescriptorDirectory)
{
    UINT AclLength;
    NDIS_STATUS Status;

    *AclEvent = NULL;
    *AclFileMapping = NULL;
    *AclDir = NULL;

    AclLength = sizeof(ACL) +
        2 * FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) +
        RtlLengthSid(SeExports->SeLocalSystemSid) +
        RtlLengthSid(SeExports->SeAliasAdminsSid);

    Status = NdisAllocateMemoryWithTag((PVOID*)AclEvent,
                                       AclLength,
                                       TORTILLA_TAG);
    if (Status != NDIS_STATUS_SUCCESS)
    {
        *AclEvent = NULL;
        goto exit;
    }

    Status = RtlCreateAcl(*AclEvent,
                          AclLength,
                          ACL_REVISION);
    if (!NT_SUCCESS(Status))
    {
        goto exit;
    }

    Status = RtlAddAccessAllowedAce(*AclEvent,
                                    ACL_REVISION,
                                    EVENT_ALL_ACCESS,
                                    SeExports->SeLocalSystemSid);
    if (!NT_SUCCESS(Status))
    {
        goto exit;
    }

    Status = RtlAddAccessAllowedAce(*AclEvent,
                                    ACL_REVISION,
                                    SYNCHRONIZE | EVENT_QUERY_STATE | EVENT_MODIFY_STATE,
                                    SeExports->SeAliasAdminsSid);
    if (!NT_SUCCESS(Status))
    {
        goto exit;
    }

    Status = RtlCreateSecurityDescriptor(SecurityDescriptorEvent,
                                         SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(Status))
    {
        goto exit;
    }

    Status = RtlSetDaclSecurityDescriptor(SecurityDescriptorEvent,
                                          TRUE,
                                          *AclEvent,
                                          FALSE);
    if (!NT_SUCCESS(Status))
    {
        goto exit;
    }

    Status = NdisAllocateMemoryWithTag((PVOID*)AclFileMapping,
                                       AclLength,
                                       TORTILLA_TAG);
    if (Status != NDIS_STATUS_SUCCESS)
    {
        *AclFileMapping = NULL;
        goto exit;
    }

    Status = RtlCreateAcl(*AclFileMapping,
                          AclLength,
                          ACL_REVISION);
    if (!NT_SUCCESS(Status))
    {
        goto exit;
    }

    Status = RtlAddAccessAllowedAce(*AclFileMapping,
                                    ACL_REVISION,
                                    SECTION_ALL_ACCESS,
                                    SeExports->SeLocalSystemSid);
    if (!NT_SUCCESS(Status))
    {
        goto exit;
    }

    Status = RtlAddAccessAllowedAce(*AclFileMapping,
                                    ACL_REVISION,
                                    SECTION_QUERY | SECTION_MAP_READ | SECTION_MAP_WRITE,
                                    SeExports->SeAliasAdminsSid);
    if (!NT_SUCCESS(Status))
    {
        goto exit;
    }

    Status = RtlCreateSecurityDescriptor(SecurityDescriptorFileMapping,
                                         SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(Status))
    {
        goto exit;
    }

    Status = RtlSetDaclSecurityDescriptor(SecurityDescriptorFileMapping,
                                          TRUE,
                                          *AclFileMapping,
                                          FALSE);
    if (!NT_SUCCESS(Status))
    {
        goto exit;
    }

    Status = NdisAllocateMemoryWithTag((PVOID*)AclDir,
                                       AclLength,
                                       TORTILLA_TAG);
    if (Status != NDIS_STATUS_SUCCESS)
    {
        *AclDir = NULL;
        goto exit;
    }

    Status = RtlCreateAcl(*AclDir,
                          AclLength,
                          ACL_REVISION);
    if (!NT_SUCCESS(Status))
    {
        goto exit;
    }

    Status = RtlAddAccessAllowedAce(*AclDir,
                                    ACL_REVISION,
                                    DIRECTORY_ALL_ACCESS,
                                    SeExports->SeLocalSystemSid);
    if (!NT_SUCCESS(Status))
    {
        goto exit;
    }

    Status = RtlAddAccessAllowedAce(*AclDir,
                                    ACL_REVISION,
                                    DIRECTORY_TRAVERSE | DIRECTORY_QUERY,
                                    SeExports->SeAliasAdminsSid);
    if (!NT_SUCCESS(Status))
    {
        goto exit;
    }

    Status = RtlCreateSecurityDescriptor(SecurityDescriptorDirectory,
                                         SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(Status))
    {
        goto exit;
    }

    Status = RtlSetDaclSecurityDescriptor(SecurityDescriptorDirectory,
                                          TRUE,
                                          *AclDir,
                                          FALSE);
    if (!NT_SUCCESS(Status))
    {
        goto exit;
    }


    Status = NDIS_STATUS_SUCCESS;

exit:
    if (Status != NDIS_STATUS_SUCCESS)
    {
        DestroySecurityDescriptorData(*AclEvent, *AclFileMapping, *AclDir);
    }

    return Status;
}

NDIS_STATUS
CreateNamedObjects(
    _In_ PMINIPORT_ADAPTER_CONTEXT pMac)
{
    PACL AclEvent;
    PACL AclFileMapping;
    PACL AclDir;
    SECURITY_DESCRIPTOR SecurityDescriptorEvent;
    SECURITY_DESCRIPTOR SecurityDescriptorFileMapping;
    SECURITY_DESCRIPTOR SecurityDescriptorDirectory;
    OBJECT_ATTRIBUTES ObjectAttributes;
    NDIS_STATUS Status;
    PKEVENT Event;

    Status = CreateSecurityDescriptorData(&AclEvent,
                                          &AclFileMapping,
                                          &AclDir,
                                          &SecurityDescriptorEvent,
                                          &SecurityDescriptorFileMapping,
                                          &SecurityDescriptorDirectory);
    if (Status != NDIS_STATUS_SUCCESS)
    {
        return Status;
    }

    InitializeObjectAttributes(&ObjectAttributes,
                               const_cast<PUNICODE_STRING>(&s_TortillaDirName),
                               OBJ_KERNEL_HANDLE | OBJ_OPENIF,
                               NULL,
                               &SecurityDescriptorDirectory);
    Status = ZwCreateDirectoryObject(&pMac->DirectoryHandle,
                                     DIRECTORY_ALL_ACCESS,
                                     &ObjectAttributes);
    if (!NT_SUCCESS(Status))
    {
        pMac->DirectoryHandle = NULL;
        goto exit;
    }

    // Ensure only one instance of the Tortilla device is active
    Event = IoCreateNotificationEvent(
        const_cast<PUNICODE_STRING>(&s_TortillaEventName),
        &pMac->EventHandle);
    if (Event == NULL)
    {
        Status = NDIS_STATUS_RESOURCES;
        goto exit;
    }

    Status = CreateNamedEvent(&s_ToTortillaWritingEventName,
                              &SecurityDescriptorEvent,
                              SynchronizationEvent,
                              TRUE,
                              &pMac->ToTortillaWritingEvent,
                              &pMac->ToTortillaWritingEventHandle);
    if (!NT_SUCCESS(Status))
    {
        goto exit;
    }

    Status = CreateNamedEvent(&s_ToTortillaWrittenEventName,
                              &SecurityDescriptorEvent,
                              SynchronizationEvent,
                              FALSE,
                              &pMac->ToTortillaWrittenEvent,
                              &pMac->ToTortillaWrittenEventHandle);
    if (!NT_SUCCESS(Status))
    {
        goto exit;
    }

    Status = CreateNamedEvent(&s_FromTortillaWritingEventName,
                              &SecurityDescriptorEvent,
                              SynchronizationEvent,
                              TRUE,
                              &pMac->FromTortillaWritingEvent,
                              &pMac->FromTortillaWritingEventHandle);
    if (!NT_SUCCESS(Status))
    {
        goto exit;
    }

    Status = CreateNamedEvent(&s_FromTortillaWrittenEventName,
                              &SecurityDescriptorEvent,
                              SynchronizationEvent,
                              FALSE,
                              &pMac->FromTortillaWrittenEvent,
                              &pMac->FromTortillaWrittenEventHandle);
    if (!NT_SUCCESS(Status))
    {
        goto exit;
    }

    Status = CreateNamedSectionWithView(&s_ToTortillaSectionName,
                                        &SecurityDescriptorFileMapping,
                                        sizeof(ULONG) + MAX_PACKET_SIZE,
                                        &pMac->ToTortillaSectionHandle,
                                        &pMac->ToTortillaSection,
                                        &pMac->ToTortillaView);
    if (!NT_SUCCESS(Status))
    {
        goto exit;
    }

    Status = CreateNamedSectionWithView(&s_FromTortillaSectionName,
                                        &SecurityDescriptorFileMapping,
                                        sizeof(ULONG) + MAX_PACKET_SIZE,
                                        &pMac->FromTortillaSectionHandle,
                                        &pMac->FromTortillaSection,
                                        &pMac->FromTortillaView);
    if (!NT_SUCCESS(Status))
    {
        goto exit;
    }

exit:
    DestroySecurityDescriptorData(AclEvent, AclFileMapping, AclDir);
    return Status;
}

KSTART_ROUTINE TxThreadFunction;
VOID
TxThreadFunction(
    _In_ PVOID StartContext)
{
    PMINIPORT_ADAPTER_CONTEXT pMac = (PMINIPORT_ADAPTER_CONTEXT) StartContext;
    PVOID WaitForDataObjects[2], WaitForSpaceObjects[2];
    PWRITE_ENTRY WriteEntry;
    UINT TotalPacketLength;
    PNDIS_BUFFER Buffer;
    PVOID VirtualAddress;
    UINT Length;
    ULONG BytesCopied;
    NTSTATUS Status;

    WaitForDataObjects[0] = &pMac->SendQueueNotEmptyEvent;
    WaitForDataObjects[1] = &pMac->MiniportHaltingEvent;

    WaitForSpaceObjects[0] = pMac->ToTortillaWritingEvent;
    WaitForSpaceObjects[1] = &pMac->MiniportHaltingEvent;

    for (;;)
    {
        // Wait for buffer space to become available
        Status = KeWaitForMultipleObjects(RTL_NUMBER_OF(WaitForSpaceObjects),
                                          WaitForSpaceObjects,
                                          WaitAny,
                                          Executive,
                                          KernelMode,
                                          FALSE,
                                          NULL,
                                          NULL);
        NT_ASSERT((Status == STATUS_WAIT_0) || (Status == STATUS_WAIT_1));
        if (Status == STATUS_WAIT_0)
        {
            // Wait for data in the list
            Status = KeWaitForMultipleObjects(RTL_NUMBER_OF(WaitForDataObjects),
                                              WaitForDataObjects,
                                              WaitAny,
                                              Executive,
                                              KernelMode,
                                              FALSE,
                                              NULL,
                                              NULL);
            if (Status == STATUS_WAIT_0)
            {
                // Remove the write entry from the head of the send queue
                NdisAcquireSpinLock(&pMac->SendQueueLock);

                NT_ASSERT(!IsListEmpty(&pMac->SendQueueHead));

                WriteEntry = CONTAINING_RECORD(RemoveHeadList(&pMac->SendQueueHead),
                                               WRITE_ENTRY,
                                               ListEntry);

                if (IsListEmpty(&pMac->SendQueueHead))
                {
                    KeClearEvent(&pMac->SendQueueNotEmptyEvent);
                }

                pMac->PendingWrites--;

                NdisReleaseSpinLock(&pMac->SendQueueLock);

                NdisQueryPacket(WriteEntry->Packet,
                                NULL,
                                NULL,
                                &Buffer,
                                &TotalPacketLength);

                NT_ASSERT(TotalPacketLength <= MAX_PACKET_SIZE);

                // Write the length before the packet data
                *(PULONG) pMac->ToTortillaView = TotalPacketLength;
                BytesCopied = sizeof(ULONG);

                while (Buffer != NULL)
                {
                    NdisQueryBufferSafe(Buffer,
                                        &VirtualAddress,
                                        &Length,
                                        NormalPagePriority);
                    if (VirtualAddress == NULL)
                    {
                        Status = NDIS_STATUS_RESOURCES;
                        goto CompleteSend;
                    }

                    NdisMoveMemory(Add2Ptr(pMac->ToTortillaView, BytesCopied),
                                   VirtualAddress,
                                   Length);

                    BytesCopied += Length;

                    NdisGetNextBuffer(Buffer, &Buffer);
                }

                Status = NDIS_STATUS_SUCCESS;
                pMac->NFramesXmitOk++;

            CompleteSend:
                pMac->CurrentXmitCount++;
                NdisMSendComplete(pMac->MiniportAdapterHandle, WriteEntry->Packet, Status);
                NdisFreeMemory(WriteEntry, 0, 0);
                KeSetEvent(pMac->ToTortillaWrittenEvent, IO_NETWORK_INCREMENT, FALSE);
            }
            else if (Status == STATUS_WAIT_1)
            {
                break;
            }
        }
        else if (Status == STATUS_WAIT_1)
        {
            break;
        }
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

NDIS_STATUS
MiniportInitialize(
    _Out_  PNDIS_STATUS OpenErrorStatus,
    _Out_  PUINT SelectedMediumIndex,
    _In_   PNDIS_MEDIUM MediumArray,
    _In_   UINT MediumArraySize,
    _In_   NDIS_HANDLE MiniportAdapterHandle,
    _In_   NDIS_HANDLE WrapperConfigurationContext)
{
    NDIS_STATUS Status;
    PMINIPORT_ADAPTER_CONTEXT MiniportAdapterContext = NULL;
    NDIS_HANDLE ConfigurationHandle = NULL;
    PUCHAR pNetworkAddress;
    UINT cbNetworkAddressLength;
    ULONG i;
    OBJECT_ATTRIBUTES ThreadAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(
        (PUNICODE_STRING)NULL, OBJ_KERNEL_HANDLE);

    UNREFERENCED_PARAMETER(OpenErrorStatus);

    for (i = 0; i < MediumArraySize; i++)
    {
        if (MediumArray[i] == NdisMedium802_3)
        {
            *SelectedMediumIndex = i;
            break;
        }
    }

    if (i == MediumArraySize)
    {
        Status = NDIS_STATUS_UNSUPPORTED_MEDIA;
        goto exit;
    }

    Status = NdisAllocateMemoryWithTag(
        (PVOID*) &MiniportAdapterContext,
        sizeof(*MiniportAdapterContext),
        TORTILLA_TAG);

    if (Status != STATUS_SUCCESS)
    {
        MiniportAdapterContext = NULL;
        goto exit;
    }

    NdisZeroMemory(
        MiniportAdapterContext,
        sizeof(*MiniportAdapterContext));

    NdisAllocateSpinLock(&MiniportAdapterContext->SendQueueLock);
    InitializeListHead(&MiniportAdapterContext->SendQueueHead);
    KeInitializeEvent(&MiniportAdapterContext->SendQueueNotEmptyEvent, NotificationEvent, FALSE);

    NdisAllocateSpinLock(&MiniportAdapterContext->Lock);
    KeInitializeEvent(&MiniportAdapterContext->MiniportHaltingEvent, NotificationEvent, FALSE);

    MiniportAdapterContext->MiniportAdapterHandle = MiniportAdapterHandle;

    MiniportAdapterContext->CurrentMediaState = NdisMediaStateConnected;

    NdisMoveMemory(
        MiniportAdapterContext->NicPermanentAddress,
        TORTILLA_PERM_MAC,
        ETHERNET_ADDRESS_SIZE);
    MiniportAdapterContext->MaximumTotalPacketSize = MAX_PACKET_SIZE;
    MiniportAdapterContext->MaximumPacketDataSize =
        MiniportAdapterContext->MaximumTotalPacketSize - ETHERNET_HEADER_SIZE;
    MiniportAdapterContext->PacketFiltersSupported =
        NDIS_PACKET_TYPE_DIRECTED       |
        NDIS_PACKET_TYPE_MULTICAST      |
        NDIS_PACKET_TYPE_ALL_MULTICAST  |
        NDIS_PACKET_TYPE_BROADCAST      |
        NDIS_PACKET_TYPE_SOURCE_ROUTING |
        NDIS_PACKET_TYPE_PROMISCUOUS    |
        NDIS_PACKET_TYPE_SMT            |
        NDIS_PACKET_TYPE_GROUP          |
        NDIS_PACKET_TYPE_ALL_FUNCTIONAL |
        NDIS_PACKET_TYPE_FUNCTIONAL     |
        NDIS_PACKET_TYPE_MAC_FRAME;

    NdisOpenConfiguration(&Status,
                          &ConfigurationHandle,
                          WrapperConfigurationContext);

    if (Status != NDIS_STATUS_SUCCESS)
    {
        goto exit;
    }

    NdisReadNetworkAddress(
        &Status,
        (PVOID*)&pNetworkAddress,
        &cbNetworkAddressLength,
        ConfigurationHandle);

    if ((Status == NDIS_STATUS_SUCCESS) && (cbNetworkAddressLength == ETHERNET_ADDRESS_SIZE))
    {
        NdisMoveMemory(
            MiniportAdapterContext->NicCurrentAddress,
            pNetworkAddress,
            ETHERNET_ADDRESS_SIZE);
    }
    else
    {
        NdisMoveMemory(
            MiniportAdapterContext->NicCurrentAddress,
            MiniportAdapterContext->NicPermanentAddress,
            ETHERNET_ADDRESS_SIZE);
    }

    NdisCloseConfiguration(ConfigurationHandle);

    NdisMSetAttributesEx(
        MiniportAdapterHandle,
        MiniportAdapterContext,
        10, // Call MiniportCheckForHang() every 10 seconds
        NDIS_ATTRIBUTE_DESERIALIZE | // We're deserialized because we run separate threads
        NDIS_ATTRIBUTE_USES_SAFE_BUFFER_APIS, // We exclusively use Ndis*Safe buffer APIs
        NdisInterfaceInternal);

    // Create the named objects that the user-mode component will use to
    // communicate with us
    Status = CreateNamedObjects(MiniportAdapterContext);
    if (Status != NDIS_STATUS_SUCCESS)
    {
        goto exit;
    }

    // Create the RX and TX threads after the named objects are created
    Status = PsCreateSystemThread(&MiniportAdapterContext->RxThreadHandle,
                                  THREAD_ALL_ACCESS,
                                  &ThreadAttributes,
                                  NULL,
                                  NULL,
                                  RxThreadFunction,
                                  MiniportAdapterContext);
    if (!NT_SUCCESS(Status))
    {
        MiniportAdapterContext->RxThreadHandle = NULL;
        goto exit;
    }

    Status = PsCreateSystemThread(&MiniportAdapterContext->TxThreadHandle,
                                  THREAD_ALL_ACCESS,
                                  &ThreadAttributes,
                                  NULL,
                                  NULL,
                                  TxThreadFunction,
                                  MiniportAdapterContext);
    if (!NT_SUCCESS(Status))
    {
        MiniportAdapterContext->TxThreadHandle = NULL;
        goto exit;
    }

    Status = NDIS_STATUS_SUCCESS;

exit:
    if (Status != NDIS_STATUS_SUCCESS)
    {
        if (MiniportAdapterContext != NULL)
        {
            CleanUp(MiniportAdapterContext);
        }
    }
    return Status;
}

NDIS_STATUS
MiniportQueryInformation(
    _In_   NDIS_HANDLE MiniportAdapterContext,
    _In_   NDIS_OID Oid,
    _In_   PVOID InformationBuffer,
    _In_   ULONG InformationBufferLength,
    _Out_  PULONG BytesWritten,
    _Out_  PULONG BytesNeeded)
{
    PMINIPORT_ADAPTER_CONTEXT pMac =
        (PMINIPORT_ADAPTER_CONTEXT)MiniportAdapterContext;
    NDIS_STATUS Status;

    *BytesWritten = 0;
    *BytesNeeded = 0;

    ULONG Value;
    PVOID pValue = &Value;
    ULONG cbValue = sizeof(ULONG);

    NdisAcquireSpinLock(&pMac->Lock);

    Status = STATUS_SUCCESS;
    switch (Oid)
    {
        case OID_GEN_MAC_OPTIONS:
            Value = NDIS_MAC_OPTION_NO_LOOPBACK;
            break;
        case OID_GEN_SUPPORTED_LIST:
            pValue = (PVOID)s_SupportedOids;
            cbValue = sizeof(s_SupportedOids);
            break;
        case OID_GEN_HARDWARE_STATUS:
            Value = NdisHardwareStatusReady;
            break;
        case OID_GEN_MEDIA_CONNECT_STATUS:
            Value = pMac->CurrentMediaState;
            break;
        case OID_GEN_MEDIA_SUPPORTED:
        case OID_GEN_MEDIA_IN_USE:
            Value = NdisMedium802_3;
            break;
        case OID_GEN_MAXIMUM_LOOKAHEAD:
            Value = pMac->MaximumPacketDataSize;
            break;
        case OID_GEN_MAXIMUM_FRAME_SIZE:
            Value = pMac->MaximumPacketDataSize;
            break;
        case OID_GEN_LINK_SPEED:
            Value = 10000000;   // 1 Gbps
            break;
        case OID_GEN_TRANSMIT_BUFFER_SPACE:
        case OID_GEN_RECEIVE_BUFFER_SPACE:
        case OID_GEN_MAXIMUM_TOTAL_SIZE:
            Value = pMac->MaximumTotalPacketSize;
            break;
        case OID_GEN_TRANSMIT_BLOCK_SIZE:
        case OID_GEN_RECEIVE_BLOCK_SIZE:
            Value = 1;
            break;
        case OID_GEN_VENDOR_ID:
            pValue = (PVOID)s_VendorId;
            cbValue = sizeof(s_VendorId);
            break;
        case OID_GEN_VENDOR_DESCRIPTION:
            pValue = (PVOID)s_VendorDescription;
            cbValue = sizeof(s_VendorDescription);
            break;
        case OID_GEN_CURRENT_PACKET_FILTER:
            Value = pMac->PacketFilter;
            cbValue = sizeof(pMac->PacketFilter);
            break;
        case OID_GEN_CURRENT_LOOKAHEAD:
            Value = pMac->MaximumPacketDataSize;
            cbValue = sizeof(pMac->MaximumPacketDataSize);
            break;
        case OID_GEN_DRIVER_VERSION:
            pValue = (PVOID)&s_DriverVersion;
            cbValue = sizeof(s_DriverVersion);
            break;
        case OID_GEN_MAXIMUM_SEND_PACKETS:
            // We don't support multi-packet indications
            Value = 1;
            break;
        case OID_GEN_VENDOR_DRIVER_VERSION:
            pValue = (PVOID)&s_VendorDriverVersion;
            cbValue = sizeof(s_VendorDriverVersion);
            break;
        case OID_GEN_XMIT_OK:
            Value = pMac->NFramesXmitOk;
            break;
        case OID_GEN_RCV_OK:
            Value = pMac->NFramesRecvOk;
            break;
        case OID_802_3_PERMANENT_ADDRESS:
            pValue = (PVOID)pMac->NicPermanentAddress;
            cbValue = sizeof(pMac->NicPermanentAddress);
            break;
        case OID_802_3_CURRENT_ADDRESS:
            pValue = (PVOID)pMac->NicCurrentAddress;
            cbValue = sizeof(pMac->NicCurrentAddress);
            break;
        case OID_802_3_MAXIMUM_LIST_SIZE:
            Value = 0;
            break;
        case OID_GEN_RCV_ERROR:
            Value = 0;
            break;
        case OID_GEN_RCV_NO_BUFFER:
            Value = 0;
            break;
        case OID_GEN_XMIT_ERROR:
            Value = 0;
            break;
        default:
            Status = NDIS_STATUS_NOT_SUPPORTED;
            break;
    }

    NdisReleaseSpinLock(&pMac->Lock);

    if (Status != NDIS_STATUS_SUCCESS)
    {
        return Status;
    }

    if (cbValue > InformationBufferLength)
    {
        *BytesNeeded = cbValue;
        return NDIS_STATUS_INVALID_LENGTH;
    }

    NdisMoveMemory(
        InformationBuffer,
        pValue,
        cbValue);
    *BytesWritten = cbValue;

    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
MiniportReset(
    _Out_  PBOOLEAN AddressingReset,
    _In_   NDIS_HANDLE MiniportAdapterContext)
{
    PMINIPORT_ADAPTER_CONTEXT pMac = (PMINIPORT_ADAPTER_CONTEXT) MiniportAdapterContext;
    PWRITE_ENTRY WriteEntry;

    *AddressingReset = FALSE;

    NdisAcquireSpinLock(&pMac->SendQueueLock);

    // The send queue is "empty" now
    KeClearEvent(&pMac->SendQueueNotEmptyEvent);

    // Rundown the send queue
    while (!IsListEmpty(&pMac->SendQueueHead))
    {
        WriteEntry = CONTAINING_RECORD(RemoveHeadList(&pMac->SendQueueHead),
                                                      WRITE_ENTRY,
                                                      ListEntry);

        NdisMSendComplete(pMac->MiniportAdapterHandle, WriteEntry->Packet, NDIS_STATUS_FAILURE);

        NdisFreeMemory(WriteEntry, 0, 0);
    }

    pMac->PendingWrites = 0;

    NdisReleaseSpinLock(&pMac->SendQueueLock);

    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
MiniportSend(
    _In_  NDIS_HANDLE MiniportAdapterContext,
    _In_  PNDIS_PACKET Packet,
    _In_  UINT Flags)
{
    PMINIPORT_ADAPTER_CONTEXT pMac = (PMINIPORT_ADAPTER_CONTEXT)MiniportAdapterContext;
    NDIS_STATUS Status;
    PWRITE_ENTRY WriteEntry;
    UINT PacketLength;

    UNREFERENCED_PARAMETER(Flags);

    NdisQueryPacketLength(Packet, &PacketLength);

    if (PacketLength > MAX_PACKET_SIZE)
    {
        return NDIS_STATUS_FAILURE;
    }

    Status = NdisAllocateMemoryWithTag(
        (PVOID*) &WriteEntry,
        sizeof(WRITE_ENTRY),
        TORTILLA_TAG);
    if (Status != NDIS_STATUS_SUCCESS)
    {
        return NDIS_STATUS_RESOURCES;
    }

    WriteEntry->Packet = Packet;

    NdisAcquireSpinLock(&pMac->SendQueueLock);

    pMac->PendingWrites++;
    if (pMac->PendingWrites > MAX_PENDING_WRITES)
    {
        pMac->PendingWrites--;
        NdisReleaseSpinLock(&pMac->SendQueueLock);

        NdisFreeMemory(WriteEntry, 0, 0);

        return NDIS_STATUS_RESOURCES;
    }

    InsertTailList(&pMac->SendQueueHead, &WriteEntry->ListEntry);

    NdisReleaseSpinLock(&pMac->SendQueueLock);

    KeSetEvent(&pMac->SendQueueNotEmptyEvent, IO_NETWORK_INCREMENT, FALSE);

    // We complete this when we actually indicate it to the user-mode component
    return NDIS_STATUS_PENDING;
}

NDIS_STATUS
MiniportSetInformation(
    _In_   NDIS_HANDLE MiniportAdapterContext,
    _In_   NDIS_OID Oid,
    _In_   PVOID InformationBuffer,
    _In_   ULONG InformationBufferLength,
    _Out_  PULONG BytesRead,
    _Out_  PULONG BytesNeeded)
{
    PMINIPORT_ADAPTER_CONTEXT pMac = (PMINIPORT_ADAPTER_CONTEXT)MiniportAdapterContext;
    NTSTATUS Status;

    *BytesRead = 0;
    *BytesNeeded = 0;

    NdisAcquireSpinLock(&pMac->Lock);

    switch (Oid)
    {
        case OID_GEN_CURRENT_PACKET_FILTER:
        {
            if (InformationBufferLength < sizeof(ULONG))
            {
                *BytesNeeded = sizeof(ULONG);
                Status = NDIS_STATUS_INVALID_LENGTH;
                goto Exit;
            }

            *BytesRead = sizeof(ULONG);

            if (pMac->PacketFiltersSupported & *(PULONG)InformationBuffer)
            {
                pMac->PacketFilter = pMac->PacketFiltersSupported & *(PULONG) InformationBuffer;
                Status = NDIS_STATUS_SUCCESS;
                goto Exit;
            }

            Status = NDIS_STATUS_INVALID_DATA;
            goto Exit;
        }

        case OID_GEN_CURRENT_LOOKAHEAD:
        {
            if (InformationBufferLength < sizeof(ULONG))
            {
                *BytesNeeded = sizeof(ULONG);
                Status = NDIS_STATUS_INVALID_LENGTH;
                goto Exit;
            }

            if (*(PULONG)InformationBuffer > pMac->MaximumPacketDataSize)
            {
                Status = NDIS_STATUS_INVALID_DATA;
                goto Exit;
            }

            // We're not required to limit our packet indications to this size,
            // so we fake success here without changing anything.
            *BytesRead = sizeof(ULONG);
            Status = NDIS_STATUS_SUCCESS;
            goto Exit;
        }

        case OID_GEN_PROTOCOL_OPTIONS:
        {
            // None of the currently defined flags affect us in any way
            Status = NDIS_STATUS_SUCCESS;
            goto Exit;
        }

        case OID_802_3_MULTICAST_LIST:
        {
            if ((InformationBufferLength % ETHERNET_ADDRESS_SIZE) == 0)
            {
                // We don't support multicast
                Status = NDIS_STATUS_MULTICAST_FULL;
                goto Exit;
            }

            Status = NDIS_STATUS_INVALID_LENGTH;
            goto Exit;
        }

        default:
        {
            Status = NDIS_STATUS_NOT_SUPPORTED;
            goto Exit;
        }
    }

Exit:
    NdisReleaseSpinLock(&pMac->Lock);
    return Status;
}

NDIS_STATUS
MiniportTransferData(
    _Out_  PNDIS_PACKET Packet,
    _Out_  PUINT BytesTransferred,
    _In_   NDIS_HANDLE MiniportAdapterContext,
    _In_   NDIS_HANDLE MiniportReceiveContext,
    _In_   UINT ByteOffset,
    _In_   UINT BytesToTransfer)
{
    UNREFERENCED_PARAMETER(Packet);
    UNREFERENCED_PARAMETER(BytesTransferred);
    UNREFERENCED_PARAMETER(MiniportAdapterContext);
    UNREFERENCED_PARAMETER(MiniportReceiveContext);
    UNREFERENCED_PARAMETER(ByteOffset);
    UNREFERENCED_PARAMETER(BytesToTransfer);

    // We indicate full packets at a time
    NT_ASSERT(FALSE);

    return STATUS_NDIS_NOT_SUPPORTED;
}

BOOLEAN
MiniportCheckForHang(
    _In_  NDIS_HANDLE MiniportAdapterContext)
{
    PMINIPORT_ADAPTER_CONTEXT pMac = (PMINIPORT_ADAPTER_CONTEXT)MiniportAdapterContext;
    BOOLEAN MiniportHung;

    NdisAcquireSpinLock(&pMac->SendQueueLock);

    // Check if there are packets waiting
    if (pMac->PendingWrites == 0)
    {
        // We can't determine whether we're hung, so let's assume we're not :)
        MiniportHung = FALSE;
        goto exit;
    }

    // Check if we've sent any packets since the last time we checked
    if (pMac->CurrentXmitCount == pMac->LastXmitCount)
    {
        // No packets sent in the last 10 seconds with packets pending, we're hung
        MiniportHung = TRUE;
    }
    else
    {
        // Sends are completing
        MiniportHung = FALSE;
    }

    // Update the xmit count
    pMac->LastXmitCount = pMac->CurrentXmitCount;

exit:
    NdisReleaseSpinLock(&pMac->SendQueueLock);
    return MiniportHung;
}

extern "C"
{
DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
    _In_  PDRIVER_OBJECT DriverObject,
    _In_  PUNICODE_STRING RegistryPath)
{
    NDIS_HANDLE NdisWrapperHandle;
    NDIS_MINIPORT_CHARACTERISTICS MiniportCharacteristics;
    NDIS_STATUS Status;

    NdisMInitializeWrapper(
        &NdisWrapperHandle,
        DriverObject,
        RegistryPath,
        NULL);
    if (NdisWrapperHandle == NULL)
    {
        return STATUS_UNSUCCESSFUL;
    }

    NdisZeroMemory(&MiniportCharacteristics, sizeof(MiniportCharacteristics));
    MiniportCharacteristics.Ndis50Chars.MajorNdisVersion = 5;

    MiniportCharacteristics.Ndis50Chars.CheckForHangHandler = MiniportCheckForHang;
    MiniportCharacteristics.Ndis50Chars.HaltHandler = MiniportHalt;
    MiniportCharacteristics.Ndis50Chars.InitializeHandler = MiniportInitialize;
    MiniportCharacteristics.Ndis50Chars.QueryInformationHandler = MiniportQueryInformation;
    MiniportCharacteristics.Ndis50Chars.ResetHandler = MiniportReset;
    MiniportCharacteristics.Ndis50Chars.SendHandler = MiniportSend;
    MiniportCharacteristics.Ndis50Chars.SetInformationHandler = MiniportSetInformation;
    MiniportCharacteristics.Ndis50Chars.TransferDataHandler = MiniportTransferData;

    Status = NdisMRegisterMiniport(
        NdisWrapperHandle,
        &MiniportCharacteristics,
        sizeof(MiniportCharacteristics));

    if (Status != NDIS_STATUS_SUCCESS)
    {
        NdisTerminateWrapper(
            NdisWrapperHandle,
            NULL);
    }

    return Status;
}
} // extern "C"