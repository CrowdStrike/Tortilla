/*!
    @file       Tortilla.cpp
    @author     Jason Geffner (jason@crowdstrike.com)
    @brief      Tortilla Client v1.0.1 Beta
   
    @details    This product is produced independently from the Tor(r)
                anonymity software and carries no guarantee from The Tor
                Project about quality, suitability or anything else.

                See LICENSE.txt file in top level directory for details.

    @copyright  CrowdStrike, Inc. Copyright (c) 2013.  All rights reserved. 
*/

#include <windows.h>
#include <ntddndis.h>
#include <stdio.h>
#include <process.h>
#include <winternl.h>
#include <sys/types.h>
#include <sys/timeb.h>

#include "lwip/sys.h"
#include "lwip/tcp.h"
#include "lwip/tcpip.h"
#include "lwip/inet_chksum.h"
#include "netif/etharp.h"

#include "resource.h"
#include "network.h"
#include "../InstallTortillaDriver/InstallTortillaDriver.h"

#pragma comment(lib, "ws2_32.lib")

typedef NTSTATUS (NTAPI* NTOPENEVENT_T)(
    OUT PHANDLE EventHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
);

typedef NTSTATUS (NTAPI* NTOPENSECTION_T)(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
);
#define STATUS_SUCCESS  0

// In this context, MTU is the maximum size of a packet on the virtual wire
#define MTU             (1500 + sizeof(eth_hdr))
#define RECV_TIMEOUT_MS 100
#define MAX_PACKETS_PER_ITERATION 10

//
// 86400 seconds = 24 hours
//
#define DHCP_LEASE_TIME 86400
#define DNS_TTL         86400

#define DHCP_BROADCAST_FLAG 0x8000

typedef struct _PACKET_WITH_SIZE
{
    DWORD cbPacket;
    BYTE abPacket[MTU];
} PACKET_WITH_SIZE;

typedef struct _SOCKET_ITEM
{
    DWORD dwServerIp;
    WORD wServerPort;
    SOCKET socket;
    struct _SOCKET_ITEM* pPreviousSocketItem;
    struct _SOCKET_ITEM* pNextSocketItem;
} SOCKET_ITEM;

typedef struct _ACTIVE_SYN_ITEM
{
    DWORD dwServerIp;
    WORD wServerPort;
    DWORD dwClientIp;
    DWORD dwSequenceNumber;
    struct _ACTIVE_SYN_ITEM* pPreviousItem;
    struct _ACTIVE_SYN_ITEM* pNextItem;
} ACTIVE_SYN_ITEM;

typedef struct _SOCKET_BRIDGE
{
    SOCKET torSocket;
    struct netconn* lwIPConn;
} SOCKET_BRIDGE;

typedef enum _LOG_COLOR
{
    Gray =      FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED,

    Cyan =      FOREGROUND_INTENSITY | FOREGROUND_BLUE | FOREGROUND_GREEN,
    Green =     FOREGROUND_INTENSITY | FOREGROUND_GREEN,
    Red =       FOREGROUND_INTENSITY | FOREGROUND_RED,
    White =     FOREGROUND_INTENSITY | FOREGROUND_BLUE | FOREGROUND_GREEN |
                FOREGROUND_RED,
    Yellow =    FOREGROUND_INTENSITY | FOREGROUND_GREEN | FOREGROUND_RED
} LOG_COLOR;

WCHAR g_wszEnableNetworkBindings[128];
WCHAR g_wszIgnoreNetworkBindings[128];
BYTE g_abGatewayMacAddress[ETHARP_HWADDR_LEN];
BYTE g_abGatewayIpAddress[sizeof(in_addr)];
BYTE g_abDhcpClientIpAddress[sizeof(in_addr)];
BYTE g_abDhcpClientSubnetMask[sizeof(in_addr)];
DWORD g_dwTorClientIpAddress;
WORD g_wTorClientTcpPort;

HANDLE g_hPcapFile;
HANDLE g_hPcapMutex;

HANDLE g_hFromTortillaWrittenEvent;
HANDLE g_hFromTortillaWritingEvent;
PVOID g_pFromTortillaFileMapping;

SOCKET_ITEM* g_pAvailableEstablishedSockets;
HANDLE g_hAesMutex;

ACTIVE_SYN_ITEM* g_pActiveSyns;
HANDLE g_hActiveSynMutex;

HANDLE g_hConsoleOutput;
HANDLE g_hLogMutex;

struct netif netif;

VOID
Log (
    LOG_COLOR color,
    WCHAR* wszFormat,
    ...
    )
{
    BOOL fMutexHeld = FALSE;
    BOOL fTextAttributeSet = FALSE;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    va_list ap;

    //
    // Try to get a handle to the Log mutex. If for whatever reason the mutex
    // cannot be obtained, still print anyway so that a log message does not
    // get discarded.
    //
    if (WAIT_OBJECT_0 == WaitForSingleObject(
        g_hLogMutex,
        INFINITE))
    {
        fMutexHeld = TRUE;
    }

    fTextAttributeSet =
        (GetConsoleScreenBufferInfo(
            g_hConsoleOutput,
            &csbi) &&
        SetConsoleTextAttribute(
        g_hConsoleOutput,
        color));

    va_start(ap, wszFormat);
    vwprintf_s(wszFormat, ap);
    va_end(ap);

    if (fTextAttributeSet)
    {
        SetConsoleTextAttribute(
            g_hConsoleOutput,
            csbi.wAttributes);
    }

    if (fMutexHeld)
    {
        ReleaseMutex(
            g_hLogMutex);
    }
}


/*!
    @brief Adds an active TCP SYN to the g_pActiveSyns linked list

    @param[in] dwServerIp IP address of remote server
    @param[in] wServerPort TCP port for remote server
    @param[in] dwClientIp IP address of VM client
    @param[in] dwSequenceNumber TCP SYN Sequence Number sent by VM client
    @return Returns TRUE if the SYN was newly added to the list, returns FALSE
            on error or if the SYN already existed in the list
*/
BOOL
AddActiveSyn (
    DWORD dwServerIp,
    WORD wServerPort,
    DWORD dwClientIp,
    DWORD dwSequenceNumber
    )
{
    BOOL fSuccess = FALSE;
    ACTIVE_SYN_ITEM* pItem;
    ACTIVE_SYN_ITEM* pLastItem = NULL;

    //
    // Wait for the Active SYN list mutex
    //
    if (WAIT_OBJECT_0 != WaitForSingleObject(
        g_hActiveSynMutex,
        INFINITE))
    {
        Log(
            Red,
            L"Error in AddActiveSyn(): WaitForSingleObject() failed "
            L"(0x%08X)\n",
            GetLastError());
        goto exit;
    }

    //
    // The Active SYN list is empty, so create a new list item based on the
    // parameters passed to AddActiveSyn()
    //
    if (g_pActiveSyns == NULL)
    {
        g_pActiveSyns = (ACTIVE_SYN_ITEM*)malloc(sizeof(ACTIVE_SYN_ITEM));
        if (g_pActiveSyns == NULL)
        {
            Log(
                Red,
                L"Error in AddActiveSyn(): malloc(%d) failed\n",
                sizeof(ACTIVE_SYN_ITEM));
            goto exit;
        }
        g_pActiveSyns->dwServerIp = dwServerIp;
        g_pActiveSyns->wServerPort = wServerPort;
        g_pActiveSyns->dwClientIp = dwClientIp;
        g_pActiveSyns->dwSequenceNumber = dwSequenceNumber;
        g_pActiveSyns->pPreviousItem = NULL;
        g_pActiveSyns->pNextItem = NULL;
        fSuccess = TRUE;
        goto exit;
    }

    //
    // Search through the Active SYN list to see if the given SYN is already in
    // the list
    //
    for(pItem = g_pActiveSyns; pItem != NULL; pItem = pItem->pNextItem)
    {
        //
        // Is the current list item a match?
        //
        if ((pItem->dwServerIp == dwServerIp) &&
            (pItem->wServerPort == wServerPort) &&
            (pItem->dwClientIp == dwClientIp) &&
            (pItem->dwSequenceNumber == dwSequenceNumber))
        {
            //
            // The new active SYN is already in our list
            //
            goto exit;
        }

        pLastItem = pItem;
    }

    //
    // We've reached the end of the list without finding a match, so add the
    // new Active SYN
    //
    ACTIVE_SYN_ITEM* pNewItem =
        (ACTIVE_SYN_ITEM*)malloc(sizeof(ACTIVE_SYN_ITEM));
    if (pNewItem == NULL)
    {
        Log(
            Red,
            L"Error in AddActiveSyn(): malloc(%d) failed\n",
            sizeof(ACTIVE_SYN_ITEM));
        goto exit;
    }
    pNewItem->dwServerIp = dwServerIp;
    pNewItem->wServerPort = wServerPort;
    pNewItem->dwClientIp = dwClientIp;
    pNewItem->dwSequenceNumber = dwSequenceNumber;
    pNewItem->pPreviousItem = pItem;
    pNewItem->pNextItem = NULL;
    pLastItem->pNextItem = pNewItem;
    fSuccess = TRUE;

exit:
    ReleaseMutex(
        g_hActiveSynMutex);

    return fSuccess;
}

/*! 
    @brief Removes an active TCP SYN from the g_pActiveSyns linked list

    @param[in] dwServerIp IP address of remote server
    @param[in] wServerPort TCP port for remote server
    @param[in] dwClientIp IP address of VM client
    @param[in] dwSequenceNumber TCP SYN Sequence Number sent by VM client
    @return Returns TRUE on success, FALSE on failure
*/
BOOL
RemoveActiveSyn (
    DWORD dwServerIp,
    WORD wServerPort,
    DWORD dwClientIp,
    DWORD dwSequenceNumber
    )
{
    BOOL fSuccess = FALSE;
    BOOL fMutexHeld = FALSE;

    //
    // Wait for the Active SYN list mutex
    //
    if (WAIT_OBJECT_0 != WaitForSingleObject(
        g_hActiveSynMutex,
        INFINITE))
    {
        Log(
            Red,
            L"Error in RemoveActiveSyn(): WaitForSingleObject() failed "
            L"(0x%08X)\n",
            GetLastError());
        goto exit;
    }
    fMutexHeld = TRUE;

    //
    // Iterate through the Active SYN list to find target ACTIVE_SYN_ITEM
    //
    for(ACTIVE_SYN_ITEM* pItem = g_pActiveSyns;
        pItem != NULL;
        pItem = pItem->pNextItem)
    {
        //
        // If the current item is our target ACTIVE_SYN_ITEM, remove it from
        // the linked list
        //
        if ((pItem->dwServerIp == dwServerIp) &&
            (pItem->wServerPort == wServerPort) &&
            (pItem->dwClientIp == dwClientIp) &&
            (pItem->dwSequenceNumber == dwSequenceNumber))
        {
            //
            // Update the item's previous item
            //
            if (pItem->pPreviousItem == NULL)
            {
                g_pActiveSyns = pItem->pNextItem;
            }
            else
            {
                pItem->pPreviousItem->pNextItem = pItem->pNextItem;
            }

            //
            // Update the item's next item
            //
            if (pItem->pNextItem != NULL)
            {
                pItem->pNextItem->pPreviousItem = pItem->pPreviousItem;
            }

            //
            // Free the ACTIVE_SYN_ITEM from memory
            //
            free(pItem);

            fSuccess = TRUE;

            break;
        }
    }

exit:
    if (fMutexHeld)
    {
        ReleaseMutex(
            g_hActiveSynMutex);
    }

    return fSuccess;
}

/*! 
    @brief Adds a socket to the g_pAvailableEstablishedSockets linked list;
           allows for duplicate entries, by design

    @param[in] dwServerIp Remote server IP address
    @param[in] wServerPort Remote server TCP port
    @param[in] s SOCKS socket for the established connection
    @return Returns TRUE on success, FALSE on failure
*/
BOOL
AddAvailableEstablishedSocket (
    DWORD dwServerIp,
    WORD wServerPort,
    SOCKET s
    )
{
    BOOL fSuccess = FALSE;
    SOCKET_ITEM* pNewItem = NULL;
    SOCKET_ITEM* pItem;

    //
    // Allocate and initialize a new SOCKET_ITEM struct
    //
    pNewItem = (SOCKET_ITEM*)malloc(sizeof(SOCKET_ITEM));
    if (pNewItem == NULL)
    {
        Log(
            Red,
            L"Error in AddAvailableEstablishedSocket(): malloc(%d) failed\n",
            sizeof(SOCKET_ITEM));
        goto exit;
    }
    pNewItem->dwServerIp = dwServerIp;
    pNewItem->wServerPort = wServerPort;
    pNewItem->socket = s;

    //
    // Wait for the g_hAesMutex before touching the Available Established
    // Sockets list
    //
    if (WAIT_OBJECT_0 != WaitForSingleObject(
        g_hAesMutex,
        INFINITE))
    {
        Log(
            Red,
            L"Error in AddAvailableEstablishedSocket(): WaitForSingleObject() "
            L"failed (0x%08X)\n",
            GetLastError());
        goto exit;
    }
    
    fSuccess = TRUE;

    //
    // If the Available Established Sockets linked list is empty, set this new
    // SOCKET_ITEM as the first item in the list
    //
    if (g_pAvailableEstablishedSockets == NULL)
    {
        pNewItem->pPreviousSocketItem = NULL;
        pNewItem->pNextSocketItem = NULL;

        g_pAvailableEstablishedSockets = pNewItem;
        goto exit;
    }

    //
    // Find the last item in the Available Established Sockets linked list
    //
    for(pItem = g_pAvailableEstablishedSockets;
        pItem->pNextSocketItem != NULL;
        pItem = pItem->pNextSocketItem)
    {
        //
        // Do nothing
        //
    }
    
    //
    // Insert the new item into the linked list
    //
    pNewItem->pPreviousSocketItem = pItem;
    pNewItem->pNextSocketItem = NULL;
    pItem->pNextSocketItem = pNewItem;

exit:
    if (fSuccess)
    {
        ReleaseMutex(
            g_hAesMutex);
    }
    else if (pNewItem != NULL)
    {
        free(pNewItem);
    }

    return fSuccess;
}

/*! 
    @brief Finds a socket in the g_pAvailableEstablishedSockets linked list and
           removes that socket from the list if found

    @param[in] dwServerIp Remote server IP address of sought socket
    @param[in] wServerPort Remote server TCP port of sought socket
    @return Returns SOCKS socket for the established connection, or
            INVALID_SOCKET on error
*/
SOCKET
FindAvailableEstablishedSocket (
    DWORD dwServerIp,
    WORD wServerPort
    )
{
    SOCKET s = INVALID_SOCKET;
    BOOL fMutexHeld = FALSE;

    //
    // Wait for the g_hAesMutex before touching the Available Established
    // Sockets list
    //
    if (WAIT_OBJECT_0 != WaitForSingleObject(
        g_hAesMutex,
        INFINITE))
    {
        Log(
            Red,
            L"Error in FindAvailableEstablishedSocket(): "
            L"WaitForSingleObject() failed (0x%08X)\n",
            GetLastError());
        goto exit;
    }
    fMutexHeld = TRUE;

    //
    // Iterate through the g_pAvailableEstablishedSockets linked list
    //
    for(SOCKET_ITEM* pItem = g_pAvailableEstablishedSockets;
        pItem != NULL;
        pItem = pItem->pNextSocketItem)
    {
        //
        // If we found the target socket, remove it from the
        // g_pAvailableEstablishedSockets linked list and return the socket
        //
        if ((pItem->dwServerIp == dwServerIp) &&
            (pItem->wServerPort == wServerPort))
        {
            //
            // Return the found socket
            //
            s = pItem->socket;

            //
            // Update the item's previous item
            //
            if (pItem->pPreviousSocketItem == NULL)
            {
                g_pAvailableEstablishedSockets = pItem->pNextSocketItem;
            }
            else
            {
                pItem->pPreviousSocketItem->pNextSocketItem =
                    pItem->pNextSocketItem;
            }

            //
            // Update the item's next item
            //
            if (pItem->pNextSocketItem != NULL)
            {
                pItem->pNextSocketItem->pPreviousSocketItem =
                    pItem->pPreviousSocketItem;
            }

            //
            // Free the SOCKET_ITEM from memory
            //
            free(pItem);

            break;
        }
    }

exit:
    if (fMutexHeld)
    {
        ReleaseMutex(
            g_hAesMutex);
    }

    return s;
}

/*! 
    @brief Logs a packet to the PCAP log file

    @param[in] abPacket Pointer to raw packet data
    @param[in] cbPacket Length of raw packet data
*/
VOID
PcapLog (
    BYTE* abPacket,
    DWORD cbPacket
    )
{
    //
    // Only log the packet if Tortilla.ini specified a PCAP file
    //
    if (g_hPcapFile == INVALID_HANDLE_VALUE)
    {
        return;
    }

    //
    // Get the current time
    //
    _timeb t;
    if (0 != _ftime_s(&t))
    {
        return;
    }

    //
    // Initialize the PCAP header
    //
    pcaprec_hdr_t pcapHeader;
    pcapHeader.ts_sec = t.time;
    pcapHeader.ts_usec = t.millitm * 1000;
    pcapHeader.incl_len = cbPacket;
    pcapHeader.orig_len = cbPacket;

    //
    // Wait until the g_hPcapMutex mutex is available before writing to the
    // PCAP file
    //
    if (WAIT_OBJECT_0 != WaitForSingleObject(
        g_hPcapMutex,
        INFINITE))
    {
        return;
    }

    //
    // Write the PCAP header and packet data to the PCAP file
    //
    DWORD dwNumberOfBytesWritten;
    if (WriteFile(
        g_hPcapFile,
        &pcapHeader,
        sizeof(pcapHeader),
        &dwNumberOfBytesWritten,
        NULL) &&
        WriteFile(
        g_hPcapFile,
        abPacket,
        cbPacket,
        &dwNumberOfBytesWritten,
        NULL))
    {
        FlushFileBuffers(
            g_hPcapFile);
    }
    else
    {
        Log(
            Red,
            L"Error in PcapLog(): WriteFile() failed (0x%08X)\n",
            GetLastError());
    }

    //
    // Release the g_hPcapMutex mutex
    //
    ReleaseMutex(
        g_hPcapMutex);
}

/*! 
    @brief Sends packet to Tortilla driver to be forwarded to virtual machine

    @param[in] abPacket Pointer to raw packet data
    @param[in] cbPacket Length of raw packet data
*/
VOID
SendPacketToClient (
    BYTE* abPacket,
    SIZE_T cbPacket
    )
{
    //
    // Validate the length of the packet
    //
    if (cbPacket > MTU)
    {
        Log(
            Red,
            L"Error in SendPacketToClient(): Packet too large\n");
        return;
    }

    //
    // Wait for the g_hFromTortillaWritingEvent event
    //
    if (WAIT_OBJECT_0 != WaitForSingleObject(
        g_hFromTortillaWritingEvent,
        INFINITE))
    {
        Log(
            Red,
            L"Error in SendPacketToClient(): Error waiting for "
            L"g_hFromTortillaWritingEvent (0x%08X)\n",
            GetLastError());
        return;
    }

    //
    // Write the packet data to the memory mapped section shared with the
    // Tortilla driver
    //
    *(DWORD*)g_pFromTortillaFileMapping = cbPacket;
    memcpy(
        (BYTE*)g_pFromTortillaFileMapping + sizeof(DWORD),
        abPacket,
        cbPacket);

    //
    // Log the packet sent to the VM
    //
    PcapLog(
        abPacket,
        cbPacket);

    //
    // Notify the driver that we've just written a packet to the shared memory
    // section
    //
    if (!SetEvent(
        g_hFromTortillaWrittenEvent))
    {
        Log(
            Red,
            L"Error in SendPacketToClient(): "
            L"SetEvent(g_hFromTortillaWrittenEvent) failed (0x%08X)\n",
            GetLastError());
        return;
    }
}

/*! 
    @brief Get a DHCP Option value from a DHCP Options buffer

    @param[in] abOptions Pointer to a DHCP Options buffer
    @param[in] cbOptions Length of the DHCP Options buffer
    @param[in] bOption DHCP Option code to find
    @param[out] pabValue DHCP Option value for given DHCP Option code
    @param[out] pcbValue Length of DHCP Option value for given DHCP Option code
    @return Returns TRUE if DHCP Option value is found, returns FALSE on error
            or if DHCP Option value is not found
*/
BOOL
GetDhcpOption (
    BYTE* abOptions,
    SIZE_T cbOptions,
    BYTE bOption,
    BYTE** pabValue,
    BYTE* pcbValue
    )
{
    SIZE_T i = 0;
    BYTE bOptionCode;
    BYTE bValueSize;
    
    //
    // Iterate through each DHCP option
    //
    for(;;)
    {
        //
        // Don't read past the end of the DHCP Options buffer
        //
        if (i >= cbOptions)
        {
            return FALSE;
        }

        //
        // Read the Option code of the current Option
        //
        bOptionCode = abOptions[i++];

        //
        // Don't read past the end of the DHCP Options buffer
        //
        if (i >= cbOptions)
        {
            return FALSE;
        }

        //
        // Read the Option value length
        //
        bValueSize = abOptions[i++];

        //
        // Don't read past the end of the DHCP Options buffer
        //
        if ((i + bValueSize) > cbOptions)
        {
            return FALSE;
        }

        //
        // Compare the current Option code to our target Option code
        //
        if (bOptionCode == bOption)
        {
            *pabValue = &abOptions[i];
            *pcbValue = bValueSize;

            return TRUE;
        }
    }
}

/*! 
    @brief Responds to DHCP_DISCOVER and DHCP_REQUEST requests from the virtual
           machine

    @param[in] abPacket Pointer to raw packet data
    @param[in] cbPacket Length of raw packet data
*/
VOID
HandleDhcp (
    BYTE* abPacket,
    SIZE_T cbPacket
    )
{
    BYTE* abMessageType;
    BYTE cbMessageType;
    FULL_DHCP_PACKET_REPLY reply;
    pbuf* pBuf;
    DWORD dwLeaseTime;

    //
    // Get the DHCP message type
    //
    if (!GetDhcpOption(
        abPacket + sizeof(FULL_DHCP_PACKET),
        cbPacket - sizeof(FULL_DHCP_PACKET),
        DHCP_OPTION_MESSAGE_TYPE,
        &abMessageType,
        &cbMessageType))
    {
        return;
    }

    //
    // DHCP Message Type values are only 1 byte long
    //
    if (cbMessageType != DHCP_OPTION_MESSAGE_TYPE_LEN)
    {
        return;
    }

    //
    // Only respond to DHCP_DISCOVER and DHCP_REQUEST messages
    //
    if (!((*abMessageType == DHCP_DISCOVER) ||
        (*abMessageType == DHCP_REQUEST)))
    {
        return;
    }

    //
    // Copy the DHCP request packet (minus the DHCP Options) into the DHCP
    // response packet
    //
    memcpy(
        &reply.fullDhcpPacket,
        abPacket,
        sizeof(FULL_DHCP_PACKET));

    //
    // Set the Ethernet header
    //
    if (ntohs(reply.fullDhcpPacket.DhcpHeader.flags) & DHCP_BROADCAST_FLAG)
    {
        memset(
            &reply.fullDhcpPacket.EthernetHeader.dest,
            0xFF,
            sizeof(reply.fullDhcpPacket.EthernetHeader.dest));
    }
    else
    {
        memcpy(
            &reply.fullDhcpPacket.EthernetHeader.dest,
            &reply.fullDhcpPacket.EthernetHeader.src,
            sizeof(reply.fullDhcpPacket.EthernetHeader.dest));
    }
    memcpy(
        &reply.fullDhcpPacket.EthernetHeader.src,
        g_abGatewayMacAddress,
        sizeof(reply.fullDhcpPacket.EthernetHeader.src));

    //
    // Set the IP header
    //
    reply.fullDhcpPacket.IpHeader._len = htons(
        sizeof(reply) -
        sizeof(reply.fullDhcpPacket.EthernetHeader));
    memcpy(
        &reply.fullDhcpPacket.IpHeader.src,
        g_abGatewayIpAddress,
        sizeof(reply.fullDhcpPacket.IpHeader.src));
    if (ntohs(reply.fullDhcpPacket.DhcpHeader.flags) & DHCP_BROADCAST_FLAG)
    {
        memset(
            &reply.fullDhcpPacket.IpHeader.dest,
            0xFF,
            sizeof(reply.fullDhcpPacket.IpHeader.dest));
    }
    else
    {
        memcpy(
            &reply.fullDhcpPacket.IpHeader.dest,
            g_abDhcpClientIpAddress,
            sizeof(reply.fullDhcpPacket.IpHeader.dest));
    }
    reply.fullDhcpPacket.IpHeader._chksum = 0;
    reply.fullDhcpPacket.IpHeader._chksum = inet_chksum(
        &reply.fullDhcpPacket.IpHeader,
        sizeof(reply.fullDhcpPacket.IpHeader));

    //
    // Set the UDP header
    //
    reply.fullDhcpPacket.UdpHeader.src = htons(67);
    reply.fullDhcpPacket.UdpHeader.dest = htons(68);
    reply.fullDhcpPacket.UdpHeader.len = htons(
        sizeof(reply) -
        sizeof(reply.fullDhcpPacket.EthernetHeader) -
        sizeof(reply.fullDhcpPacket.IpHeader));
    reply.fullDhcpPacket.UdpHeader.chksum = 0;

    //
    // Set the DHCP header
    //
    reply.fullDhcpPacket.DhcpHeader.op = DHCP_BOOTREPLY;
    memcpy(
        &reply.fullDhcpPacket.DhcpHeader.yiaddr,
        g_abDhcpClientIpAddress,
        sizeof(reply.fullDhcpPacket.DhcpHeader.yiaddr));
    memcpy(
        &reply.fullDhcpPacket.DhcpHeader.siaddr,
        g_abGatewayIpAddress,
        sizeof(reply.fullDhcpPacket.DhcpHeader.siaddr));

    //
    // Set the DHCP options
    //
    reply.dhcpReplyOptions.MESSAGE_TYPE.ucOption = DHCP_OPTION_MESSAGE_TYPE;
    reply.dhcpReplyOptions.MESSAGE_TYPE.cbValue = 1;
    reply.dhcpReplyOptions.MESSAGE_TYPE.aucValue[0] =
        ((*abMessageType == DHCP_DISCOVER) ? DHCP_OFFER : DHCP_ACK);
    reply.dhcpReplyOptions.SUBNET_MASK.ucOption = DHCP_OPTION_SUBNET_MASK;
    reply.dhcpReplyOptions.SUBNET_MASK.cbValue = 4;
    memcpy(
        &reply.dhcpReplyOptions.SUBNET_MASK.aucValue,
        g_abDhcpClientSubnetMask,
        sizeof(reply.dhcpReplyOptions.SUBNET_MASK.aucValue));
    reply.dhcpReplyOptions.ROUTERS.ucOption = DHCP_OPTION_ROUTER;
    reply.dhcpReplyOptions.ROUTERS.cbValue = 4;
    memcpy(
        &reply.dhcpReplyOptions.ROUTERS.aucValue,
        g_abGatewayIpAddress,
        sizeof(reply.dhcpReplyOptions.ROUTERS.aucValue));
    reply.dhcpReplyOptions.LEASE_TIME.ucOption = DHCP_OPTION_LEASE_TIME;
    reply.dhcpReplyOptions.LEASE_TIME.cbValue = 4;
    dwLeaseTime = htonl(DHCP_LEASE_TIME);
    memcpy(
        &reply.dhcpReplyOptions.LEASE_TIME.aucValue,
        &dwLeaseTime,
        sizeof(reply.dhcpReplyOptions.LEASE_TIME.aucValue));
    reply.dhcpReplyOptions.SERVER_IDENTIFIER.ucOption = DHCP_OPTION_SERVER_ID;
    reply.dhcpReplyOptions.SERVER_IDENTIFIER.cbValue = 4;
    memcpy(
        &reply.dhcpReplyOptions.SERVER_IDENTIFIER.aucValue,
        g_abGatewayIpAddress,
        sizeof(reply.dhcpReplyOptions.SERVER_IDENTIFIER.aucValue));
    reply.dhcpReplyOptions.DOMAIN_NAME_SERVERS.ucOption =
        DHCP_OPTION_DNS_SERVER;
    reply.dhcpReplyOptions.DOMAIN_NAME_SERVERS.cbValue = 4;
    memcpy(
        &reply.dhcpReplyOptions.DOMAIN_NAME_SERVERS.aucValue,
        g_abGatewayIpAddress,
        sizeof(reply.dhcpReplyOptions.DOMAIN_NAME_SERVERS.aucValue));
    reply.dhcpReplyOptions.ucEnd = 0xFF;

    //
    // Set the UDP checksum
    //
    pBuf = pbuf_alloc(
        PBUF_RAW,
        sizeof(reply) - sizeof(eth_hdr) - sizeof(ip_hdr),
        PBUF_RAM);
    if (pBuf == NULL)
    {
        Log(
            Red,
            L"Error in HandleDhcp(): pbuf_alloc(..., %d, ...) failed\n",
            sizeof(reply) - sizeof(eth_hdr) - sizeof(ip_hdr));
        return;
    }
    memcpy(
        pBuf->payload,
        &reply.fullDhcpPacket.UdpHeader,
        sizeof(reply) - sizeof(eth_hdr) - sizeof(ip_hdr));
    reply.fullDhcpPacket.UdpHeader.chksum = inet_chksum_pseudo(
        pBuf,
        (ip_addr_t*)&reply.fullDhcpPacket.IpHeader.src,
        (ip_addr_t*)&reply.fullDhcpPacket.IpHeader.dest,
        IP_PROTO_UDP,
        sizeof(reply) - sizeof(eth_hdr) - sizeof(ip_hdr));
    if (reply.fullDhcpPacket.UdpHeader.chksum == 0)
    {
        reply.fullDhcpPacket.UdpHeader.chksum = 0xFFFF;
    }
    pbuf_free(pBuf);

    //
    // Send the DHCP response packet
    //
    SendPacketToClient(
        (BYTE*)&reply,
        sizeof(reply));
}

/*! 
    @brief Responds to an ARP request from the virtual machine

    @param[in] abPacket Pointer to raw packet data
    @param[in] cbPacket Length of raw packet data
*/
VOID
HandleArp (
    BYTE* abPacket,
    SIZE_T cbPacket
    )
{
    FULL_ARP_PACKET arp;
    BYTE abIp[4];

    //
    // Only respond to ARP requests for the Gateway IP address
    //
    if (0 != memcmp(
        ((FULL_ARP_PACKET*)abPacket)->ArpHeader.dipaddr.addrw,
        g_abGatewayIpAddress,
        sizeof(g_abGatewayIpAddress)))
    {
        return;
    }
    
    //
    // Copy the ARP request packet buffer into the ARP response packet buffer
    //
    memcpy(
        &arp,
        abPacket,
        sizeof(arp));

    //
    // Set the Ethernet header
    //
    memcpy(
        &arp.EthernetHeader.dest,
        &arp.EthernetHeader.src,
        sizeof(arp.EthernetHeader.dest));
    memcpy(
        &arp.EthernetHeader.src,
        g_abGatewayMacAddress,
        sizeof(arp.EthernetHeader.src));

    //
    // Set the ARP header
    //
    arp.ArpHeader.opcode = htons(ARP_REPLY);
    memcpy(
        abIp,
        &arp.ArpHeader.dipaddr.addrw,
        sizeof(abIp));
    memcpy(
        &arp.ArpHeader.dhwaddr,
        &arp.ArpHeader.shwaddr,
        sizeof(arp.ArpHeader.dhwaddr));
    memcpy(
        &arp.ArpHeader.dipaddr,
        &arp.ArpHeader.sipaddr,
        sizeof(arp.ArpHeader.dipaddr));
    memcpy(
        &arp.ArpHeader.shwaddr,
        g_abGatewayMacAddress,
        sizeof(arp.ArpHeader.shwaddr));
    memcpy(
        &arp.ArpHeader.sipaddr,
        abIp,
        sizeof(arp.ArpHeader.sipaddr));

    //
    // Send the ARP response to the virtual machine
    //
    SendPacketToClient(
        (BYTE*)&arp,
        sizeof(arp));
}

/*! 
    @brief Connects to and authenticates to the local Tor client

    @return Returns a TCP SOCKET on success, returns INVALID_SOCKET on failure
*/
SOCKET
ConnectToTorClient (
    VOID
    )
{
    BOOL fSuccess = FALSE;
    SOCKET s = INVALID_SOCKET;
    sockaddr_in sin;
    BYTE abSocksAuthenticationRequest[3];
    BYTE abSocksAuthenticationResponse[2];

    //
    // Create a new socket
    //
    s = socket(
        AF_INET,
        SOCK_STREAM,
        IPPROTO_TCP);
    if (s == INVALID_SOCKET)
    {
        Log(
            Red,
            L"Error in ConnectToTorClient(): Could not create a new socket "
            L"object (0x%08X)\n",
            WSAGetLastError());
        goto exit;
    }

    //
    // Connect to the local Tor client
    //
    sin.sin_family = AF_INET;
    sin.sin_addr.S_un.S_addr = g_dwTorClientIpAddress;
    sin.sin_port = htons(g_wTorClientTcpPort);
    memset(
        &sin.sin_zero,
        0,
        sizeof(sin.sin_zero));
    if (0 != connect(
        s,
        (sockaddr*)&sin,
        sizeof(sin)))
    {
        Log(
            Red,
            L"Error in ConnectToTorClient(): Could not connect to the local "
            L"Tor client (0x%08X)\nEnsure that Tor is running and that its "
            L"listening IP address and TCP port are\ncorrectly specified in "
            L"Tortilla.ini\n",
            WSAGetLastError());
        goto exit;
    }

    //
    // Perform authentication handshake with local Tor client
    //
    abSocksAuthenticationRequest[0] = 0x05; // SOCKS5
    abSocksAuthenticationRequest[1] = 0x01; // 1 authentication method
    abSocksAuthenticationRequest[2] = 0x00; // No authentication
    if (SOCKET_ERROR == send(
        s,
        (char*)abSocksAuthenticationRequest,
        sizeof(abSocksAuthenticationRequest),
        0))
    {
        Log(
            Red,
            L"Error in ConnectToTorClient(): send() failed (0x%08X)\n",
            WSAGetLastError());
        goto exit;
    }
    if (sizeof(abSocksAuthenticationResponse) != recv(
        s,
        (char*)abSocksAuthenticationResponse,
        sizeof(abSocksAuthenticationResponse),
        0))
    {
        Log(
            Red,
            L"Error in ConnectToTorClient(): recv() failed (0x%08X)\n",
            WSAGetLastError());
        goto exit;
    }
    if (!((abSocksAuthenticationResponse[0] == 0x05) && // SOCKS5
        (abSocksAuthenticationResponse[1] == 0x00)))    // No authentication
    {
        Log(
            Red,
            L"Error in ConnectToTorClient(): Could not authenticate to local "
            L"Tor client\n");
        goto exit;
    }

    fSuccess = TRUE;

exit:
    if ((!fSuccess) && (s != INVALID_SOCKET))
    {
        closesocket(s);
        s = INVALID_SOCKET;
    }

    return s;
}

/*! 
    @brief Extracts the queried name or IP from a DNS query

    @param[in] abPacket Pointer to raw packet data
    @param[in] cbPacket Length of raw packet data
    @param[out] szName Buffer where name or IP will be written
    @param[in] cchName Size of szName buffer
    @param[out] pfTypeAQuery TRUE if DNS_TYPE_A query, FALSE if DNS_TYPE_PTR
                             query
    @return TRUE on success, FALSE on error
*/
BOOL
ExtractNameFromDnsQuery (
    BYTE* abPacket,
    SIZE_T cbPacket,
    CHAR* szName,
    SIZE_T cchName,
    BOOL* pfTypeAQuery
    )
{
    BYTE bNameIndex;
    BYTE bQNameIndex;
    BOOL fReadingLabelLength;
    BYTE cbLabel;
    DNS_WIRE_QUESTION* pQuestion;
    in_addr addrIp;

    //
    // Extract the queried name or IP from the DNS query
    //
    bNameIndex = 0;
    fReadingLabelLength = TRUE;
    for (bQNameIndex = 0; ; bQNameIndex++)
    {
        //
        // Don't read past the end of the packet
        //
        if ((sizeof(FULL_DNS_PACKET) + bQNameIndex) >= cbPacket)
        {
            Log(
                Red,
                L"Error in ExtractNameFromDnsQuery(): "
                L"(sizeof(FULL_DNS_PACKET) + ucQNameIndex) >= cbPacket\n");
            return FALSE;
        }

        if (fReadingLabelLength)
        {
            //
            // Read the length of the label
            //
            cbLabel = abPacket[sizeof(FULL_DNS_PACKET) + bQNameIndex];
            if (cbLabel > DNS_MAX_LABEL_LENGTH)
            {
                Log(
                    Red,
                    L"Error in ExtractNameFromDnsQuery(): Label length too "
                    L"long\n");
                return FALSE;
            }

            //
            // If there are no more labels to read
            //
            if (cbLabel == 0)
            {
                //
                // Stop extracting the queried name or IP
                //
                bQNameIndex++;
                break;
            }

            //
            // Append a '.' to the szName buffer
            //
            if (bQNameIndex != 0)
            {
                if (bNameIndex >= cchName)
                {
                    Log(
                        Red,
                        L"Error in ExtractNameFromDnsQuery(): Queried name "
                        L"too long\n");
                    return FALSE;
                }
                szName[bNameIndex++] = '.';
            }

            //
            // Next, read the label string
            //
            fReadingLabelLength = FALSE;
            continue;
        }

        //
        // Read the next character in the label string
        //
        if (bNameIndex >= cchName)
        {
            Log(
                Red,
                L"Error in ExtractNameFromDnsQuery(): Queried name "
                L"too long\n");
            return FALSE;
        }
        szName[bNameIndex++] =
            abPacket[sizeof(FULL_DNS_PACKET) + bQNameIndex];
        
        //
        // If we're done reading this label string
        //
        if (--cbLabel == 0)
        {
            //
            // Next, read the next label's length
            //
            fReadingLabelLength = TRUE;
        }
    }

    //
    // Ensure that the queried name is not a NULL-string, and NULL-terminate it
    //
    if ((bNameIndex == 0) || (bNameIndex >= cchName))
    {
        Log(
            Red,
            L"Error in ExtractNameFromDnsQuery(): Invalid length for queried "
            L"name\n");
        return FALSE;
    }
    szName[bNameIndex] = 0;

    //
    // Validate the QuestionClass
    //
    if ((sizeof(FULL_DNS_PACKET) + bQNameIndex + sizeof(DNS_WIRE_QUESTION)) >
        cbPacket)
    {
        Log(
            Red,
            L"Error in ExtractNameFromDnsQuery(): Packet too small to contain "
            L"a DNS_WIRE_QUESTION\n");
        return FALSE;
    }
    pQuestion =
        (DNS_WIRE_QUESTION*)&abPacket[sizeof(FULL_DNS_PACKET) + bQNameIndex];
    if (pQuestion->QuestionClass != htons(DNS_CLASS_INTERNET))
    {
        Log(
            Red,
            L"Error in ExtractNameFromDnsQuery(): Query is not for "
            L"DNS_CLASS_INTERNET\n");
        return FALSE;
    }

    //
    // Drop the ".in-addr.arpa" from a DNS_TYPE_PTR query and reverse the
    //   order of the octet labels in the IP address string
    //
    if (pQuestion->QuestionType == htons(DNS_TYPE_A))
    {
        *pfTypeAQuery = TRUE;
    }
    else if (pQuestion->QuestionType == htons(DNS_TYPE_PTR))
    {
        *pfTypeAQuery = FALSE;

        //
        // Validate the minimum length of the DNS_TYPE_PTR name
        //
        if ((size_t)(bNameIndex - 1) < (strlen("0.0.0.0.in-addr.arpa")))
        {
            Log(
                Red,
                L"Error in ExtractNameFromDnsQuery(): Invalid length for "
                L"DNS_TYPE_PTR name\n");
            return FALSE;
        }

        //
        // Drop the ".in-addr.arpa" from the queried name
        //
        bNameIndex -= strlen(".in-addr.arpa");
        szName[bNameIndex] = 0;

        //
        // Convert the ASCII IP address to an unsigned long and reverse its
        // endianness
        //
        addrIp.S_un.S_addr = ntohl(inet_addr(szName));
        if (addrIp.S_un.S_addr == INADDR_NONE)
        {
            Log(
                Red,
                L"Error in ExtractNameFromDnsQuery(): DNS_TYPE_PTR query "
                L"appears to be for an invalid IP address\n");
            return FALSE;
        }

        //
        // Convert the unsigned long IP address with reversed endianness back
        // to an ASCII IP address
        //
        if (0 != strcpy_s(
            szName,
            cchName,
            inet_ntoa(addrIp)))
        {
            Log(
                Red,
                L"Error in ExtractNameFromDnsQuery(): Could not copy IP "
                L"address to string buffer\n");
            return FALSE;
        }
    }
    else
    {
        //wprintf_s(
        //    L"Error in ExtractNameFromDnsQuery(): Query is not for "
        //    L"DNS_TYPE_A or DNS_TYPE_PTR\n");
        return FALSE;
    }

    return TRUE;
}

/*! 
    @brief Responds to a DNS query from the virtual machine

    @param[in] pParameter Pointer to a PACKET_WITH_SIZE struct
    @return Always returns 0
*/
UINT
__stdcall
HandleDns (
    VOID* pParameter
    )
{
    SOCKET s = INVALID_SOCKET;
    BYTE* abDnsResponsePacket = NULL;
    BOOL fSuccess = FALSE;
    BOOL fTypeAQuery;
    CHAR szName[DNS_MAX_NAME_BUFFER_LENGTH];
    BOOL fNameExtracted = FALSE;
    PACKET_WITH_SIZE* pPacket = (PACKET_WITH_SIZE*)pParameter;
    BYTE abSocksDnsRequest[DNS_MAX_NAME_LENGTH + 7];
    SIZE_T cchNameLength;
    DWORD dwIp;
    DWORD dwResolvedIp;
    BYTE cbResolvedName;
    CHAR szResolvedName[DNS_MAX_NAME_BUFFER_LENGTH];
    CHAR acSocksDnsResponse[DNS_MAX_NAME_LENGTH + 7];
    INT cbSocksDnsResponse;
    SIZE_T cbDnsResponsePacket;
    FULL_DNS_PACKET* pFullDnsResponsePacket;
    DNS_ANSWER_RECORD* pDnsAnswerRecord;
    BYTE cbLabel;
    CHAR* pcQName;
    pbuf* pBuf;
    CHAR c;

    //
    // Extract the hostname or IP address from the DNS query
    //
    if (!ExtractNameFromDnsQuery(
        pPacket->abPacket,
        pPacket->cbPacket,
        szName,
        _countof(szName),
        &fTypeAQuery))
    {
        goto sendResponse;
    }
    fNameExtracted = TRUE;

    //
    // Connect to and authenticate to the local Tor client
    //
    s = ConnectToTorClient();
    if (s == INVALID_SOCKET)
    {
        goto sendResponse;
    }

    //
    // Send the DNS request to the local Tor client
    //
    cchNameLength = strlen(szName);
    abSocksDnsRequest[0] = 0x05;                // SOCKS5
    if (fTypeAQuery)
    {
        abSocksDnsRequest[1] = (BYTE)SOCKS_COMMAND_RESOLVE; // Command
        abSocksDnsRequest[2] = 0x00;            // Reserved
        abSocksDnsRequest[3] = 0x03;            // Address type: FQDN
        abSocksDnsRequest[4] = cchNameLength;   // FQDN length
        memcpy(                                 // FQDN
            &abSocksDnsRequest[5],
            szName,
            cchNameLength);
        abSocksDnsRequest[5 + cchNameLength] = 0x00;  // Port
        abSocksDnsRequest[6 + cchNameLength] = 0x00;  // Port
    }
    else
    {
        abSocksDnsRequest[1] = (BYTE)SOCKS_COMMAND_RESOLVE_PTR; // Command
        abSocksDnsRequest[2] = 0x00;    // Reserved
        abSocksDnsRequest[3] = 0x01;    // Address type: IPv4
        dwIp = inet_addr(szName);
        memcpy(                         // IP
            &abSocksDnsRequest[4],
            &dwIp,
            sizeof(dwIp));
        abSocksDnsRequest[8] = 0x00;    // Port
        abSocksDnsRequest[9] = 0x00;    // Port
    }
    if (SOCKET_ERROR == send(
        s,
        (char*)abSocksDnsRequest,
        fTypeAQuery ? (7 + cchNameLength) : 10,
        0))
    {
        Log(
            Red,
            L"Error in HandleDns(): Could not send DNS request to local Tor "
            L"client (0x%08X)\n",
            WSAGetLastError());
        goto sendResponse;
    }

    //
    // Get DNS response from local Tor client
    //
    cbSocksDnsResponse = recv(
        s,
        acSocksDnsResponse,
        sizeof(acSocksDnsResponse),
        0);
    if (cbSocksDnsResponse == SOCKET_ERROR)
    {
        Log(
            Red,
            L"Error in HandleDns(): Could not receive DNS response from local "
            L"Tor client (0x%08X)\n",
            WSAGetLastError());
        goto sendResponse;
    }
    if (fTypeAQuery)
    {
        //
        // Query was a hostname, so validate that response is an IP address
        //
        if (!((cbSocksDnsResponse == 10) &&
            (acSocksDnsResponse[0] == 0x05) &&  // SOCKS5
            (acSocksDnsResponse[1] == 0x00) &&  // SOCKS5_SUCCEEDED
            (acSocksDnsResponse[3] == 0x01)))   // IPv4 address
        {
            //wprintf_s(
            //    L"Error in HandleDns(): DNS_TYPE_A lookup failed\n");
            goto sendResponse;
        }

        //
        // Save the response IP address
        //
        memcpy(
            &dwResolvedIp,
            &acSocksDnsResponse[4],
            sizeof(dwResolvedIp));
    }
    else 
    {
        //
        // Query was an IP address, so validate that response is a hostname
        //
        if (!((cbSocksDnsResponse >= 7) &&
            (acSocksDnsResponse[0] == 0x05) &&  // SOCKS5
            (acSocksDnsResponse[1] == 0x00) &&  // SOCKS5_SUCCEEDED
            (acSocksDnsResponse[3] == 0x03)))   // Domain name
        {
            //wprintf_s(
            //    L"Error in HandleDns(): DNS_TYPE_PTR lookup failed\n");
            goto sendResponse;
        }

        //
        // Validate the length of the resolved hostname
        //
        cbResolvedName = acSocksDnsResponse[4];
        if ((cbResolvedName == 0) ||
            (cbSocksDnsResponse != ((size_t)cbResolvedName + 7)))
        {
            Log(
                Red,
                L"Error in HandleDns(): DNS_TYPE_PTR lookup returned hostname "
                L"with invalid length\n");
            goto sendResponse;
        }
        
        //
        // Save the response hostname and NULL-terminate it
        //
        memcpy(
            szResolvedName,
            &acSocksDnsResponse[5],
            cbResolvedName);
        szResolvedName[cbResolvedName] = 0;
    }

    fSuccess = TRUE;


sendResponse:
    //
    // Allocate a success/fail DNS response back to client
    //
    cbDnsResponsePacket = pPacket->cbPacket;
    if (fSuccess)
    {
        //
        // If we have a DNS answer to send back, allocate space for it
        //
        cbDnsResponsePacket += sizeof(DNS_ANSWER_RECORD) + (fTypeAQuery ?
            sizeof(dwResolvedIp) : ((size_t)cbResolvedName + 2));
    }
    abDnsResponsePacket = (BYTE*)malloc(
        cbDnsResponsePacket);
    if (abDnsResponsePacket == NULL)
    {
        Log(
            Red,
            L"Error in HandleDns(): malloc(%d) failed\n",
            cbDnsResponsePacket);
        goto exit;
    }

    //
    // Copy the DNS request packet into the DNS response packet
    //
    memcpy(
        abDnsResponsePacket,
        pPacket->abPacket,
        pPacket->cbPacket);

    //
    // Set the Ethernet header
    //
    pFullDnsResponsePacket = (FULL_DNS_PACKET*)abDnsResponsePacket;
    memcpy(
        &pFullDnsResponsePacket->EthernetHeader.dest,
        &pFullDnsResponsePacket->EthernetHeader.src,
        sizeof(pFullDnsResponsePacket->EthernetHeader.dest));
    memcpy(
        &pFullDnsResponsePacket->EthernetHeader.src,
        g_abGatewayMacAddress,
        sizeof(pFullDnsResponsePacket->EthernetHeader.src));

    //
    // Set the IP header
    //
    pFullDnsResponsePacket->IpHeader._len = htons(
        cbDnsResponsePacket -
        sizeof(pFullDnsResponsePacket->EthernetHeader));
    memcpy(
        &pFullDnsResponsePacket->IpHeader.src,
        g_abGatewayIpAddress,
        sizeof(pFullDnsResponsePacket->IpHeader.src));
    memcpy(
        &pFullDnsResponsePacket->IpHeader.dest,
        g_abDhcpClientIpAddress,
        sizeof(pFullDnsResponsePacket->IpHeader.dest));
    pFullDnsResponsePacket->IpHeader._chksum = 0;
    pFullDnsResponsePacket->IpHeader._chksum = inet_chksum(
        &pFullDnsResponsePacket->IpHeader,
        sizeof(pFullDnsResponsePacket->IpHeader));

    //
    // Set the UDP header
    //
    pFullDnsResponsePacket->UdpHeader.dest =
        pFullDnsResponsePacket->UdpHeader.src;
    pFullDnsResponsePacket->UdpHeader.src = htons(53);
    pFullDnsResponsePacket->UdpHeader.len = htons(
        cbDnsResponsePacket -
        sizeof(pFullDnsResponsePacket->EthernetHeader) -
        sizeof(pFullDnsResponsePacket->IpHeader));
    pFullDnsResponsePacket->UdpHeader.chksum = 0;

    //
    // Set the DNS header
    //
    pFullDnsResponsePacket->DnsHeader.IsResponse = TRUE;
    pFullDnsResponsePacket->DnsHeader.Opcode = DNS_OPCODE_QUERY;
    pFullDnsResponsePacket->DnsHeader.Authoritative = FALSE;
    pFullDnsResponsePacket->DnsHeader.Truncation = FALSE;
    pFullDnsResponsePacket->DnsHeader.RecursionAvailable = TRUE;
    pFullDnsResponsePacket->DnsHeader.Reserved = FALSE;
    pFullDnsResponsePacket->DnsHeader.AuthenticatedData = FALSE;
    pFullDnsResponsePacket->DnsHeader.CheckingDisabled = FALSE;
    pFullDnsResponsePacket->DnsHeader.ResponseCode = fSuccess ?
        DNS_RCODE_NOERROR :
        DNS_RCODE_SERVFAIL;
    pFullDnsResponsePacket->DnsHeader.AnswerCount = htons(
        fSuccess ? 1 : 0);

    //
    // Construct the DNS_ANSWER_RECORD
    //
    if (fSuccess)
    {
        pDnsAnswerRecord =
            (DNS_ANSWER_RECORD*)((BYTE*)pFullDnsResponsePacket +
            pPacket->cbPacket);

        pDnsAnswerRecord->CompressedName = htons(0xC00C); // Name pointer
        pDnsAnswerRecord->DnsWireRecord.RecordType =
            htons(fTypeAQuery ? DNS_TYPE_A : DNS_TYPE_PTR);
        pDnsAnswerRecord->DnsWireRecord.RecordClass =
            htons(DNS_CLASS_INTERNET);
        pDnsAnswerRecord->DnsWireRecord.TimeToLive = htonl(DNS_TTL);
        if (fTypeAQuery)
        {
            pDnsAnswerRecord->DnsWireRecord.DataLength =
                htons(sizeof(dwResolvedIp));
            memcpy(
                (PVOID)((BYTE*)pDnsAnswerRecord +
                sizeof(DNS_ANSWER_RECORD)),
                &dwResolvedIp,
                sizeof(dwResolvedIp));
        }
        else
        {
            pDnsAnswerRecord->DnsWireRecord.DataLength =
                htons((size_t)cbResolvedName + 2);
            cbLabel = 0;
            pcQName = (char*)pDnsAnswerRecord + sizeof(DNS_ANSWER_RECORD);
            for (size_t iResolvedName = 0;
                iResolvedName < ((size_t)cbResolvedName + 1);
                iResolvedName++)
            {
                c = szResolvedName[iResolvedName];

                if ((c == 0) || (c == '.'))
                {
                    *pcQName++ = cbLabel;
                    memcpy(
                        pcQName,
                        &szResolvedName[iResolvedName - cbLabel],
                        cbLabel);
                    pcQName += cbLabel;
                    cbLabel = 0;

                    continue;
                }

                cbLabel++;
            }
            *pcQName = 0;
        }
    }

    //
    // Set the UDP checksum
    //
    pBuf = pbuf_alloc(
        PBUF_RAW,
        cbDnsResponsePacket - sizeof(eth_hdr) - sizeof(ip_hdr),
        PBUF_RAM);
    if (pBuf == NULL)
    {
        Log(
            Red,
            L"Error in HandleDns(): pbuf_alloc(..., %d, ...) failed\n",
            cbDnsResponsePacket - sizeof(eth_hdr) - sizeof(ip_hdr));
        goto exit;
    }
    memcpy(
        pBuf->payload,
        &pFullDnsResponsePacket->UdpHeader,
        cbDnsResponsePacket - sizeof(eth_hdr) - sizeof(ip_hdr));
    pFullDnsResponsePacket->UdpHeader.chksum = inet_chksum_pseudo(
        pBuf,
        (ip_addr_t*)&pFullDnsResponsePacket->IpHeader.src,
        (ip_addr_t*)&pFullDnsResponsePacket->IpHeader.dest,
        IP_PROTO_UDP,
        cbDnsResponsePacket - sizeof(eth_hdr) - sizeof(ip_hdr));
    if (pFullDnsResponsePacket->UdpHeader.chksum == 0)
    {
        pFullDnsResponsePacket->UdpHeader.chksum = 0xFFFF;
    }
    pbuf_free(pBuf);

    //
    // Send the DNS response to the virtual machine
    //
    SendPacketToClient(
        abDnsResponsePacket,
        cbDnsResponsePacket);

exit:
    if (fNameExtracted)
    {
        if (fSuccess)
        {
            Log(
                Cyan,
                L"Resolved DNS query for %S to %S\n",
                szName,
                fTypeAQuery ? inet_ntoa(*(in_addr*)&dwResolvedIp) :
                szResolvedName);
        }
        else
        {
            Log(
                Red,
                L"Failed to resolve DNS query for %S\n",
                szName);
        }
    }

    if (abDnsResponsePacket != NULL)
    {
        free(abDnsResponsePacket);
    }
    if (s != INVALID_SOCKET)
    {
        closesocket(s);
    }
    free(pParameter);

    return 0;
}

/*! 
    @brief Connect to a remote server via Tor
    @details If the TCP connection is successfully established, ConnectViaTor()
             adds the connected socket to the list of Available Established
             Sockets and returns TRUE. If the connection request is actively
             refused by the remote server (SOCKS response status 0x05),
             ConnectViaTor() responds to the virtual machine with a TCP RST
             (without using lwIP) and returns FALSE. If the connection request
             is passively refused or if another error occurs, ConnectViaTor()
             simply returns FALSE, effectively dropping the TCP SYN packet. 

    @param[in] pTcp The original TCP SYN packet from the virtual machine
    @return Returns TRUE if the connection was successfully established,
            returns FALSE otherwise
*/
BOOL
ConnectViaTor (
    FULL_TCP_PACKET* pTcp
    )
{
    SOCKET s;
    BOOL fSuccess = FALSE;
    BYTE abSocksTcpRequest[10];
    BYTE abSocksConnectionResponse[10];
    INT cbSocksConnectionResponse;
    FULL_TCP_PACKET tcpReset;
    pbuf* pBuf;

    //
    // Connect to and authenticate to the local Tor client
    //
    s = ConnectToTorClient();
    if (s == INVALID_SOCKET)
    {
        goto exit;
    }

    //
    // Send the connection request to the local Tor client
    //
    abSocksTcpRequest[0] = 0x05;                    // SOCKS5
    abSocksTcpRequest[1] = SOCKS_COMMAND_CONNECT;   // Command
    abSocksTcpRequest[2] = 0x00;                    // Reserved
    abSocksTcpRequest[3] = 0x01;                    // Address type: IPv4
    memcpy(                                         // Destination IP
        &abSocksTcpRequest[4],
        &pTcp->IpHeader.dest,
        sizeof(pTcp->IpHeader.dest));
    memcpy(                                         // Destination port
        &abSocksTcpRequest[8],
        &pTcp->TcpHeader.dest,
        sizeof(pTcp->TcpHeader.dest));
    if (SOCKET_ERROR == send(
        s,
        (char*)abSocksTcpRequest,
        _countof(abSocksTcpRequest),
        0))
    {
        Log(
            Red,
            L"Error in ConnectViaTor(): send() failed when attempting to send "
            L"the connection request to the local Tor client\n");
        goto exit;
    }

    //
    // Get connection response from the local Tor client
    //
    cbSocksConnectionResponse = recv(
        s,
        (char*)abSocksConnectionResponse,
        sizeof(abSocksConnectionResponse),
        0);
    if (!((cbSocksConnectionResponse == sizeof(abSocksConnectionResponse)) &&
        (abSocksConnectionResponse[0] == 0x05)))
    {
        Log(
            Red,
            L"Error in ConnectViaTor(): Unexpected response from the local "
            L"Tor client\n");
        goto exit;
    }

    //
    // Process the connection response from the local Tor client
    //
    if (abSocksConnectionResponse[1] == 0x00)
    {
        //
        // The local Tor service was able to connect to the target server, so
        // add this conncted SOCKS socket to the list of Available Established
        // Sockets
        //
        if (AddAvailableEstablishedSocket(
            pTcp->IpHeader.dest.addr,
            pTcp->TcpHeader.dest,
            s))
        {
            fSuccess = TRUE;
        }

        Log(
            Green,
            L"Connected to %S:%d (socket #%d)\n",
            inet_ntoa(*(in_addr*)&pTcp->IpHeader.dest),
            ntohs(pTcp->TcpHeader.dest),
            s);

        goto exit;
    }
    else if (abSocksConnectionResponse[1] != 0x05)
    {
        //
        // The SOCKS client informed us that there was a passive connection
        // failure
        //

        Log(
            Red,
            L"Could not connect to %S:%d\n",
            inet_ntoa(*(in_addr*)&pTcp->IpHeader.dest),
            ntohs(pTcp->TcpHeader.dest));

        goto exit;
    }

    //
    // The remote server actively refused the connection attempt, so respond to
    // the virtual machine with a TCP SYN packet
    //

    Log(
        Red,
        L"Connection request refused by %S:%d\n",
        inet_ntoa(*(in_addr*)&pTcp->IpHeader.dest),
        ntohs(pTcp->TcpHeader.dest));

    //
    // Set the Ethernet header
    //
    memcpy(
        &tcpReset.EthernetHeader.dest,
        &pTcp->EthernetHeader.src,
        sizeof(tcpReset.EthernetHeader.dest));
    memcpy(
        &tcpReset.EthernetHeader.src,
        &pTcp->EthernetHeader.dest,
        sizeof(tcpReset.EthernetHeader.dest));
    tcpReset.EthernetHeader.type = pTcp->EthernetHeader.type;

    //
    // Set the IP header
    //
    tcpReset.IpHeader._v_hl = 0x45;
    tcpReset.IpHeader._tos = 0;
    tcpReset.IpHeader._len = htons(
        sizeof(tcpReset) - sizeof(tcpReset.EthernetHeader));
    tcpReset.IpHeader._id = 0;
    tcpReset.IpHeader._offset = 0;
    tcpReset.IpHeader._ttl = 64;
    tcpReset.IpHeader._proto = IPPROTO_TCP;
    tcpReset.IpHeader.src = pTcp->IpHeader.dest;
    tcpReset.IpHeader.dest = pTcp->IpHeader.src;
    tcpReset.IpHeader._chksum = 0;
    tcpReset.IpHeader._chksum = inet_chksum(
        &tcpReset.IpHeader,
        sizeof(tcpReset.IpHeader));
            
    //
    // Set the TCP header
    //
    tcpReset.TcpHeader.src = pTcp->TcpHeader.dest;
    tcpReset.TcpHeader.dest = pTcp->TcpHeader.src;
    tcpReset.TcpHeader.seqno = 0;
    tcpReset.TcpHeader.ackno = htonl(
        ntohl(pTcp->TcpHeader.seqno) + 1);
    TCPH_HDRLEN_SET(&tcpReset.TcpHeader, 5);
    TCPH_UNSET_FLAG(&tcpReset.TcpHeader, TCP_CWR);
    TCPH_UNSET_FLAG(&tcpReset.TcpHeader, TCP_ECE);
    TCPH_UNSET_FLAG(&tcpReset.TcpHeader, TCP_URG);
    TCPH_SET_FLAG(&tcpReset.TcpHeader, TCP_ACK);
    TCPH_UNSET_FLAG(&tcpReset.TcpHeader, TCP_PSH);
    TCPH_SET_FLAG(&tcpReset.TcpHeader, TCP_RST);
    TCPH_UNSET_FLAG(&tcpReset.TcpHeader, TCP_SYN);
    TCPH_UNSET_FLAG(&tcpReset.TcpHeader, TCP_FIN);
    tcpReset.TcpHeader.wnd = 0;
    tcpReset.TcpHeader.urgp = 0;
    tcpReset.TcpHeader.chksum = 0;

    //
    // Set the TCP checksum
    //
    pBuf = pbuf_alloc(
        PBUF_RAW,
        sizeof(tcpReset),
        PBUF_RAM);
    if (pBuf == NULL)
    {
        Log(
            Red,
            L"Error in ConnectViaTor(): pbuf_alloc() failed\n");
        goto exit;
    }
    memcpy(
        pBuf->payload,
        &tcpReset,
        sizeof(tcpReset));
    tcpReset.TcpHeader.chksum = inet_chksum_pseudo(
        pBuf,
        (ip_addr_t*)&tcpReset.IpHeader.src,
        (ip_addr_t*)&tcpReset.IpHeader.dest,
        IP_PROTO_TCP,
        pBuf->tot_len);
    pbuf_free(pBuf);

    //
    // Send the TCP RST packet to the virtual machine
    //
    SendPacketToClient(
        (BYTE*)&tcpReset,
        sizeof(tcpReset));

exit:
    if ((s != INVALID_SOCKET) && (!fSuccess))
    {
        closesocket(s);
    }

    return fSuccess;
}

/*! 
    @brief Handle a TCP packet received from the virtual machine

    @param[in] pParameter Pointer to a PACKET_WITH_SIZE struct
    @return Always returns 0
*/
VOID
__stdcall
HandleTcp (
    BYTE* Packet,
	DWORD PacketLength
    )
{
    pbuf* pBuf;

    //
    // Send the TCP packet to the lwIP TCP/IP stack
    //
    pBuf = pbuf_alloc(
        PBUF_RAW,
		PacketLength,
        PBUF_RAM);
    if (pBuf == NULL)
    {
        Log(
            Red,
            L"Error in HandleTcp(): pbuf_alloc() failed\n");
        goto exit;
    }
    memcpy(
        pBuf->payload,
        Packet,
        PacketLength);
    if (ERR_OK != tcpip_input(
        pBuf,
        &netif))
    {
        Log(
            Red,
            L"Error in HandleTcp(): tcpip_input() failed\n");

        pbuf_free(
            pBuf);

        goto exit;
    }

exit:
	return;
}

UINT
__stdcall
HandleTcpSyn(
	PVOID Parameter
	)
{
	PACKET_WITH_SIZE *packet = (PACKET_WITH_SIZE*)Parameter;
	FULL_TCP_PACKET *pTcp = (FULL_TCP_PACKET*) packet->abPacket;

	if (ConnectViaTor(pTcp))
	{
		HandleTcp(packet->abPacket, packet->cbPacket);
	}
    
    free(Parameter);

	return 0;
}

/*! 
    @brief Forward TCP data from the virtual machine to the Tor SOCKS socket
           and from the Tor SOCKS socket to the virtual machine (this must be
           done in a single thread since lwIP does not support full-duplex TCP
           (http://lwip.wikia.com/wiki/LwIP_and_multithreading))

    @param[in] arg Pointer to a SOCKET_BRIDGE struct
*/
VOID 
tortilla_tcp_forwarder (
    VOID* arg
    )
{
    SOCKET_BRIDGE* pSocketBridge = (SOCKET_BRIDGE*)arg;
    DWORD dwServerIpAddress;
    WORD wServerTcpPort;
    err_t err;
    struct netbuf* pBuf;
    BYTE* abReceivedFromVm;
    WORD cbReceivedFromVm;
    BYTE abReceivedFromServer[0xFFFF];
    INT cbReceivedFromServer;
    BOOL fSendError = FALSE;
    BOOL fClosedByVm = FALSE;
    BOOL fClosedByServer = FALSE;
	BOOL fTorReadClosed = FALSE;
	BOOL fVmReadClosed = FALSE;
	INT i;
	fd_set readfds;
	TIMEVAL timeout;

    //
    // Save connection information
    //
    dwServerIpAddress = pSocketBridge->lwIPConn->pcb.tcp->local_ip.addr;
    wServerTcpPort = pSocketBridge->lwIPConn->pcb.tcp->local_port;

    //
    // Set the recv timeout for reading from the virtual machine
    //
    netconn_set_recvtimeout(
        pSocketBridge->lwIPConn,
        RECV_TIMEOUT_MS);

    //
    // Keep polling for received data and forwarding it
    //
    for(;;)
    {
		for (i = 0; !fVmReadClosed && i < MAX_PACKETS_PER_ITERATION; i++)
		{
			//
			// Try to receive data from the virtual machine
			//
			err = netconn_recv(
				pSocketBridge->lwIPConn,
				&pBuf);

			//
			// If data was received from the virtual machine, forward it to the
            // Tor SOCKS socket
			//
			if (err == ERR_OK)
			{
				do
				{
					if (!((ERR_OK == netbuf_data(
						pBuf,
						(VOID**) &abReceivedFromVm,
						&cbReceivedFromVm)) &&
						(SOCKET_ERROR != send(
						pSocketBridge->torSocket,
						(char*) abReceivedFromVm,
						cbReceivedFromVm,
						0))))
					{
						fSendError = TRUE;
						break;
					}
				} while (netbuf_next(pBuf) >= 0);
				netbuf_delete(pBuf);

				//
				// If there was an error forwarding the data to the Tor SOCKS
				// socket then close both sides of this connection
				//
				if (fSendError)
				{
					fClosedByServer = TRUE;
					goto exit;
				}
			}
			else
			{
				break;
			}
		}

        //
        // If a non-timeout error occurred while trying to read data from the
        // virtual machine then close both sides of this connection
        //
		if (err == ERR_CLSD)
		{
			shutdown(pSocketBridge->torSocket, 1);
			fVmReadClosed = TRUE;
            if (!fTorReadClosed)
            {
                fClosedByVm = TRUE;
            }
		}
        else if ((err != ERR_OK) && (err != ERR_TIMEOUT))
        {
            fClosedByVm = TRUE;
            goto exit;
        }

		if (fTorReadClosed && fVmReadClosed)
		{
			goto exit;
		}

		for (i = 0; !fTorReadClosed && i < MAX_PACKETS_PER_ITERATION; i++)
		{
			FD_ZERO(&readfds);
			FD_SET(pSocketBridge->torSocket, &readfds);

			timeout.tv_sec = 0;
			timeout.tv_usec = 1000 * RECV_TIMEOUT_MS;
			if (SOCKET_ERROR == select(1, &readfds, NULL, NULL, &timeout))
			{
				fClosedByServer = TRUE;
				goto exit;
			}

			if (!FD_ISSET(pSocketBridge->torSocket, &readfds))
			{
				//
				// No data yet
				//
				break;
			}

			//
			// A timeout occurred while trying to read data from the virtual
			// machine, so try instead to read data from the Tor SOCKS socket
			//
			cbReceivedFromServer = recv(
				pSocketBridge->torSocket,
				(char*) abReceivedFromServer,
				sizeof(abReceivedFromServer),
				0);

			//
			// If the Tor SOCKS socket sent a TCP FIN then it won't be sending
			// any more data to the virtual machine
			//
			if (cbReceivedFromServer == 0)
			{
				netconn_shutdown(pSocketBridge->lwIPConn, 0, 1);
				fTorReadClosed = TRUE;
                if (!fVmReadClosed)
                {
                    fClosedByServer = TRUE;
                }
				continue;
			}

			//
			// If there was an error while trying to read data from the Tor
			// SOCKS socket...
			//
			if (cbReceivedFromServer == SOCKET_ERROR)
			{
				//
				// The error was not due to a timeout, so close both sides of
				// this connection
				//
				fClosedByServer = TRUE;

				goto exit;
			}

			//
			// Forward data received from the Tor SOCKS socket to the virtual
			// machine
			//
			if (ERR_OK != (err = netconn_write(
				pSocketBridge->lwIPConn,
				abReceivedFromServer,
				cbReceivedFromServer,
				NETCONN_COPY)))
			{
				//
				// If there was an error sending the data to the virtual
				// machine then close both sides of this connection
				//
				fClosedByVm = TRUE;
				goto exit;
			}
		}
    }

exit:
    if (fClosedByVm || fClosedByServer)
    {
        Log(
            Yellow,
            L"Connection to %S:%d closed by %s (socket #%d)\n",
            inet_ntoa(*(in_addr*)&dwServerIpAddress),
            wServerTcpPort,
            fClosedByVm ? L"virtual machine" : L"server",
            pSocketBridge->torSocket);
    }

    closesocket(pSocketBridge->torSocket);
    netconn_close(pSocketBridge->lwIPConn);
    netconn_delete(pSocketBridge->lwIPConn);
    free(pSocketBridge);
}

/*! 
    @brief Listen for and handle incoming TCP/IP connections from the virtual
           machine

    @param[in] arg Reserved
*/
VOID
tortilla_tcp_listener (
    VOID* arg
    )
{
    LWIP_UNUSED_ARG(arg);

    struct netconn* pConnListener;
    struct netconn* pConnIncoming;
    SOCKET s;
    SOCKET_BRIDGE* pSocketBridge;

    //
    // Create a new lwIP TCP connection listener
    //
    pConnListener = netconn_new(
        NETCONN_TCP);
    if (pConnListener == NULL)
    {
        Log(
            Red,
            L"Error in tortilla_tcp_listener(): netconn_new() failed\n");
        return;
    }

    //
    // Bind to all IP addresses and all TCP ports (port parameter ignored
    // thanks to some hacks made to lwIP)
    //
    if (ERR_OK != netconn_bind(
        pConnListener,
        IP_ADDR_ANY,
        1))
    {
        Log(
            Red,
            L"Error in tortilla_tcp_listener(): netconn_bind() failed\n");
        return;
    }

    //
    // Listen on all IP address and all TCP ports
    //
    if (ERR_OK != netconn_listen(
        pConnListener))
    {
        Log(
            Red,
            L"Error in tortilla_tcp_listener(): netconn_listen() failed\n");
        return;
    }

    //
    // Continuously monitor for and handle new connections
    //
    for(;;)
    {
        pConnIncoming = NULL;
        s = INVALID_SOCKET;
        pSocketBridge = NULL;

        //
        // Accept an incoming connection (this is a blocking call)
        //
        if (ERR_OK != netconn_accept(
            pConnListener,
            &pConnIncoming))
        {
            Log(
                Red,
                L"Error in tortilla_tcp_listener(): netconn_accept() failed"
                L"\n");
            goto next;
        }

        //
        // Remove the SYN for this connection from the list of active SYNs
        //
        if (!RemoveActiveSyn(
            pConnIncoming->pcb.tcp->local_ip.addr,
            htons(pConnIncoming->pcb.tcp->local_port),
            pConnIncoming->pcb.tcp->remote_ip.addr,
            htonl(pConnIncoming->pcb.tcp->rcv_nxt - 1)))
        {
            goto next;
        }

        //
        // Get the Tor SOCKS socket that has already been established for this
        //   connection
        //
        s = FindAvailableEstablishedSocket(
            pConnIncoming->pcb.tcp->local_ip.addr,
            ntohs(pConnIncoming->pcb.tcp->local_port));
        if (s == INVALID_SOCKET)
        {
            Log(
                Red,
                L"Error in tortilla_tcp_listener(): Established socket not "
                L"found for connection\n");
            goto next;
        }

        //
        // Allocate and initialize a SOCKET_BRIDGE structure to associate the
        //   Tor socket with the lwIP connection
        //
        pSocketBridge = (SOCKET_BRIDGE*)malloc(sizeof(SOCKET_BRIDGE));
        if (pSocketBridge == NULL)
        {
            Log(
                Red,
                L"Error in tortilla_tcp_listener(): malloc(%d) failed\n",
                sizeof(SOCKET_BRIDGE));
            goto next;
        }
        pSocketBridge->torSocket = s;
        pSocketBridge->lwIPConn = pConnIncoming;

        //
        // Create tortilla_tcp_forwarder thread
        //
        if (0 == sys_thread_new(
            "tortilla_tcp_forwarder",
            tortilla_tcp_forwarder,
            pSocketBridge,
            DEFAULT_THREAD_STACKSIZE,
            DEFAULT_THREAD_PRIO))
        {
            Log(
                Red,
                L"Error in tortilla_tcp_listener(): sys_thread_new() failed"
                L"\n");
            goto next;
        }

        continue;

next:
        if (pSocketBridge != NULL)
        {
            free(pSocketBridge);
        }
        if (s != INVALID_SOCKET)
        {
            closesocket(s);
        }
        if (pConnIncoming != NULL)
        {
            netconn_close(pConnIncoming);
            netconn_delete(pConnIncoming);
        }
    }
}

/*! 
    @brief Low-level output callback function for lwIP; sends TCP/IP packet
           from lwIP to the Tortilla driver

    @param[in] pNetif lwIP network interface
    @param[in] pBuf lwIP packet buffer chain
    @return Returns ERR_OK on success, or ERR_BUF if the packet's length is
            greater than the defined MTU or the packet buffer chain's content
            doesn't match the total size of the packet
*/
err_t
tortillaif_low_level_output (
    struct netif* pNetif,
    struct pbuf* pBuf
    )
{
    struct pbuf* pCurrentPacketBuffer;
    BYTE abBuffer[MTU];
    SIZE_T cbBytesCopied;

    //
    // Return ERR_BUF if the total length of the outgoing packet is greater
    // than the defined MTU
    //
    if (pBuf->tot_len > MTU)
    {
        Log(
            Red,
            L"Error in tortillaif_low_level_output(): Packet larger than MTU"
            L"\n");
        return ERR_BUF;
    }

    //
    // If the entire packet is in the first packet buffer, just send the first
    // packet buffer
    //
    if (pBuf->len == pBuf->tot_len)
    {
        SendPacketToClient(
            (BYTE*)pBuf->payload,
            pBuf->len);
    }
    //
    // Otherwise, unchain the packet buffer and then send the full packet
    //
    else
    {
        //
        // Iterate through each packet buffer in the packet buffer chain
        //
        cbBytesCopied = 0;
        for(pCurrentPacketBuffer = pBuf;
            pCurrentPacketBuffer != NULL;
            pCurrentPacketBuffer = pCurrentPacketBuffer->next)
        {
            //
            // Append the current packet buffer into aucBuffer
            //
            memcpy_s(
                abBuffer + cbBytesCopied,
                sizeof(abBuffer) - cbBytesCopied,
                pCurrentPacketBuffer->payload,
                pCurrentPacketBuffer->len);
            cbBytesCopied += pCurrentPacketBuffer->len;
        }

        //
        // Ensure that the correct number of bytes were copied
        //
        if (cbBytesCopied != pBuf->tot_len)
        {
            Log(
                Red,
                L"Error in tortillaif_low_level_output(): Packet buffer chain "
                L"corrupt\n");
            return ERR_BUF;
        }

        //
        // Send the unchained packet
        //
        SendPacketToClient(
            abBuffer,
            pBuf->tot_len);
    }
    
    return ERR_OK;
}

/*! 
    @brief lwIP's initialization callback function
    @details Initializes the flags for lwIP's network interface, sets the
             hardware address, and sets the low-level output callback functions

    @param[in] pNetif lwIP network interface
    @return Always returns ERR_OK
*/
err_t
tortillaif_init (
    struct netif* pNetif
    )
{
    pNetif->name[0] = 0;
    pNetif->name[1] = 0;

    pNetif->linkoutput = tortillaif_low_level_output;
    pNetif->output = etharp_output;

    pNetif->mtu = MTU - sizeof(eth_hdr);
    pNetif->flags =
		NETIF_FLAG_UP |
		NETIF_FLAG_BROADCAST |
		NETIF_FLAG_LINK_UP |
		NETIF_FLAG_ETHARP |
		NETIF_FLAG_ETHERNET;

    pNetif->hwaddr_len = ETHARP_HWADDR_LEN;
    memcpy(
        &pNetif->hwaddr,
        g_abGatewayMacAddress,
        ETHARP_HWADDR_LEN);

    return ERR_OK;
}

/*! 
    @brief Initialize lwIP's network interface

    @param[in] arg sys_sem_t initialization semaphore
*/
VOID
tortilla_init (
    VOID* arg
    )
{
    sys_sem_t* init_sem = (sys_sem_t*)arg;
    ip_addr_t ipaddr, netmask, gw;

    //
    // Initialize the gateway IP address and netmask
    //
    IP4_ADDR(
        &gw,
        g_abGatewayIpAddress[0],
        g_abGatewayIpAddress[1],
        g_abGatewayIpAddress[2],
        g_abGatewayIpAddress[3]);
    IP4_ADDR(
        &ipaddr,
        g_abGatewayIpAddress[0],
        g_abGatewayIpAddress[1],
        g_abGatewayIpAddress[2],
        g_abGatewayIpAddress[3]);
    IP4_ADDR(
        &netmask,
        0,0,0,0);

    //
    // Set and initialize lwIP's default network interface
    //
    netif_set_default(
        netif_add(
            &netif,
            &ipaddr,
            &netmask,
            &gw,
            NULL,
            tortillaif_init,
            tcpip_input));

    sys_sem_signal(
        init_sem);
}

/*! 
    @brief Initialize lwIP and create the tortilla_tcp_listener thread
 
    @return Returns TRUE on success, FALSE on failure
*/
BOOL
lwIP_init (
    VOID
    )
{
    sys_sem_t init_sem;

    //
    // Initialize lwIP's network interface
    //
    if (ERR_OK != sys_sem_new(&init_sem, 0))
    {
        return FALSE;
    }
    tcpip_init(
        tortilla_init,
        &init_sem);
    sys_sem_wait(&init_sem);
    sys_sem_free(&init_sem);

    //
    // Start the tortilla_tcp_listener thread
    //
    return (0 != sys_thread_new(
        "tortilla_tcp_listener",
        tortilla_tcp_listener,
        NULL,
        DEFAULT_THREAD_STACKSIZE,
        DEFAULT_THREAD_PRIO));
}

/*! 
    @brief Writes an embedded resource to disk
    @details Writes an embedded reousrce to disk. If a file already exists at
             the destination file path, that file is overwritten.
 
    @param[in] wszName The name of the resource (supplied to FindResource())
    @param[in] wszFilePath The destination file path
    @return Returns TRUE on success, FALSE on failure
*/
BOOL
DropResource (
    WCHAR* wszName,
    WCHAR* wszFilePath
    )
{
    BOOL fSuccess = FALSE;

    HANDLE hFile;
    HRSRC hResInfo;
    HGLOBAL hResData;
    BYTE* abFileData;
    DWORD dwNumerOfBytesWritten;

    //
    // Create the destination file
    //
    hFile = CreateFile(
        wszFilePath,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        0,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        Log(
            Red,
            L"\nError in DropResource(..., \"%s\") - CreateFile() failed "
            L"(0x%08X)\n",
            wszFilePath,
            GetLastError());
        goto exit;
    }

    //
    // Load the data to be written from the embedded resources
    //
    hResInfo = FindResource(
        GetModuleHandle(NULL),
        wszName,
        RT_RCDATA);
    if (hResInfo == NULL)
    {
        Log(
            Red,
            L"\nError in DropResource(..., \"%s\") - FindResource() failed "
            L"(0x%08X)\n",
            wszFilePath,
            GetLastError());
        goto exit;
    }
    hResData = LoadResource(
        GetModuleHandle(NULL),
        hResInfo);
    if (hResData == NULL)
    {
        Log(
            Red,
            L"\nError in DropResource(..., \"%s\") - LoadResource() failed "
            L"(0x%08X)\n",
            wszFilePath,
            GetLastError());
        goto exit;
    }
    abFileData = (BYTE*)LockResource(
        hResData);
    if (abFileData == NULL)
    {
        Log(
            Red,
            L"\nError in DropResource(..., \"%s\") - LockResource() failed "
            L"(0x%08X)\n",
            wszFilePath,
            GetLastError());
        goto exit;
    }

    //
    // Write the embedded resource to the created file
    //
    if (!WriteFile(
        hFile,
        abFileData,
        SizeofResource(GetModuleHandle(NULL), hResInfo),
        &dwNumerOfBytesWritten,
        NULL))
    {
        Log(
            Red,
            L"\nError in DropResource(..., \"%s\") - WriteFile() failed "
            L"(0x%08X)\n",
            wszFilePath,
            GetLastError());
        goto exit;
    }

    fSuccess = TRUE;

exit:
    if (hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);

        if (!fSuccess)
        {
            DeleteFile(
                wszFilePath);
        }
    }

    return fSuccess;
}

/*!
	@brief Copies a DWORD array to a BYTE array; used for converting arrays
	       from swscanf_s() into the final BYTE arrays

	@param[out] abDst Destination BYTE array
	@param[in] dwSrc Source DWORD array
	@param[in] cbLength Number of elements to copy

*/
VOID
CopyDwordsToByteArray(
	BYTE* abDst,
	DWORD* adwSrc,
	SIZE_T cbLength
	)
{
	for (SIZE_T i = 0; i < cbLength; i++)
	{
		abDst[i] = (BYTE)adwSrc[i];
	}
}
    
/*! 
    @brief Loads the configuration information for Tortilla Client
    @details Loads the configuration information for Tortilla Client from
             Tortilla.ini. If Tortilla.ini is not found in the current
             directory, this function drops a default Tortilla.ini file into
             the current directory and loads its configuration from that file.
 
    @return Returns TRUE on success, FALSE on failure
*/
BOOL
LoadConfiguration (
    VOID
    )
{
    BOOL fSuccess = FALSE;

    WCHAR wszIniFile[MAX_PATH];

    WCHAR wszGatewayMacAddress[18];
    WCHAR wszGatewayIpAddress[16];
    WCHAR wszDhcpClientIpAddress[16];
    WCHAR wszDhcpClientSubnetMask[16];
    WCHAR wszTorClientIpAddress[16];
    CHAR szTorClientIpAddress[16];

	DWORD adwGatewayMacAddress[ETHARP_HWADDR_LEN];
	DWORD adwGatewayIpAddress[sizeof(in_addr)];
	DWORD adwDhcpClientIpAddress[sizeof(in_addr)];
	DWORD adwDhcpClientSubnetMask[sizeof(in_addr)];

    WCHAR wszPcapFile[MAX_PATH];
    pcap_hdr_t pcapHeader;
    DWORD dwNumberOfBytesWritten;

    //
    // Determine the expected location of Tortilla.ini
    //
    if (0 == GetCurrentDirectory(
        _countof(wszIniFile),
        wszIniFile))
    {
        Log(
            Red,
            L"\nError in LoadConfiguration(): GetCurrentDirectory() failed "
            L"(0x%08X)\n",
            GetLastError());
        goto exit;
    }
    if (0 != wcscat_s(
        wszIniFile,
        _countof(wszIniFile),
        L"\\Tortilla.ini"))
    {
        Log(
            Red,
            L"\nError in LoadConfiguration(): wcscat_s() failed\n");
        goto exit;
    }

    //
    // If Tortilla.ini does not exist, drop it from the embedded resources
    //
    if (INVALID_FILE_ATTRIBUTES == GetFileAttributes(
        wszIniFile))
    {
        if (!DropResource(
            MAKEINTRESOURCE(IDR_INI),
            L"Tortilla.ini"))
        {
            goto exit;
        }
    }

    //
    // Get the EnableNetworkBindings value from the INI
    //
    if (0 == GetPrivateProfileString(
        L"Tortilla",
        L"EnableNetworkBindings",
        NULL,
        g_wszEnableNetworkBindings,
        _countof(g_wszEnableNetworkBindings),
        wszIniFile))
    {
        *g_wszEnableNetworkBindings = 0;
    }

    //
    // Deter command-line injection issues
    //
    if (NULL != wcschr(
        g_wszEnableNetworkBindings,
        L'\"'))
    {
        Log(
            Red,
            L"\nError in LoadConfiguration(): \" character found in "
            L"EnableNetworkBindings in Tortilla.ini\n");
        goto exit;
    }

    //
    // Get the IgnoreNetworkBindings value from the INI
    //
    if (0 == GetPrivateProfileString(
        L"Tortilla",
        L"IgnoreNetworkBindings",
        NULL,
        g_wszIgnoreNetworkBindings,
        _countof(g_wszIgnoreNetworkBindings),
        wszIniFile))
    {
        *g_wszIgnoreNetworkBindings = 0;
    }

    //
    // Deter command-line injection issues
    //
    if (NULL != wcschr(
        g_wszIgnoreNetworkBindings,
        L'\"'))
    {
        Log(
            Red,
            L"\nError in LoadConfiguration(): \" character found in "
            L"IgnoreNetworkBindings in Tortilla.ini\n");
        goto exit;
    }

    //
    // Get the GatewayMacAddress from the INI
    //
    if (!((17 == GetPrivateProfileString(
            L"Tortilla",
            L"GatewayMacAddress",
            NULL,
            wszGatewayMacAddress,
            _countof(wszGatewayMacAddress),
            wszIniFile)) &&
        (6 == swscanf_s(
            wszGatewayMacAddress,
            L"%x-%x-%x-%x-%x-%x",
			&adwGatewayMacAddress[0],
			&adwGatewayMacAddress[1],
			&adwGatewayMacAddress[2],
			&adwGatewayMacAddress[3],
			&adwGatewayMacAddress[4],
			&adwGatewayMacAddress[5]))))
    {
        Log(
            Red,
            L"\nError reading GatewayMacAddress from \"%s\"\n"
            L"Manually fix the GatewayMacAddress entry in Tortilla.ini or "
            L"delete the\nTortilla.ini file and restart Tortilla.exe to "
            L"recreate a default Tortilla.ini\nfile\n",
            wszIniFile);
        goto exit;
    }

    //
    // Get the GatewayIpAddress from the INI
    //
    if (!((0 != GetPrivateProfileString(
            L"Tortilla",
            L"GatewayIpAddress",
            NULL,
            wszGatewayIpAddress,
            _countof(wszGatewayIpAddress),
            wszIniFile)) &&
        (4 == swscanf_s(
            wszGatewayIpAddress,
            L"%d.%d.%d.%d",
			&adwGatewayIpAddress[0],
			&adwGatewayIpAddress[1],
			&adwGatewayIpAddress[2],
			&adwGatewayIpAddress[3]))))
    {
        Log(
            Red,
            L"\nError reading GatewayIpAddress from \"%s\"\n"
            L"Manually fix the GatewayIpAddress entry in Tortilla.ini or "
            L"delete the\nTortilla.ini file and restart Tortilla.exe to "
            L"recreate a default Tortilla.ini\nfile\n",
            wszIniFile);
        goto exit;
    }

    //
    // Get the DhcpClientIpAddress from the INI
    //
    if (!((0 != GetPrivateProfileString(
            L"Tortilla",
            L"DhcpClientIpAddress",
            NULL,
            wszDhcpClientIpAddress,
            _countof(wszDhcpClientIpAddress),
            wszIniFile)) &&
        (4 == swscanf_s(
            wszDhcpClientIpAddress,
            L"%d.%d.%d.%d",
			&adwDhcpClientIpAddress[0],
			&adwDhcpClientIpAddress[1],
			&adwDhcpClientIpAddress[2],
			&adwDhcpClientIpAddress[3]))))
    {
        Log(
            Red,
            L"\nError reading DhcpClientIpAddress from \"%s\"\n"
            L"Manually fix the DhcpClientIpAddress entry in Tortilla.ini or "
            L"delete the\nTortilla.ini file and restart Tortilla.exe to "
            L"recreate a default Tortilla.ini\nfile\n",
            wszIniFile);
        goto exit;
    }

    //
    // Get the DhcpClientSubnetMask from the INI
    //
    if (!((0 != GetPrivateProfileString(
            L"Tortilla",
            L"DhcpClientSubnetMask",
            NULL,
            wszDhcpClientSubnetMask,
            _countof(wszDhcpClientSubnetMask),
            wszIniFile)) &&
        (4 == swscanf_s(
			wszDhcpClientSubnetMask,
            L"%d.%d.%d.%d",
			&adwDhcpClientSubnetMask[0],
			&adwDhcpClientSubnetMask[1],
			&adwDhcpClientSubnetMask[2],
			&adwDhcpClientSubnetMask[3]))))
    {
        Log(
            Red,
            L"\nError reading DhcpClientSubnetMask from \"%s\"\n"
            L"Manually fix the DhcpClientSubnetMask entry in Tortilla.ini or "
            L"delete the\nTortilla.ini file and restart Tortilla.exe to "
            L"recreate a default Tortilla.ini\nfile\n",
            wszIniFile);
        goto exit;
    }

    //
    // Get the TorClientIpAddress from the INI
    //
    if (!((0 != GetPrivateProfileString(
            L"Tortilla",
            L"TorClientIpAddress",
            NULL,
            wszTorClientIpAddress,
            _countof(wszTorClientIpAddress),
            wszIniFile)) &&
        (0 != WideCharToMultiByte(
            CP_ACP,
            0,
            wszTorClientIpAddress,
            -1,
            szTorClientIpAddress,
            _countof(szTorClientIpAddress),
            NULL,
            NULL)) &&
        (INADDR_NONE != (g_dwTorClientIpAddress = inet_addr(
            szTorClientIpAddress)))))
    {
        Log(
            Red,
            L"\nError reading TorClientIpAddress from \"%s\"\n"
            L"Manually fix the TorClientIpAddress entry in Tortilla.ini or "
            L"delete the\nTortilla.ini file and restart Tortilla.exe to "
            L"recreate a default Tortilla.ini\nfile\n",
            wszIniFile);
        goto exit;
    }

    //
    // Get the TorClientTcpPort from the INI
    //
    g_wTorClientTcpPort = GetPrivateProfileInt(
            L"Tortilla",
            L"TorClientTcpPort",
            0,
            wszIniFile);
    if (g_wTorClientTcpPort == 0)
    {
        Log(
            Red,
            L"\nError reading TorClientTcpPort from \"%s\"\n"
            L"Manually fix the TorClientTcpPort entry in Tortilla.ini or "
            L"delete the\nTortilla.ini file and restart Tortilla.exe to "
            L"recreate a default Tortilla.ini\nfile\n",
            wszIniFile);
        goto exit;
    }

    //
    // Get the PCAP file path from the INI
    //
    if (0 == GetPrivateProfileString(
        L"Tortilla",
        L"PCAP",
        NULL,
        wszPcapFile,
        _countof(wszPcapFile),
        wszIniFile))
    {
        //
        // If the entry is missing or blank, assume the user doesn't want to
        //   create a PCAP
        //
        g_hPcapFile = INVALID_HANDLE_VALUE;
    }
    else
    {
        //
        // Create the PCAP file
        //
        g_hPcapFile = CreateFile(
            wszPcapFile,
            GENERIC_WRITE,
            FILE_SHARE_READ,
            NULL,
            CREATE_ALWAYS,
            0,
            NULL);
        if (g_hPcapFile == INVALID_HANDLE_VALUE)
        {
            Log(
                Red,
                L"\nError creating PCAP file \"%s\"\n",
                wszPcapFile);
            goto exit;
        }

        //
        // Write the PCAP global header
        //

        pcapHeader.magic_number = 0xa1b2c3d4;
        pcapHeader.version_major = 2;
        pcapHeader.version_minor = 4;
        pcapHeader.thiszone = 0;
        pcapHeader.sigfigs = 0;
        pcapHeader.snaplen = MTU;
        pcapHeader.network = 1;

        if (!WriteFile(
            g_hPcapFile,
            &pcapHeader,
            sizeof(pcapHeader),
            &dwNumberOfBytesWritten,
            NULL))
        {
            Log(
                Red,
                L"\nError writing PCAP global header to file \"%s\"\n",
                wszPcapFile);
            goto exit;
        }
    }

	CopyDwordsToByteArray(
        g_abDhcpClientIpAddress,
		adwDhcpClientIpAddress,
		_countof(g_abDhcpClientIpAddress));

	CopyDwordsToByteArray(
        g_abDhcpClientSubnetMask,
		adwDhcpClientSubnetMask,
		_countof(g_abDhcpClientSubnetMask));

	CopyDwordsToByteArray(
        g_abGatewayIpAddress,
		adwGatewayIpAddress,
		_countof(g_abGatewayIpAddress));

	CopyDwordsToByteArray(
        g_abGatewayMacAddress,
		adwGatewayMacAddress,
		_countof(g_abGatewayMacAddress));

    fSuccess = TRUE;    

exit:
    return fSuccess;
}

/*! 
    @brief Installs the Tortilla driver if not already installed
    @details If the Tortilla driver is not already installed, installs the
             Tortilla driver.
             If the Tortilla driver is already installed but the version is
             different from the bundled driver's version, replace the
             installed driver with the bundled one.
             If the Tortilla driver is already installed and the version is
             the same as the bundled driver's version just return TRUE.
 
    @return Returns TRUE on success, FALSE on failure
*/
BOOL
EnsureTortillaAdapterInstalled (
    VOID
    )
{
    BOOL fSuccess = FALSE;

    BOOL f64 = FALSE;
    BOOL (WINAPI* fnIsWow64Process)(HANDLE, PBOOL);

    WCHAR wszTempPath[MAX_PATH];
    WCHAR wszTempInfPath[MAX_PATH];
    WCHAR wszTempCatPath[MAX_PATH];
    WCHAR wszTempSysPath[MAX_PATH];
    WCHAR wszTempInstallPath[MAX_PATH];

    WCHAR wszCommandLine[512];

    BOOL fInfDropped = FALSE;
    BOOL fCatDropped = FALSE;
    BOOL fSysDropped = FALSE;
    BOOL fInstallDropped = FALSE;

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    INSTALL_TORTILLA_ERROR iteExitCode;

    //
    // If we're running on a 64-bit system, we need to drop the 64-bit
    //   installer
    //
    fnIsWow64Process =
        (BOOL (WINAPI*)(HANDLE, PBOOL))GetProcAddress(
        GetModuleHandle(L"kernel32.dll"),
        "IsWow64Process");
    if (fnIsWow64Process != NULL)
    {
        fnIsWow64Process(
            GetCurrentProcess(),
            &f64);
    }

    //
    // Determine the temporary file path
    //
    if (0 == GetTempPath(
        _countof(wszTempPath),
        wszTempPath))
    {
        Log(
            Red,
            L"\nError in EnsureTortillaAdapterInstalled() - GetTempPath() "
            L"failed (0x%08X)\n",
            GetLastError());
        goto exit;
    }

    //
    // Drop the Tortilla driver INF file
    //
    if (0 != wcscpy_s(
        wszTempInfPath,
        _countof(wszTempInfPath),
        wszTempPath))
    {
        Log(
            Red,
            L"\nError in EnsureTortillaAdapterInstalled() - wcscpy_s() "
            L"failed\n");
        goto exit;
    }
    if (0 != wcscat_s(
        wszTempInfPath,
        _countof(wszTempInfPath),
        L"netTor.inf"))
    {
        Log(
            Red,
            L"\nError in EnsureTortillaAdapterInstalled() - wcscat_s() "
            L"failed\n");
        goto exit;
    }
    if (!DropResource(
        MAKEINTRESOURCE(f64 ? IDR_INF64 : IDR_INF32),
        wszTempInfPath))
    {
        goto exit;
    }
    fInfDropped = TRUE;

    //
    // Drop the Tortilla driver CAT file
    //
    if (0 != wcscpy_s(
        wszTempCatPath,
        _countof(wszTempCatPath),
        wszTempPath))
    {
        Log(
            Red,
            L"\nError in EnsureTortillaAdapterInstalled() - wcscpy_s() "
            L"failed\n");
        goto exit;
    }
    if (0 != wcscat_s(
        wszTempCatPath,
        _countof(wszTempCatPath),
        L"tortilla.cat"))
    {
        Log(
            Red,
            L"\nError in EnsureTortillaAdapterInstalled() - wcscat_s() "
            L"failed\n");
        goto exit;
    }
    if (!DropResource(
        MAKEINTRESOURCE(f64 ? IDR_CAT64 : IDR_CAT32),
        wszTempCatPath))
    {
        goto exit;
    }
    fCatDropped = TRUE;

    //
    // Drop the Tortilla driver SYS file
    //
    if (0 != wcscpy_s(
        wszTempSysPath,
        _countof(wszTempSysPath),
        wszTempPath))
    {
        Log(
            Red,
            L"\nError in EnsureTortillaAdapterInstalled() - wcscpy_s() "
            L"failed\n");
        goto exit;
    }
    if (0 != wcscat_s(
        wszTempSysPath,
        _countof(wszTempSysPath),
        L"tortilla.sys"))
    {
        Log(
            Red,
            L"\nError in EnsureTortillaAdapterInstalled() - wcscat_s() "
            L"failed\n");
        goto exit;
    }
    if (!DropResource(
        MAKEINTRESOURCE(f64 ? IDR_SYS64 : IDR_SYS32),
        wszTempSysPath))
    {
        goto exit;
    }
    fSysDropped = TRUE;

    //
    // Drop InstallTortillaDriver.exe
    //
    if (0 != wcscpy_s(
        wszTempInstallPath,
        _countof(wszTempInstallPath),
        wszTempPath))
    {
        Log(
            Red,
            L"\nError in EnsureTortillaAdapterInstalled() - wcscpy_s() "
            L"failed\n");
        goto exit;
    }
    if (0 != wcscat_s(
        wszTempInstallPath,
        _countof(wszTempInstallPath),
        L"InstallTortillaDriver.exe"))
    {
        Log(
            Red,
            L"\nError in EnsureTortillaAdapterInstalled() - wcscat_s() "
            L"failed\n");
        goto exit;
    }
    if (!DropResource(
        MAKEINTRESOURCE(f64 ? IDR_INSTALL64 : IDR_INSTALL32),
        wszTempInstallPath))
    {
        goto exit;
    }
    fInstallDropped = TRUE;

    //
    // Build the command line for InstallTortillaDriver.exe:
    // "<file path of InstallTortillaDriver.exe>" "<EnableNetworkBindings>" "<IgnoreNetworkBindings>"
    //
    *wszCommandLine = 0;
    if (!((0 == wcscat_s(
        wszCommandLine,
        _countof(wszCommandLine),
        L"\"")) &&
        (0 == wcscat_s(
        wszCommandLine,
        _countof(wszCommandLine),
        wszTempInstallPath)) &&
        (0 == wcscat_s(
        wszCommandLine,
        _countof(wszCommandLine),
        L"\" \"")) &&
        (0 == wcscat_s(
        wszCommandLine,
        _countof(wszCommandLine),
        g_wszEnableNetworkBindings)) &&
        (0 == wcscat_s(
        wszCommandLine,
        _countof(wszCommandLine),
        L"\" \"")) &&
        (0 == wcscat_s(
        wszCommandLine,
        _countof(wszCommandLine),
        g_wszIgnoreNetworkBindings)) &&
        (0 == wcscat_s(
        wszCommandLine,
        _countof(wszCommandLine),
        L"\""))))
    {
        Log(
            Red,
            L"\nError in EnsureTortillaAdapterInstalled() - wcscat_s() "
            L"failed\n");
    }

    //
    // Run InstallTortillaDriver.exe
    //
    memset(
        &si,
        0,
        sizeof(si));
    si.cb = sizeof(si);
    if (!CreateProcess(
        NULL,
        wszCommandLine,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &si,
        &pi))
    {
        Log(
            Red,
            L"\nError in EnsureTortillaAdapterInstalled() - CreateProcess() "
            L"failed (0x%08X)\n",
            GetLastError());
        goto exit;
    }

    //
    // Wait for InstallTortillaDriver.exe to finish and get its exit code
    //
    if (WAIT_OBJECT_0 != WaitForSingleObject(
        pi.hProcess,
        INFINITE))
    {
        Log(
            Red,
            L"\nError in EnsureTortillaAdapterInstalled() - "
            L"WaitForSingleObject() failed (0x%08X)\n",
            GetLastError());
        goto exit;
    }
    if (!GetExitCodeProcess(
        pi.hProcess,
        (DWORD*)&iteExitCode))
    {
        Log(
            Red,
            L"\nError in EnsureTortillaAdapterInstalled() - "
            L"GetExitCodeProcess() failed (0x%08X)\n",
            GetLastError());
        goto exit;
    }

    //
    // Handle the exit code of InstallTortillaDriver.exe
    //
    if (iteExitCode == InsTorErrSuccess)
    {
        fSuccess = TRUE;
        goto exit;
    }
    Log(
        Red,
        L"\nError during InstallTortillaDriver - ");
    switch (iteExitCode)
    {
        //
        // wmain()
        //
        case InsTorErrCommandLine:
            Log(
                Red,
                L"The wrong of number of command line arguments were supplied "
                L"to InstallTortillaDriver.exe\n");
            break;
        case InsTorErrInfPath:
            Log(
                Red,
                L"Could not build file path for netTor.inf\n");
            break;
        case InsTorErrInfRead:
            Log(
                Red,
                L"Could not read driver version from netTor.inf\n");
            break;
        case InsTorErrPrintVer:
            Log(
                Red,
                L"swprintf_s() failed\n");
            break;
        case InsTorErrUpdateDriver:
            Log(
                Red,
                L"UpdateDriverForPlugAndPlayDevices() failed to update the "
                L"existing Tortilla driver\n");
            break;
        case InsTorErrRebootRequired:
            Log(
                Red,
                L"A reboot is required\n");
            break;
        case InsTorErrCreateDeviceInfoList:
            Log(
                Red,
                L"SetupDiCreateDeviceInfoList() failed\n");
            break;
        case InsTorErrCreateDeviceInfo:
            Log(
                Red,
                L"SetupDiCreateDeviceInfo() failed\n");
            break;
        case InsTorErrSetDeviceRegistryProperty:
            Log(
                Red,
                L"SetupDiSetDeviceRegistryProperty() failed\n");
            break;
        case InsTorErrCallClassInstaller:
            Log(
                Red,
                L"SetupDiCallClassInstaller() failed\n");
            break;
        case InsTorErrInstallDriver:
            Log(
                Red,
                L"UpdateDriverForPlugAndPlayDevices() failed to install the "
                L"Tortilla driver\n");
            break;

        //
        // FindInstalledDevice()
        //
        case InsTorErrGetClassDevs:
            Log(
                Red,
                L"SetupDiGetClassDevs() failed\n");
            break;
        case InsTorErrGetDeviceInstallParams:
            Log(
                Red,
                L"SetupDiGetDeviceInstallParams() failed\n");
            break;
        case InsTorErrSetDeviceInstallParams:
            Log(
                Red,
                L"SetupDiSetDeviceInstallParams() failed\n");
            break;
        case InsTorErrBuildDriverInfoList:
            Log(
                Red,
                L"SetupDiBuildDriverInfoList() failed\n");
            break;
        case InsTorErrEnumDriverInfo:
            Log(
                Red,
                L"SetupDiEnumDriverInfo() failed\n");
            break;

        //
        // UnbindBindings()
        //
        case InsTorErrCoInitialize:
            Log(
                Red,
                L"CoInitialize() failed\n");
            break;
        case InsTorErrCoCreateInstance:
            Log(
                Red,
                L"CoCreateInstance() failed\n");
            break;
        case InsTorErrQueryNetCfgLock:
            Log(
                Red,
                L"QueryInterface(IID_INetCfgLock, ...) failed\n");
            break;
        case InsTorErrAcquireWriteLock:
            Log(
                Red,
                L"AcquireWriteLock() failed\n");
            break;
        case InsTorErrInitialize:
            Log(
                Red,
                L"Initialize() failed\n");
            break;
        case InsTorErrFindComponent:
            Log(
                Red,
                L"FindComponent() failed\n");
            break;
        case InsTorErrQueryNetCfgComponentBindings:
            Log(
                Red,
                L"QueryInterface(IID_INetCfgComponentBindings, ...) failed\n");
            break;
        case InsTorErrEnumBindingPaths:
            Log(
                Red,
                L"EnumBindingPaths() failed\n");
            break;
        case InsTorErrGetPathToken:
            Log(
                Red,
                L"GetPathToken() failed\n");
            break;
        case InsTorErrStringDup:
            Log(
                Red,
                L"_wcsdup() failed\n");
            break;
        case InsTorErrBindingEnable:
            Log(
                Red,
                L"Failed to enable a Tortilla Adapter network binding\n");
            break;
        case InsTorErrBindingDisable:
            Log(
                Red,
                L"Failed to disable a Tortilla Adapter network binding\n");
            break;
        case InsTorErrApply:
            Log(
                Red,
                L"Failed to apply network binding changes\n");
            break;

        default:
            Log(
                Red,
                L"Undefined error\n");
    }

exit:
    if (fInstallDropped)
    {
        DeleteFile(
            wszTempInstallPath);
    }
    if (fSysDropped)
    {
        DeleteFile(
            wszTempSysPath);
    }
    if (fCatDropped)
    {
        DeleteFile(
            wszTempCatPath);
    }
    if (fInfDropped)
    {
        DeleteFile(
            wszTempInfPath);
    }

    return fSuccess;
}

/*! 
    @brief Beginning of program execution
 
    @param[in] argc Number of arguments passed to program from command line
    @param[in] argv Array of arguments from command line
    @return Always returns 0
*/
INT
wmain (
    INT argc,
    WCHAR* argv[]
    )
{
    WSADATA wsaData;
    HMODULE hNtdll;
    NTOPENEVENT_T NtOpenEvent;
    UNICODE_STRING unicodeString;
    OBJECT_ATTRIBUTES objectAttributes;
    NTSTATUS status;
    HANDLE hToTortillaWrittenEvent;
    HANDLE hToTortillaWritingEvent;
    NTOPENSECTION_T NtOpenSection;
    HANDLE hToTortillaFileMapping;
    BYTE* abToTortillaFileMapping;
    HANDLE hFromTortillaFileMapping;

    DWORD dwNumberOfBytesRead;
    BYTE* abBuffer;
    FULL_IP_PACKET* pIp;
    FULL_TCP_PACKET* pTcp;
    FULL_DHCP_PACKET* pDhcp;
    FULL_ARP_PACKET* pArp;
    FULL_DNS_PACKET* pDns;
    PACKET_WITH_SIZE* pPacket;

    DWORD dwProcessList;
    CONSOLE_CURSOR_INFO cci;
    HANDLE hConsoleInput;
    INPUT_RECORD ir;
    DWORD dwNumberOfEventsRead;

    //
    // Initialize logging handles
    //
    g_hConsoleOutput = GetStdHandle(
        STD_OUTPUT_HANDLE);
    if (g_hConsoleOutput == INVALID_HANDLE_VALUE)
    {
        wprintf_s(
            L"Error in wmain(): GetStdHandle() failed (0x%08X)\n",
            GetLastError());
        g_hLogMutex = INVALID_HANDLE_VALUE;
        goto exit;
    }
    g_hLogMutex = CreateMutex(
        NULL,
        FALSE,
        NULL);
    if (g_hLogMutex == NULL)
    {
        wprintf_s(
            L"Error in wmain(): CreateMutex() failed (0x%08X)\n",
            GetLastError());
        goto exit;
    }

    //
    // Print banner
    //
    Log(
        White,
        L"Tortilla v1.0.1 Beta\n"
        L"by Jason Geffner (jason@crowdstrike.com)\n"
        L"and Cameron Gutman (cameron@crowdstrike.com)\n"
        L"CrowdStrike, Inc. Copyright (c) 2013.  All rights reserved.\n"
        L"\n");
    Log(
        Gray,
        L"This product is produced independently from the Tor(r) anonymity "
        L"software and\ncarries no guarantee from The Tor Project about "
        L"quality, suitability or\nanything else.\n"
        L"\n");

    //
    // Load Tortilla's configuration from Tortilla.ini
    //
    Log(
        Cyan,
        L"Loading configuration...");
    if (!LoadConfiguration())
    {
        goto exit;
    }
    Log(
        Cyan,
        L" done\n");

    //
    // Initialize global variables
    //
    Log(
        Cyan,
        L"Initializing global variables...");
    g_hPcapMutex = CreateMutex(
        NULL,
        FALSE,
        NULL);
    if (g_hPcapMutex == NULL)
    {
        Log(
            Red,
            L"\nError in wmain(): CreateMutex() failed (0x%08X)\n",
            GetLastError());
        goto exit;
    }
    g_pAvailableEstablishedSockets = NULL;
    g_hAesMutex = CreateMutex(
        NULL,
        FALSE,
        NULL);
    if (g_hAesMutex == NULL)
    {
        Log(
            Red,
            L"\nError in wmain(): CreateMutex() failed (0x%08X)\n",
            GetLastError());
        goto exit;
    }
    g_pActiveSyns = NULL;
    g_hActiveSynMutex = CreateMutex(
        NULL,
        FALSE,
        NULL);
    if (g_hActiveSynMutex == NULL)
    {
        Log(
            Red,
            L"\nError in wmain(): CreateMutex() failed (0x%08X)\n",
            GetLastError());
        goto exit;
    }
    Log(
        Cyan,
        L" done\n");

    //
    // Ensure that we only have one Tortilla client running at a time
    //
    if (NULL == CreateMutex(
        NULL,
        TRUE,
        L"Global\\TortillaMutex"))
    {
        Log(
            Red,
            L"Error in wmain(): CreateMutex(..., "
            L"\"Global\\\\TortillaMutex\") failed (0x%08X)\n",
            GetLastError());
        goto exit;
    }
    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        Log(
            Red,
            L"Error in wmain(): Only one instance of Tortilla may run at a "
            L"time\n");
        goto exit;
    }

    //
    // Ensure that the Tortilla driver is installed
    //
    Log(
        Cyan,
        L"Ensuring Tortilla Adapter is installed (may take a minute)...");
    if (!EnsureTortillaAdapterInstalled())
    {
        goto exit;
    }
    Log(
        Cyan,
        L" done\n");

    //
    // Initialize Winsock
    //
    if (0 != WSAStartup(MAKEWORD(2, 2), &wsaData))
    {
        Log(
            Red,
            L"Error in wmain(): WSAStartup() failed (0x%08X)\n",
            GetLastError());
        goto exit;
    }

    Log(
        Cyan,
        L"Initializing communication channel with Tortilla driver...");

    //
    // Open a handle to the ToTortillaWrittenEvent event, created by
    //   Tortilla's driver
    //
    hNtdll = GetModuleHandle(
        L"ntdll.dll");
    if (hNtdll == NULL)
    {
        Log(
            Red,
            L"\nError in wmain(): GetModuleHandle(\"ntdll.dll\") failed "
            L"(0x%08X)\n",
            GetLastError());
        goto exit;
    }
    NtOpenEvent = (NTOPENEVENT_T)GetProcAddress(
        hNtdll,
        "NtOpenEvent");
    if (NtOpenEvent == NULL)
    {
        Log(
            Red,
            L"\nError in wmain(): GetProcAddress(..., \"NtOpenEvent\") failed "
            L"(0x%08X)\n",
            GetLastError());
        goto exit;
    }
    RtlInitUnicodeString(
        &unicodeString,
        L"\\Tortilla\\ToTortillaWrittenEvent");
    InitializeObjectAttributes(
        &objectAttributes,
        &unicodeString,
        0,
        NULL,
        NULL);
    status = NtOpenEvent(
        &hToTortillaWrittenEvent,
        SYNCHRONIZE,
        &objectAttributes);
    if (status != STATUS_SUCCESS)
    {
        Log(
            Red,
            L"\nError in wmain(): Failed to open ToTortillaWrittenEvent "
            L"(0x%08X)\n",
            status);
        goto exit;
    }

    //
    // Open a handle to the ToTortillaWritingEvent event, created by
    //   Tortilla's driver
    //
    RtlInitUnicodeString(
        &unicodeString,
        L"\\Tortilla\\ToTortillaWritingEvent");
    InitializeObjectAttributes(
        &objectAttributes,
        &unicodeString,
        0,
        NULL,
        NULL);
    status = NtOpenEvent(
        &hToTortillaWritingEvent,
        SYNCHRONIZE | EVENT_MODIFY_STATE,
        &objectAttributes);
    if (status != STATUS_SUCCESS)
    {
        Log(
            Red,
            L"\nError in wmain(): Failed to open ToTortillaWritingEvent "
            L"(0x%08X)\n",
            status);
        goto exit;
    }
    
    //
    // Map the ToTortillaFileMapping shared section, created by Tortilla's
    //   driver
    //
    NtOpenSection = (NTOPENSECTION_T)GetProcAddress(
        hNtdll,
        "NtOpenSection");
    if (NtOpenSection == NULL)
    {
        Log(
            Red,
            L"\nError in wmain(): GetProcAddress(..., \"NtOpenSection\") "
            L"failed (0x%08X)\n",
            GetLastError());
        goto exit;
    }
    RtlInitUnicodeString(
        &unicodeString,
        L"\\Tortilla\\ToTortillaFileMapping");
    InitializeObjectAttributes(
        &objectAttributes,
        &unicodeString,
        0,
        NULL,
        NULL);
    status = NtOpenSection(
        &hToTortillaFileMapping,
        SECTION_MAP_READ,
        &objectAttributes);
    if (status != STATUS_SUCCESS)
    {
        Log(
            Red,
            L"\nError in wmain(): Failed to open ToTortillaFileMapping "
            L"(0x%08X)\n",
            status);
        goto exit;
    }
    abToTortillaFileMapping = (BYTE*)MapViewOfFile(
        hToTortillaFileMapping,
        FILE_MAP_READ,
        0,
        0,
        0);
    if (abToTortillaFileMapping == NULL)
    {
        Log(
            Red,
            L"\nError in wmain(): MapViewOfFile(hToTortillaFileMapping, ...) "
            L"failed (0x%08X)\n",
            GetLastError());
        goto exit;
    }

    //
    // Open a handle to the FromTortillaWrittenEvent event, created by
    //   Tortilla's driver
    //
    RtlInitUnicodeString(
        &unicodeString,
        L"\\Tortilla\\FromTortillaWrittenEvent");
    InitializeObjectAttributes(
        &objectAttributes,
        &unicodeString,
        0,
        NULL,
        NULL);
    status = NtOpenEvent(
        &g_hFromTortillaWrittenEvent,
        SYNCHRONIZE | EVENT_MODIFY_STATE,
        &objectAttributes);
    if (status != STATUS_SUCCESS)
    {
        Log(
            Red,
            L"\nError in wmain(): Failed to open FromTortillaWrittenEvent "
            L"(0x%08X)\n",
            status);
        goto exit;
    }

    //
    // Open a handle to the FromTortillaWritingEvent event, created by
    //   Tortilla's driver
    //
    RtlInitUnicodeString(
        &unicodeString,
        L"\\Tortilla\\FromTortillaWritingEvent");
    InitializeObjectAttributes(
        &objectAttributes,
        &unicodeString,
        0,
        NULL,
        NULL);
    status = NtOpenEvent(
        &g_hFromTortillaWritingEvent,
        SYNCHRONIZE | EVENT_MODIFY_STATE,
        &objectAttributes);
    if (status != STATUS_SUCCESS)
    {
        Log(
            Red,
            L"\nError in wmain(): Failed to open FromTortillaWritingEvent "
            L"(0x%08X)\n",
            status);
        goto exit;
    }
    
    //
    // Map the FromTortillaFileMapping shared section, created by Tortilla's
    //   driver
    //
    RtlInitUnicodeString(
        &unicodeString,
        L"\\Tortilla\\FromTortillaFileMapping");
    InitializeObjectAttributes(
        &objectAttributes,
        &unicodeString,
        0,
        NULL,
        NULL);
    status = NtOpenSection(
        &hFromTortillaFileMapping,
        SECTION_MAP_WRITE,
        &objectAttributes);
    if (status != STATUS_SUCCESS)
    {
        Log(
            Red,
            L"\nError in wmain(): Failed to open FromTortillaFileMapping "
            L"(0x%08X)\n",
            status);
        goto exit;
    }
    g_pFromTortillaFileMapping = MapViewOfFile(
        hFromTortillaFileMapping,
        FILE_MAP_WRITE,
        0,
        0,
        0);
    if (g_pFromTortillaFileMapping == NULL)
    {
        Log(
            Red,
            L"\nError in wmain(): MapViewOfFile("
            L"hFromTortillaFileMapping, ...) failed (0x%08X)\n",
            GetLastError());
        goto exit;
    }
    
    Log(
        Cyan,
        L" done\n");

    //
    // Initialize lwIP and start the tortilla_tcp_listener thread
    //
    Log(
        Cyan,
        L"Initializing Lightweight TCP/IP stack...");
	if (!lwIP_init())
    {
        Log(
            Red,
            L"Error in lwIP_init(): Failed to allocate memory\n");
        goto exit;
    }
    Log(
        Cyan,
        L" done\n");

    Log(
        Cyan,
        L"\nTortilla initialization completed\n"
        L"Ready to receive network traffic from virtual machine\n\n");

    //
    // Continuously read packets from Tortilla's driver
    //
    for(;;)
    {
        //
        // Wait until the driver notifies us that a packet has been written
        //
        if (WAIT_OBJECT_0 != WaitForSingleObject(
            hToTortillaWrittenEvent,
            INFINITE))
        {
            Log(
                Red,
                L"Error in wmain(): WaitForSingleObject("
                L"hToTortillaWrittenEvent, ...) failed (0x%08X)\n",
                GetLastError());
            goto exit;
        }

        //
        // "Read" the received packet from the Tortilla driver
        //
        dwNumberOfBytesRead = *(volatile DWORD*)abToTortillaFileMapping;
        abBuffer = abToTortillaFileMapping + sizeof(DWORD);

        //
        // Log the packet received from the VM
        //
        PcapLog(
            abBuffer,
            dwNumberOfBytesRead);

        //
        // Update lwIP's ARP table
        //
        pIp = (FULL_IP_PACKET*)abBuffer;
        if ((dwNumberOfBytesRead >= sizeof(FULL_IP_PACKET)) &&
            (ntohs(pIp->EthernetHeader.type) == ETHTYPE_IP))
        {
            etharp_add_static_entry(
                (ip_addr_t*)&pIp->IpHeader.src,
                (eth_addr*)&pIp->EthernetHeader.src);
        }

        //
        // Since establishing a new TCP connection over Tor is relatively
        // costly, keep track of TCP SYN packets received from the virtual
        // machine and ignore retransmitted TCP SYN packets
        //
        pTcp = (FULL_TCP_PACKET*)abBuffer;
        if ((dwNumberOfBytesRead >= sizeof(FULL_TCP_PACKET)) &&
            (ntohs(pTcp->EthernetHeader.type) == ETHTYPE_IP) &&
            (pTcp->IpHeader._proto == IPPROTO_TCP) &&
            (TCPH_FLAGS(&pTcp->TcpHeader) & TCP_SYN))
        {
            //
            // Add the TCP SYN to our internal list of "active" SYNs; this list
            // isn't a list of established connections, but rather a list of
            // SYNs for which a connection needs to be established
            //
			if (!AddActiveSyn(
                pTcp->IpHeader.dest.addr,
                pTcp->TcpHeader.dest,
                pTcp->IpHeader.src.addr,
                pTcp->TcpHeader.seqno))
            {
                //
                // This is a retransmitted TCP SYN, so drop the packet
                //
                goto next;
            }

			//
			// Copy the packet to the heap
			//
			pPacket = (PACKET_WITH_SIZE*) malloc(sizeof(PACKET_WITH_SIZE));
			if (pPacket == NULL)
			{
				Log(
					Red,
					L"Error in wmain(): malloc(%d) failed\n",
					sizeof(PACKET_WITH_SIZE));
				goto next;
			}
			pPacket->cbPacket = dwNumberOfBytesRead;
			memcpy(
				pPacket->abPacket,
				abBuffer,
				dwNumberOfBytesRead);

			//
			// Asynchonously process the TCP connect
			//
			if (-1 == _beginthreadex(
				NULL,
				0,
				HandleTcpSyn,
				pPacket,
				0,
				NULL))
			{
				Log(
					Red,
					L"Error in wmain(): _beginthreadex() failed\n");
			}

			goto next;
        }

        //
        // If this is a DHCP request, call HandleDhcp()
        //
        pDhcp = (FULL_DHCP_PACKET*)abBuffer;
        if ((dwNumberOfBytesRead > sizeof(FULL_DHCP_PACKET)) &&
            (ntohs(pDhcp->EthernetHeader.type) == ETHTYPE_IP) &&
            (pDhcp->IpHeader._proto == IPPROTO_UDP) &&
            (ntohs(pDhcp->UdpHeader.src) == DHCP_CLIENT_PORT) &&
            (ntohs(pDhcp->UdpHeader.dest) == DHCP_SERVER_PORT) &&
            (pDhcp->DhcpHeader.op == DHCP_BOOTREQUEST) &&
            (ntohl(pDhcp->DhcpHeader.cookie) == DHCP_MAGIC_COOKIE))
        {
            HandleDhcp(
                abBuffer,
                dwNumberOfBytesRead);
            goto next;
        }
        
        //
        // If this is an ARP request, call HandleArp()
        //
        pArp = (FULL_ARP_PACKET*)abBuffer;
        if ((dwNumberOfBytesRead >= sizeof(FULL_ARP_PACKET)) &&
            (ntohs(pArp->EthernetHeader.type) == ETHTYPE_ARP) &&
            (ntohs(pArp->ArpHeader.opcode) == ARP_REQUEST))
        {
            HandleArp(
                abBuffer,
                dwNumberOfBytesRead);
            goto next;
        }

        //
        // If this is a DNS query, call HandleDns()
        //
        pDns = (FULL_DNS_PACKET*)abBuffer;
        if ((dwNumberOfBytesRead > sizeof(FULL_DNS_PACKET)) &&
            (ntohs(pDns->EthernetHeader.type) == ETHTYPE_IP) &&
            (pDns->IpHeader._proto == IPPROTO_UDP) &&
            (ntohs(pDns->UdpHeader.dest) == 53) &&
            (pDns->DnsHeader.Opcode == DNS_OPCODE_QUERY) &&
            (pDns->DnsHeader.IsResponse == 0) &&
            (ntohs(pDns->DnsHeader.QuestionCount) == 1))
        {
            //
            // Copy the packet to the heap
            //
            pPacket = (PACKET_WITH_SIZE*)malloc(sizeof(PACKET_WITH_SIZE));
            if (pPacket == NULL)
            {
                Log(
                    Red,
                    L"Error in wmain(): malloc(%d) failed\n",
                    sizeof(PACKET_WITH_SIZE));
                goto next;
            }
            pPacket->cbPacket = dwNumberOfBytesRead;
            memcpy(
                pPacket->abPacket,
                abBuffer,
                dwNumberOfBytesRead);

            //
            // Asynchonously process the DNS query
            //
            if (-1 == _beginthreadex(
                NULL,
                0,
                HandleDns,
                pPacket,
                0,
                NULL))
            {
                Log(
                    Red,
                    L"Error in wmain(): _beginthreadex() failed\n");
            }

            goto next;
        }

        //
        // If this is a TCP packet, call HandleTcp()
        //
        pTcp = (FULL_TCP_PACKET*)abBuffer;
        if ((dwNumberOfBytesRead >= sizeof(FULL_TCP_PACKET)) &&
            (ntohs(pTcp->EthernetHeader.type) == ETHTYPE_IP) &&
            (pTcp->IpHeader._proto == IPPROTO_TCP))
        {
			HandleTcp(
				abBuffer,
				dwNumberOfBytesRead);
            goto next;
        }

	next:
		//
		// Notify the Tortilla driver that we're ready to receive a packet
		//
		if (!SetEvent(
			hToTortillaWritingEvent))
		{
			Log(
				Red,
				L"Error in wmain(): SetEvent(hToTortillaWritingEvent) failed "
				L"(0x%08X)\n",
				GetLastError());
			goto exit;
		}

		continue;
    }

exit:
    //
    // If the Tortilla client was not launched from an existing console window,
    //   do not immediately terminate the process
    //
    if (GetConsoleProcessList(&dwProcessList, 1) <= 1)
    {
        Log(
            White,
            L"Press any key to exit...");

        //
        // Hide the cursor
        //
        cci.dwSize = 1;
        cci.bVisible = FALSE;
        SetConsoleCursorInfo(
            GetStdHandle(STD_OUTPUT_HANDLE),
            &cci);

        //
        // Wait until a key is pressed
        //
        hConsoleInput = GetStdHandle(STD_INPUT_HANDLE);
        FlushConsoleInputBuffer(
            hConsoleInput);
        for(;;)
        {
            ReadConsoleInput(
                hConsoleInput,
                &ir,
                1,
                &dwNumberOfEventsRead);
            if (ir.EventType != KEY_EVENT)
            {
                continue;
            }
            if ((ir.Event.KeyEvent.wVirtualKeyCode == VK_MENU) ||
                (ir.Event.KeyEvent.wVirtualKeyCode == VK_CONTROL) ||
                (ir.Event.KeyEvent.wVirtualKeyCode == VK_SHIFT))
            {
                continue;
            }

            break;
        }
    }

	return 0;
}
