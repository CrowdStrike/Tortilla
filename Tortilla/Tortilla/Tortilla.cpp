/*!
    @file       Tortilla.cpp
    @author     Jason Geffner (jason@crowdstrike.com)
    @brief      Tortilla Client v1.1.0 Beta
   
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
#define STATUS_SUCCESS              0

//
// In this context, MTU is the maximum size of a packet on the virtual wire
//
#define MTU                         (1500 + sizeof(eth_hdr))
#define RECV_TIMEOUT_MS             100
#define MAX_PACKETS_PER_ITERATION   10

//
// 86400 seconds = 24 hours
//
#define DHCP_LEASE_TIME             86400
#define DNS_TTL                     86400

#define DHCP_BROADCAST_FLAG         0x8000

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

typedef enum _ASYNCHRONOUS_SOCKET_STATE
{
    ConnectingToTorClient,
    ConnectedToTorClient,
    AuthenticationSent,
    Authenticated,
    DnsRequestSent,
    TcpConnectionRequestSent
} ASYNCHRONOUS_SOCKET_STATE;

#pragma pack(push, 1)
typedef struct _ASYNCHRONOUS_SOCKET_ITEM
{
    SOCKET s;
    ASYNCHRONOUS_SOCKET_STATE state;
    BOOL fDnsQuery;
    BOOL fTypeAQuery;
    CHAR szQueriedNameOrIp[DNS_MAX_NAME_BUFFER_LENGTH];
    BYTE* abPacket;
    SIZE_T cbPacket;
    struct _ASYNCHRONOUS_SOCKET_ITEM* pNextItem;
} ASYNCHRONOUS_SOCKET_ITEM;
#pragma pack(pop)

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

ASYNCHRONOUS_SOCKET_ITEM* g_pAsynchronousSockets;
HANDLE g_hAsiMutex;
HWND g_hwndAsynchronousSocketEngine;

HANDLE g_hConsoleOutput;
HANDLE g_hLogMutex;

struct netif netif;

/*!
    @brief Logs text to the console window

    @param[in] color The color to use for printing the logged text
    @param[in] wszFormat The format string for the logged text
    @param[in] ... The arguments for the format string
*/
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
    for (SOCKET_ITEM* pItem = g_pAvailableEstablishedSockets;
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
    @brief Sends a DNS response to the virtual machine

    @param[in] pFullDnsPacket Pointer to the original DNS request packet data
    @param[in] cbFullDnsPacket Length of the original DNS request packet
    @param[in] fDnsAnswerFound If true, the DNS lookup succeeded
    @param[in] fTypeAQuery If fDnsAnswerFound, TRUE if the DNS request was
                           DNS_TYPE_A and FALSE if the DNS request was
                           DNS_TYPE_PTR; reserved if !fDnsAnswerFound
    @param[in] dwResolvedIp If fDnsAnswerFound and fTypeAQuery, resolved IP
                            address in big-endian; otherwise reserved
    @param[in] szResolvedName If fDnsAnswerFound and !fTypeAQuery, points to
                              the resolved name; otherwise reserved
    @param[in] cbResolvedName If fDnsAnswerFound and !fTypeAQuery, length of
                              the resolved name; otherwise reserved
*/
VOID
SendDnsResponse (
    FULL_DNS_PACKET* pFullDnsPacket,
    SIZE_T cbFullDnsPacket,
    BOOL fDnsAnswerFound,
    BOOL fTypeAQuery,
    DWORD dwResolvedIp,
    CHAR* szResolvedName,
    SIZE_T cbResolvedName
    )
{
    FULL_DNS_PACKET* pFullDnsResponsePacket = NULL;
    SIZE_T cbFullDnsResponsePacket;
    DNS_ANSWER_RECORD* pDnsAnswerRecord;
    WORD cbLabel;
    CHAR* pcQName;
    CHAR c;
    pbuf* pBuf;

    //
    // Allocate a success/fail DNS response back to client
    //
    cbFullDnsResponsePacket = cbFullDnsPacket;
    if (fDnsAnswerFound)
    {
        //
        // If we have a DNS answer to send back, allocate space for it
        //
        cbFullDnsResponsePacket += sizeof(DNS_ANSWER_RECORD) + (fTypeAQuery ?
            sizeof(dwResolvedIp) : ((size_t)cbResolvedName + 2));
    }
    pFullDnsResponsePacket = (FULL_DNS_PACKET*)malloc(
        cbFullDnsResponsePacket);
    if (pFullDnsResponsePacket == NULL)
    {
        Log(
            Red,
            L"Error in HandleDns(): malloc(%d) failed\n",
            cbFullDnsResponsePacket);
        goto exit;
    }

    //
    // Copy the DNS request packet into the DNS response packet
    //
    memcpy(
        pFullDnsResponsePacket,
        pFullDnsPacket,
        cbFullDnsPacket);

    //
    // Set the Ethernet header
    //
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
        cbFullDnsResponsePacket -
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
    pFullDnsResponsePacket->UdpHeader.src = htons(DNS_PORT_HOST_ORDER);
    pFullDnsResponsePacket->UdpHeader.len = htons(
        cbFullDnsResponsePacket -
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
    pFullDnsResponsePacket->DnsHeader.ResponseCode = fDnsAnswerFound ?
        DNS_RCODE_NOERROR :
        DNS_RCODE_SERVFAIL;
    pFullDnsResponsePacket->DnsHeader.AnswerCount = htons(
        fDnsAnswerFound ? 1 : 0);

    //
    // Construct the DNS_ANSWER_RECORD
    //
    if (fDnsAnswerFound)
    {
        pDnsAnswerRecord =
            (DNS_ANSWER_RECORD*)((BYTE*)pFullDnsResponsePacket +
            cbFullDnsPacket);

        pDnsAnswerRecord->CompressedName = htons(DNS_COMPRESSED_QUESTION_NAME);
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
                htons((SIZE_T)cbResolvedName + 2);
            cbLabel = 0;
            pcQName = (CHAR*)pDnsAnswerRecord + sizeof(DNS_ANSWER_RECORD);
            for (SIZE_T iResolvedName = 0;
                iResolvedName < ((SIZE_T)cbResolvedName + 1);
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
        cbFullDnsResponsePacket - sizeof(eth_hdr) - sizeof(ip_hdr),
        PBUF_RAM);
    if (pBuf == NULL)
    {
        Log(
            Red,
            L"Error in HandleDns(): pbuf_alloc(..., %d, ...) failed\n",
            cbFullDnsResponsePacket - sizeof(eth_hdr) - sizeof(ip_hdr));
        goto exit;
    }
    memcpy(
        pBuf->payload,
        &pFullDnsResponsePacket->UdpHeader,
        cbFullDnsResponsePacket - sizeof(eth_hdr) - sizeof(ip_hdr));
    pFullDnsResponsePacket->UdpHeader.chksum = inet_chksum_pseudo(
        pBuf,
        (ip_addr_t*)&pFullDnsResponsePacket->IpHeader.src,
        (ip_addr_t*)&pFullDnsResponsePacket->IpHeader.dest,
        IP_PROTO_UDP,
        cbFullDnsResponsePacket - sizeof(eth_hdr) - sizeof(ip_hdr));
    if (pFullDnsResponsePacket->UdpHeader.chksum == 0)
    {
        pFullDnsResponsePacket->UdpHeader.chksum = 0xFFFF;
    }
    pbuf_free(pBuf);

    //
    // Send the DNS response to the virtual machine
    //
    SendPacketToClient(
        (BYTE*)pFullDnsResponsePacket,
        cbFullDnsResponsePacket);

exit:
    if (pFullDnsResponsePacket != NULL)
    {
        free(pFullDnsResponsePacket);
    }
}

/*! 
    @brief Inserts an ASYNCHRONOUS_SOCKET_ITEM into the g_pAsynchronousSockets
           linked-list

    @param[in] pAsi Pointer to the ASYNCHRONOUS_SOCKET_ITEM to insert into the
                    g_pAsynchronousSockets linked-list
    @return Returns TRUE on success, FALSE on failure
*/
BOOL
InsertAsynchronousSocketItemIntoList (
    ASYNCHRONOUS_SOCKET_ITEM* pAsi
    )
{
    if (WAIT_OBJECT_0 != WaitForSingleObject(
        g_hAsiMutex,
        INFINITE))
    {
        Log(
            Red,
            L"Error in InsertAsynchronousSocketItemIntoList(): Could not "
            L"acquire mutex (0x%08X)\n",
            GetLastError());
        return FALSE;
    }
    
    if (g_pAsynchronousSockets == NULL)
    {
        g_pAsynchronousSockets = pAsi;
    }
    else
    {
        for (
            ASYNCHRONOUS_SOCKET_ITEM* p = g_pAsynchronousSockets;
            ;
            p = p->pNextItem)
        {
            if (p->pNextItem == NULL)
            {
                p->pNextItem = pAsi;
                break;
            }
        }
    }

    ReleaseMutex(g_hAsiMutex);

    return TRUE;
}

/*! 
    @brief Updates an ASYNCHRONOUS_SOCKET_ITEM in the g_pAsynchronousSockets
           linked-list

    @param[in] pAsi Pointer to the ASYNCHRONOUS_SOCKET_ITEM to update
    @return Returns TRUE on success, FALSE on failure
*/
BOOL
UpdateAsynchronousSocketItemInList (
    ASYNCHRONOUS_SOCKET_ITEM* pAsi
    )
{
    BOOL fSuccess = FALSE;
    BOOL fMutexHeld = FALSE;

    if (WAIT_OBJECT_0 != WaitForSingleObject(
        g_hAsiMutex,
        INFINITE))
    {
        Log(
            Red,
            L"Error in UpdateAsynchronousSocketItemInList(): Could not "
            L"acquire mutex (0x%08X)\n",
            GetLastError());
        goto exit;
    }
    fMutexHeld = TRUE;
    
    for (
        ASYNCHRONOUS_SOCKET_ITEM* p = g_pAsynchronousSockets;
        p != NULL;
        p = p->pNextItem)
    {
        if (p != pAsi)
        {
            continue;
        }

        memcpy(
            p,
            pAsi,
            sizeof(ASYNCHRONOUS_SOCKET_ITEM) - sizeof(pAsi->pNextItem));
        fSuccess = TRUE;
        break;
    }
    
exit:
    if (fMutexHeld)
    {
        ReleaseMutex(g_hAsiMutex);
    }

    return fSuccess;
}

/*! 
    @brief Removes an ASYNCHRONOUS_SOCKET_ITEM from the g_pAsynchronousSockets
           linked-list and optionally closes that item's socket

    @param[in] s SOCKET for the ASYNCHRONOUS_SOCKET_ITEM to be removed
    @param[in] fCloseSocket Specifies if the caller wants
                            UpdateAsynchronousSocketItemInList() to close the
                            socket
    @return Returns TRUE on success, FALSE on failure
*/
BOOL
RemoveAsynchronousSocketItemFromList (
    SOCKET s,
    BOOL fCloseSocket
    )
{
    BOOL fSuccess = FALSE;
    BOOL fMutexHeld = FALSE;
    ASYNCHRONOUS_SOCKET_ITEM* pAsi;

    if (WAIT_OBJECT_0 != WaitForSingleObject(
        g_hAsiMutex,
        INFINITE))
    {
        Log(
            Red,
            L"Error in RemoveAsynchronousSocketItemFromList(): Could not "
            L"acquire mutex (0x%08X)\n",
            GetLastError());
        goto exit;
    }
    fMutexHeld = TRUE;
    
    if (g_pAsynchronousSockets == NULL)
    {
        goto exit;
    }

    if (g_pAsynchronousSockets->s == s)
    {
        if (fCloseSocket)
        {
            closesocket(s);
        }
        free(g_pAsynchronousSockets->abPacket);

        pAsi = g_pAsynchronousSockets->pNextItem;
        free(g_pAsynchronousSockets);
        g_pAsynchronousSockets = pAsi;

        fSuccess = TRUE;
        goto exit;
    }

    for (
        ASYNCHRONOUS_SOCKET_ITEM* p = g_pAsynchronousSockets;
        ;
        p = p->pNextItem)
    {
        if (p->pNextItem == NULL)
        {
            goto exit;
        }

        if (p->pNextItem->s != s)
        {
            continue;
        }

        if (fCloseSocket)
        {
            closesocket(s);
        }
        free(p->pNextItem->abPacket);

        pAsi = p->pNextItem->pNextItem;
        free(p->pNextItem);
        p->pNextItem = pAsi;

        fSuccess = TRUE;
        goto exit;
    }
    
exit:
    if (fMutexHeld)
    {
        ReleaseMutex(g_hAsiMutex);
    }

    return fSuccess;
}


/*! 
    @brief Handles a DNS query or TCP SYN packet from the virtual machine

    @param[in] fDns If TRUE, the packet is a DNS packet; if FALSE, the packet
                    is a TCP SYN packet
    @param[in] abPacket Pointer to the original packet data received from the
                        virtual machine
    @param[in] cbPacket Length of the original packet
*/
VOID
HandleDnsOrTcpSyn (
    BOOL fDns,
    BYTE* abPacket,
    SIZE_T cbPacket
    )
{
    BOOL fSuccess = FALSE;
    BOOL fNameExtracted = FALSE;
    BOOL fTypeAQuery;
    CHAR szName[DNS_MAX_NAME_BUFFER_LENGTH];
    SOCKET s = INVALID_SOCKET;
    ASYNCHRONOUS_SOCKET_ITEM* pAsi = NULL;
    sockaddr_in sin;
    BOOL fInserted = FALSE;

    if (fDns)
    {
        //
        // Extract the hostname or IP address from the DNS query
        //
        if (!ExtractNameFromDnsQuery(
            abPacket,
            cbPacket,
            szName,
            _countof(szName),
            &fTypeAQuery))
        {
            goto exit;
        }

        fNameExtracted = TRUE;
    }

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
            L"Error in HandleDnsOrTcpSyn(): Could not create a new socket "
            L"object (0x%08X)\n",
            WSAGetLastError());
        goto exit;
    }

    //
    // Set the new socket to be asynchronous
    //
    if (0 != WSAAsyncSelect(
        s,
        g_hwndAsynchronousSocketEngine,
        WM_USER,
        FD_READ | FD_WRITE | FD_CONNECT | FD_CLOSE))
    {
        Log(
            Red,
            L"Error in HandleDnsOrTcpSyn(): WSAAsyncSelect() failed "
            L"(0x%08X)\n",
            WSAGetLastError());
        goto exit;
    }

    //
    // Construct an ASYNCHRONOUS_SOCKET_ITEM structure and insert it into the
    // g_pAsynchronousSockets list
    //
    pAsi = (ASYNCHRONOUS_SOCKET_ITEM*)malloc(sizeof(ASYNCHRONOUS_SOCKET_ITEM));
    if (pAsi == NULL)
    {
        Log(
            Red,
            L"Error in HandleDnsOrTcpSyn(): malloc(%d) failed\n",
            sizeof(ASYNCHRONOUS_SOCKET_ITEM));
        goto exit;
    }
    pAsi->s = s;
    pAsi->state = ConnectingToTorClient;
    pAsi->fDnsQuery = fDns;
    if (fDns)
    {
        pAsi->fTypeAQuery = fTypeAQuery;
        strcpy_s(
            pAsi->szQueriedNameOrIp,
            _countof(pAsi->szQueriedNameOrIp),
            szName);
    }
    pAsi->abPacket = (BYTE*)malloc(cbPacket);
    if (pAsi->abPacket == NULL)
    {
        Log(
            Red,
            L"Error in HandleDnsOrTcpSyn(): malloc(%d) failed\n",
            cbPacket);
        goto exit;
    }
    memcpy(
        pAsi->abPacket,
        abPacket,
        cbPacket);
    pAsi->cbPacket = cbPacket;
    pAsi->pNextItem = NULL;
    if (!InsertAsynchronousSocketItemIntoList(pAsi))
    {
        goto exit;
    }
    fInserted = TRUE;

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
    if (!((SOCKET_ERROR == connect(
        s,
        (sockaddr*)&sin,
        sizeof(sin))) &&
        (WSAGetLastError() == WSAEWOULDBLOCK)))
    {
        Log(
            Red,
            L"Error in HandleDnsOrTcpSyn(): connect() failed (0x%08X)\n",
            WSAGetLastError());
        goto exit;
    }

    fSuccess = TRUE;

exit:
    if (fSuccess)
    {
        return;
    }

    if (fDns)
    {
        if (fNameExtracted)
        {
            Log(
                Red,
                L"Failed to resolve DNS query for %S\n",
                szName);
        }

        //
        // Send a DNS_RCODE_SERVFAIL response to the virtual machine
        //
        SendDnsResponse(
            (FULL_DNS_PACKET*)abPacket,
            cbPacket,
            FALSE,
            fTypeAQuery,
            0,
            NULL,
            0);
    }

    if (fInserted)
    {
        RemoveAsynchronousSocketItemFromList(
            s,
            TRUE);
    }
    else
    {
        if (s != INVALID_SOCKET)
        {
            closesocket(s);
        }

        if (pAsi != NULL)
        {
            if (pAsi->abPacket != NULL)
            {
                free(pAsi->abPacket);
            }
            free(pAsi);
        }
    }
}

/*! 
    @brief Handle a TCP packet received from the virtual machine

    @param[in] abPacket Pointer to the original packet data received from the
                        virtual machine
    @param[in] cbPacket Length of the original packet
*/
VOID
HandleTcp (
    BYTE* abPacket,
	SIZE_T cbPacket
    )
{
    pbuf* pBuf;

    //
    // Send the TCP packet to the lwIP TCP/IP stack
    //

    pBuf = pbuf_alloc(
        PBUF_RAW,
		cbPacket,
        PBUF_RAM);
    if (pBuf == NULL)
    {
        Log(
            Red,
            L"Error in HandleTcp(): pbuf_alloc(..., %d, ...) failed\n",
            cbPacket);
        return;
    }

    memcpy(
        pBuf->payload,
        abPacket,
        cbPacket);

    if (ERR_OK != tcpip_input(
        pBuf,
        &netif))
    {
        Log(
            Red,
            L"Error in HandleTcp(): tcpip_input() failed\n");

        pbuf_free(
            pBuf);
    }
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
    @brief Connects to a remote server through the local Tor client; called
           after authentication to local Tor client

    @param[in] pAsi The ASYNCHRONOUS_SOCKET_ITEM to handle
    @param[in] wSelectEvent The network event about which we're being notified
    @param[in] wSelectError The error value (if any) associated with the
                            network event
*/
VOID
ProcessAsynchronousTcpEvent (
    ASYNCHRONOUS_SOCKET_ITEM* pAsi,
    WORD wSelectEvent,
    WORD wSelectError
    )
{
    BOOL fSuccess = FALSE;
    BYTE abSocksTcpRequest[10];
    FULL_TCP_PACKET* pTcp = (FULL_TCP_PACKET*)pAsi->abPacket;
    BYTE abSocksConnectionResponse[10];
    INT cbSocksConnectionResponse;
    FULL_TCP_PACKET tcpReset;
    pbuf* pBuf;
    ULONG ulZero;


    if (pAsi->state == Authenticated)
    {
        //
        // This is the state after we've authenticated to the local Tor client
        //

        if (wSelectEvent == FD_CLOSE)
        {
            Log(
                Red,
                L"Error in ProcessAsynchronousTcpEvent(): The connection to "
                L"the local Tor client was unexpectedly closed in state "
                L"Authenticated (%d, 0x%04X, 0x%04X)\n",
                pAsi->s,
                wSelectEvent,
                wSelectError);
            goto exit;
        }

        if (wSelectError != 0)
        {
            Log(
                Red,
                L"Error in ProcessAsynchronousTcpEvent(): Unexpected socket "
                L"event received in state Authenticated (%d, 0x%04X, "
                L"0x%04X)\n",
                pAsi->s,
                wSelectEvent,
                wSelectError);
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
            pAsi->s,
            (char*)abSocksTcpRequest,
            _countof(abSocksTcpRequest),
            0))
        {
            Log(
                Red,
                L"Error in ProcessAsynchronousTcpEvent(): send() failed when "
                L"attempting to send the connection request to the local Tor "
                L"client (%d, 0x%08X)\n",
                pAsi->s,
                WSAGetLastError());
            goto exit;
        }

        pAsi->state = TcpConnectionRequestSent;
        fSuccess = UpdateAsynchronousSocketItemInList(
            pAsi);

        goto exit;
    }
    else if (pAsi->state != TcpConnectionRequestSent)
    {
        Log(
            Red,
            L"Error in ProcessAsynchronousTcpEvent(): Unexpected state "
            L"(%d, 0x%08X)\n",
            pAsi->s,
            pAsi->state);
        goto exit;
    }

    //
    // This is the state after we've just sent the TCP connection request to
    // the local Tor client
    //

    if (wSelectEvent == FD_CLOSE)
    {
        Log(
            Red,
            L"Error in ProcessAsynchronousTcpEvent(): The connection to the "
            L"local Tor client was unexpectedly closed in state "
            L"TcpConnectionRequestSent (%d, 0x%04X, 0x%04X)\n",
            pAsi->s,
            wSelectEvent,
            wSelectError);
        goto exit;
    }
            
    if ((wSelectEvent == FD_WRITE) && (wSelectError == 0))
    {
        fSuccess = TRUE;
        goto exit;
    }

    if (!((wSelectEvent == FD_READ) && (wSelectError == 0)))
    {
        Log(
            Red,
            L"Error in ProcessAsynchronousTcpEvent(): Unexpected socket event "
            L"received in TcpConnectionRequestSent state (%d, 0x%04X, "
            L"0x%04X)\n",
            pAsi->s,
            wSelectEvent,
            wSelectError);
        goto exit;
    }

    //
    // Get the TCP connection response from the local Tor client
    //
    cbSocksConnectionResponse = recv(
        pAsi->s,
        (char*)abSocksConnectionResponse,
        sizeof(abSocksConnectionResponse),
        0);
    if (!((cbSocksConnectionResponse == sizeof(abSocksConnectionResponse)) &&
        (abSocksConnectionResponse[0] == 0x05)))
    {
        Log(
            Red,
            L"Error in ProcessAsynchronousTcpEvent(): Unexpected response "
            L"from the local Tor client (%d, 0x%08X)\n",
            pAsi->s,
            WSAGetLastError());
        goto exit;
    }

    //
    // Process the connection response from the local Tor client
    //
    if (abSocksConnectionResponse[1] == 0x00)
    {
        //
        // The local Tor service was able to connect to the target server, so
        // set the socket mode back to blocking
        //
        if (0 != WSAAsyncSelect(
            pAsi->s,
            g_hwndAsynchronousSocketEngine,
            WM_USER,
            0))
        {
            Log(
                Red,
                L"Error in ProcessAsynchronousTcpEvent(): WSAAsyncSelect() "
                L"failed when trying to set socket #%d back to blocking mode "
                L"(0x%08X)\n",
                pAsi->s,
                WSAGetLastError());
            goto exit;
        }
        ulZero = 0;
        if (0 != ioctlsocket(
            pAsi->s,
            FIONBIO,
            &ulZero))
        {
            Log(
                Red,
                L"Error in ProcessAsynchronousTcpEvent(): ioctlsocket() "
                L"failed when trying to set socket #%d back to blocking mode "
                L"(0x%08X)\n",
                pAsi->s,
                WSAGetLastError());
            goto exit;
        }

        //
        // Add this conncted SOCKS socket to the list of Available Established
        // Sockets
        //
        fSuccess = AddAvailableEstablishedSocket(
            pTcp->IpHeader.dest.addr,
            pTcp->TcpHeader.dest,
            pAsi->s);
        if (!fSuccess)
        {
            goto exit;
        }

        Log(
            Green,
            L"Connected to %S:%d (socket #%d)\n",
            inet_ntoa(*(in_addr*)&pTcp->IpHeader.dest),
            ntohs(pTcp->TcpHeader.dest),
            pAsi->s);

        HandleTcp(
            pAsi->abPacket,
            pAsi->cbPacket);

        RemoveAsynchronousSocketItemFromList(
            pAsi->s,
            FALSE);

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
            L"Could not connect to %S:%d (socket #%d)\n",
            inet_ntoa(*(in_addr*)&pTcp->IpHeader.dest),
            ntohs(pTcp->TcpHeader.dest),
            pAsi->s);

        goto exit;
    }

    //
    // The remote server actively refused the connection attempt, so respond to
    // the virtual machine with a TCP SYN packet
    //

    Log(
        Red,
        L"Connection request refused by %S:%d (socket #%d)\n",
        inet_ntoa(*(in_addr*)&pTcp->IpHeader.dest),
        ntohs(pTcp->TcpHeader.dest),
        pAsi->s);

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
            L"Error in ProcessAsynchronousTcpEvent(): "
            L"pbuf_alloc(..., %d, ...) failed\n",
            sizeof(tcpReset));
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
    if (!fSuccess)
    {
        RemoveAsynchronousSocketItemFromList(
            pAsi->s,
            TRUE);
    }
}

/*! 
    @brief Performs a DNS lookup through the local Tor client; called
           after authentication to local Tor client

    @param[in] pAsi The ASYNCHRONOUS_SOCKET_ITEM to handle
    @param[in] wSelectEvent The network event about which we're being notified
    @param[in] wSelectError The error value (if any) associated with the
                            network event
*/
VOID
ProcessAsynchronousDnsEvent (
    ASYNCHRONOUS_SOCKET_ITEM* pAsi,
    WORD wSelectEvent,
    WORD wSelectError
    )
{
    BOOL fSuccess = FALSE;
    BYTE abSocksDnsRequest[DNS_MAX_NAME_LENGTH + 7];
    SIZE_T cchNameLength;
    DWORD dwIp;
    INT cbSocksDnsResponse;
    CHAR acSocksDnsResponse[DNS_MAX_NAME_LENGTH + 7];
    BYTE cbResolvedName;
    CHAR szResolvedName[DNS_MAX_NAME_BUFFER_LENGTH];
    DWORD dwResolvedIp;

    if (pAsi->state == Authenticated)
    {
        //
        // This is the state after we've authenticated to the local Tor client
        //

        if (wSelectEvent == FD_CLOSE)
        {
            Log(
                Red,
                L"Error in ProcessAsynchronousDnsEvent(): The connection to "
                L"the local Tor client was unexpectedly closed in state "
                L"Authenticated (%d, 0x%04X, 0x%04X)\n",
                pAsi->s,
                wSelectEvent,
                wSelectError);
            goto exit;
        }

        if (wSelectError != 0)
        {
            Log(
                Red,
                L"Error in ProcessAsynchronousDnsEvent(): Unexpected socket "
                L"event received in state Authenticated "
                L"(%d, 0x%04X, 0x%04X)\n",
                pAsi->s,
                wSelectEvent,
                wSelectError);
            goto exit;
        }

        //
        // Send the DNS request to the local Tor client
        //

        abSocksDnsRequest[0] = 0x05;                    // SOCKS5
        if (pAsi->fTypeAQuery)
        {
            cchNameLength = strlen(pAsi->szQueriedNameOrIp);
            abSocksDnsRequest[1] =
                (BYTE)SOCKS_COMMAND_RESOLVE;            // Command
            abSocksDnsRequest[2] = 0x00;                // Reserved
            abSocksDnsRequest[3] = 0x03;                // Address type: FQDN
            abSocksDnsRequest[4] = cchNameLength;       // FQDN length
            memcpy(                                     // FQDN
                &abSocksDnsRequest[5],
                pAsi->szQueriedNameOrIp,
                cchNameLength);
            abSocksDnsRequest[5 + cchNameLength] = 0x00;    // Port
            abSocksDnsRequest[6 + cchNameLength] = 0x00;    // Port
        }
        else
        {
            abSocksDnsRequest[1] =
                (BYTE)SOCKS_COMMAND_RESOLVE_PTR;        // Command
            abSocksDnsRequest[2] = 0x00;                // Reserved
            abSocksDnsRequest[3] = 0x01;                // Address type: IPv4
            dwIp = inet_addr(pAsi->szQueriedNameOrIp);
            memcpy(                                     // IP
                &abSocksDnsRequest[4],
                &dwIp,
                sizeof(dwIp));
            abSocksDnsRequest[8] = 0x00;                // Port
            abSocksDnsRequest[9] = 0x00;                // Port
        }
            
        if (SOCKET_ERROR == send(
            pAsi->s,
            (CHAR*)abSocksDnsRequest,
            pAsi->fTypeAQuery ? (7 + cchNameLength) : 10,
            0))
        {
            Log(
                Red,
                L"Error in ProcessAsynchronousDnsEvent(): Could not send DNS "
                L"request to local Tor client (%d, 0x%08X)\n",
                pAsi->s,
                WSAGetLastError());
            goto exit;
        }

        pAsi->state = DnsRequestSent;
        fSuccess = UpdateAsynchronousSocketItemInList(
            pAsi);

        goto exit;
    }
    else if (pAsi->state != DnsRequestSent)
    {
        Log(
            Red,
            L"Error in ProcessAsynchronousDnsEvent(): Unexpected state "
            L"(%d, 0x%08X)\n",
            pAsi->s,
            pAsi->state);
        goto exit;
    }

    //
    // This is the state after we've just sent the DNS request to the local Tor
    // client
    //

    if (wSelectEvent == FD_CLOSE)
    {
        Log(
            Red,
            L"Error in ProcessAsynchronousDnsEvent(): The connection to the"
            L"local Tor client was unexpectedly closed in state "
            L"DnsRequestSent (%d, 0x%04X, 0x%04X)\n",
            pAsi->s,
            wSelectEvent,
            wSelectError);
        goto exit;
    }
            
    if ((wSelectEvent == FD_WRITE) && (wSelectError == 0))
    {
        fSuccess = TRUE;
        goto exit;
    }

    if (!((wSelectEvent == FD_READ) && (wSelectError == 0)))
    {
        Log(
            Red,
            L"Error in ProcessAsynchronousDnsEvent(): Unexpected socket event "
            L"received in DnsRequestSent state (%d, 0x%04X, 0x%04X)\n",
            pAsi->s,
            wSelectEvent,
            wSelectError);
        goto exit;
    }

    //
    // Get the DNS response from the local Tor client
    //
    cbSocksDnsResponse = recv(
        pAsi->s,
        acSocksDnsResponse,
        sizeof(acSocksDnsResponse),
        0);
    if (cbSocksDnsResponse == SOCKET_ERROR)
    {
        Log(
            Red,
            L"Error in ProcessAsynchronousDnsEvent(): Could not receive DNS "
            L"response from local Tor client (%d, 0x%08X)\n",
            pAsi->s,
            WSAGetLastError());
        goto exit;
    }

    if (pAsi->fTypeAQuery)
    {
        //
        // Query was a hostname, so validate that response is an IP address
        //
        if (!((cbSocksDnsResponse == 10) &&
            (acSocksDnsResponse[0] == 0x05) &&  // SOCKS5
            (acSocksDnsResponse[1] == 0x00) &&  // SOCKS5_SUCCEEDED
            (acSocksDnsResponse[3] == 0x01)))   // IPv4 address
        {
            goto exit;
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
            goto exit;
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
                L"Error in ProcessAsynchronousDnsEvent(): DNS_TYPE_PTR lookup "
                L"returned hostname with invalid length\n");
            goto exit;
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

    Log(
        Cyan,
        L"Resolved DNS query for %S to %S\n",
        pAsi->szQueriedNameOrIp,
        pAsi->fTypeAQuery ? inet_ntoa(*(in_addr*)&dwResolvedIp) :
        szResolvedName);
    
    SendDnsResponse(
        (FULL_DNS_PACKET*)pAsi->abPacket,
        pAsi->cbPacket,
        TRUE,
        pAsi->fTypeAQuery,
        dwResolvedIp,
        szResolvedName,
        cbResolvedName);

    RemoveAsynchronousSocketItemFromList(
        pAsi->s,
        TRUE);

exit:
    if (!fSuccess)
    {
        Log(
            Red,
            L"Failed to resolve DNS query for %S\n",
            pAsi->szQueriedNameOrIp);

        //
        // Send a DNS_RCODE_SERVFAIL response to the virtual machine
        //
        SendDnsResponse(
            (FULL_DNS_PACKET*)pAsi->abPacket,
            pAsi->cbPacket,
            FALSE,
            pAsi->fTypeAQuery,
            0,
            NULL,
            0);

        RemoveAsynchronousSocketItemFromList(
            pAsi->s,
            TRUE);
    }
}

/*! 
    @brief A WNDPROC callback that receives notifications of asynchronous
           socket events; acts as a state machine per socket to connect to and
           authenticate to the local Tor client, then call the appropriate TCP
           and DNS handling functions
    
    @param[in] hwnd Handle to the g_hwndAsynchronousSocketEngine window
    @param[in] uMsg Window message; if WM_USER then this is a socket event
    @param[in] wParam If uMsg == WM_USER, this is the socket for the received
                      event
    @param[in] lParam If uMsg == WM_USER, this value contains the network event
                      and error values which can be extracted via
                      WSAGETSELECTEVENT() and WSAGETSELECTERROR()
    @return Returns 0 if uMsg == WM_USER, otherwise returns return value of
            DefWindowProc()
*/
LRESULT
__stdcall
AsynchronousSocketEngine (
    HWND hwnd,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam
    )
{
    SOCKET s;
    WORD wSelectEvent;
    WORD wSelectError;
    ASYNCHRONOUS_SOCKET_ITEM* pAsi = NULL;
    BOOL fSuccess = TRUE;

    //
    // All WSAAsyncSelect events will have a uMsg value of WM_USER. Call
    // DefWindowProc() on all other window messages (window creation, etc.).
    //
    if (uMsg != WM_USER)
    {
        return DefWindowProc(
            hwnd,
            uMsg,
            wParam,
            lParam);
    }

    //
    // Extract the socket, WSAAsyncSelect event, and WSAAsyncSelect error (if
    // any) from the AsynchronousTcpSynEngine() function arguments
    //
    s = wParam;
    wSelectEvent = WSAGETSELECTEVENT(lParam);
    wSelectError = WSAGETSELECTERROR(lParam);

    //
    // Acquire the g_hAsiMutex mutex
    //
    if (WAIT_OBJECT_0 != WaitForSingleObject(
        g_hAsiMutex,
        INFINITE))
    {
        Log(
            Red,
            L"Error in AsynchronousSocketEngine(): Could not acquire mutex "
            L"(0x%08X)\n",
            GetLastError());
        goto exit;
    }

    //
    // Find the ASYNCHRONOUS_SOCKET_ITEM for this socket in the
    // g_pAsynchronousSockets list
    //
    for (pAsi = g_pAsynchronousSockets;
        pAsi != NULL;
        pAsi = pAsi->pNextItem)
    {
        if (pAsi->s == s)
        {
            break;
        }
    }

    ReleaseMutex(g_hAsiMutex);

    if (pAsi == NULL)
    {
        //
        // It may be the case that we're still receiving notifications from the
        // application message queue backlog after we've removed the socket
        // from the g_pAsynchronousSockets list. This is not a problem or a
        // bug, and we can silently ignore this.
        //
        goto exit;
    }

    fSuccess = FALSE;

    //
    // The switch statement below handles the states during authentication to
    // the local Tor client
    //
    switch (pAsi->state)
    {
        case ConnectingToTorClient:
        {
            //
            // This is the state for the initial connect() call
            //

            if (wSelectEvent != FD_CONNECT)
            {
                //
                // Ignore all events prior to the FD_CONNECT event, since these
                // other events would have been for a previously closed socket
                // which happened to have the same socket number
                //

                fSuccess = TRUE;

                goto exit;
            }

            if (wSelectError != 0)
            {
                Log(
                    Red,
                    L"Error in AsynchronousSocketEngine(): Could not connect "
                    L"socket #%d to the local Tor client (0x%04X). This could "
                    L"be because the running Tor client cannot receive any "
                    L"more incoming connections, or because the Tor client is "
                    L"not running, or because Tortilla.ini is not configured "
                    L"correctly to access the Tor client via the correct IP "
                    L"address and TCP port.\n",
                    pAsi->s,
                    wSelectError);
                goto exit;
            }

            pAsi->state = ConnectedToTorClient;
            fSuccess = UpdateAsynchronousSocketItemInList(
                pAsi);

            goto exit;
        }

        case ConnectedToTorClient:
        {
            //
            // This is the state after we've just connected to the local Tor
            // client
            //

            if (wSelectEvent == FD_CLOSE)
            {
                Log(
                    Red,
                    L"Error in AsynchronousSocketEngine(): The connection to "
                    L"the local Tor client was unexpectedly closed in state "
                    L"ConnectedToTorClient (%d, 0x%04X, 0x%04X)\n",
                    pAsi->s,
                    wSelectEvent,
                    wSelectError);
                goto exit;
            }

            if (!((wSelectEvent == FD_WRITE) && (wSelectError == 0)))
            {
                Log(
                    Red,
                    L"Error in AsynchronousSocketEngine(): Unexpected socket "
                    L"event received in state ConnectedToTorClient "
                    L"(%d, 0x%04X, 0x%04X)\n",
                    pAsi->s,
                    wSelectEvent,
                    wSelectError);
                goto exit;
            }

            //
            // Perform authentication handshake with local Tor client
            //
            if (SOCKET_ERROR == send(
                s,
                "\x05"  // SOCKS5
                "\x01"  // 1 authentication method
                "\x00", // No authentication
                3,
                0))
            {
                Log(
                    Red,
                    L"Error in AsynchronousSocketEngine(): send() failed in "
                    L"state ConnectedToTorClient (%d, 0x%08X)\n",
                    pAsi->s,
                    WSAGetLastError());
                goto exit;
            }

            pAsi->state = AuthenticationSent;
            fSuccess = UpdateAsynchronousSocketItemInList(
                pAsi);

            goto exit;
        }

        case AuthenticationSent:
        {
            //
            // This is the state after we've just sent the authentication
            // string to the local Tor client
            //

            if (wSelectEvent == FD_CLOSE)
            {
                Log(
                    Red,
                    L"Error in AsynchronousSocketEngine(): The connection to "
                    L"the local Tor client was unexpectedly closed in state "
                    L"AuthenticationSent (%d, 0x%04X, 0x%04X)\n",
                    pAsi->s,
                    wSelectEvent,
                    wSelectError);
                goto exit;
            }
            
            if ((wSelectEvent == FD_WRITE) && (wSelectError == 0))
            {
                fSuccess = TRUE;
                goto exit;
            }

            if (!((wSelectEvent == FD_READ) && (wSelectError == 0)))
            {
                Log(
                    Red,
                    L"Error in AsynchronousSocketEngine(): Unexpected socket "
                    L"event received in state AuthenticationSent "
                    L"(%d, 0x%04X, 0x%04X)\n",
                    pAsi->s,
                    wSelectEvent,
                    wSelectError);
                goto exit;
            }

            BYTE abSocksAuthenticationResponse[2];
            if (sizeof(abSocksAuthenticationResponse) != recv(
                s,
                (char*)abSocksAuthenticationResponse,
                sizeof(abSocksAuthenticationResponse),
                0))
            {
                Log(
                    Red,
                    L"Error in AsynchronousSocketEngine(): recv() failed in "
                    L"state AuthenticationSent (%d, 0x%08X)\n",
                    pAsi->s,
                    WSAGetLastError());
                goto exit;
            }

            if (!((abSocksAuthenticationResponse[0] == 0x05) && // SOCKS5
                (abSocksAuthenticationResponse[1] == 0x00)))    // No auth
            {
                Log(
                    Red,
                    L"Error in AsynchronousSocketEngine(): Could not "
                    L"authenticate to local Tor client\n");
                goto exit;
            }

            pAsi->state = Authenticated;
            if (!UpdateAsynchronousSocketItemInList(
                pAsi))
            {
                goto exit;
            }
        }
    }

    fSuccess = TRUE;

    //
    // By this point, the state is either Authenticated or post-Authenticated
    //

    if (pAsi->fDnsQuery)
    {
        ProcessAsynchronousDnsEvent(
            pAsi,
            wSelectEvent,
            wSelectError);
    }
    else
    {
        ProcessAsynchronousTcpEvent(
            pAsi,
            wSelectEvent,
            wSelectError);
    }

exit:
    if (!fSuccess)
    {
        if (pAsi->fDnsQuery)
        {
            Log(
                Red,
                L"Failed to resolve DNS query for %S\n",
                pAsi->szQueriedNameOrIp);

            //
            // Send a DNS_RCODE_SERVFAIL response to the virtual machine
            //
            SendDnsResponse(
                (FULL_DNS_PACKET*)pAsi->abPacket,
                pAsi->cbPacket,
                FALSE,
                pAsi->fTypeAQuery,
                0,
                NULL,
                0);
        }
        RemoveAsynchronousSocketItemFromList(
            pAsi->s,
            TRUE);
    }

    return 0;
}

/*! 
    @brief Creates a hidden window for use by WSAAsyncSelect()
 
    @param[in] arglist The first argument in arglist is a handle to the event
                       to be signaled when this function finishes. The second
                       argument in arglist is a pointer to a BOOL which
                       signifies the success or failure of this function.
    @return On failure, returns 0; on success, doesn't return
*/
UINT
__stdcall
StartAsynchronousSocketEngine (
    VOID* arglist
    )
{
    WNDCLASS wndclass;
    ATOM atomClass;
    MSG msg;
    HANDLE hSocketEngineEvent;
    BOOL* pfSuccess;

    //
    // Extract function arguments
    //
    hSocketEngineEvent = (HANDLE)((VOID**)arglist)[0];
    pfSuccess = (BOOL*)((VOID**)arglist)[1];

    //
    // The code in StartAsynchronousSocketEngine() has not yet successfully
    // executed
    //
    *pfSuccess = FALSE;
 
    //
    // Register the "Tortilla" window class with the AsynchronousSocketEngine
    // window procedure
    //
    memset(
        &wndclass,
        0,
        sizeof(wndclass));
    wndclass.lpszClassName = L"Tortilla";
    wndclass.lpfnWndProc = AsynchronousSocketEngine;
    atomClass = RegisterClass(&wndclass);
    if (atomClass == 0)
    {
        Log(
            Red,
            L"\nError in StartAsynchronousSocketEngine(): RegisterClass()"
            L"failed (0x%08X)\n",
            GetLastError());
        SetEvent(hSocketEngineEvent);
        return 0;
    }
 
    //
    // Create the AsynchronousSocketEngine window
    //
    g_hwndAsynchronousSocketEngine = CreateWindow(
        (LPCTSTR)atomClass,
        NULL,
        0,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        NULL,
        NULL,
        NULL,
        NULL);
    if (g_hwndAsynchronousSocketEngine == NULL)
    {
        Log(
            Red,
            L"\nError in StartAsynchronousSocketEngine(): CreateWindow()"
            L"failed (0x%08X)\n",
            GetLastError());
        SetEvent(hSocketEngineEvent);
        return 0;
    }

    //
    // The AsynchronousSocketEngine window was successfully created
    //
    *pfSuccess = TRUE;
    SetEvent(hSocketEngineEvent);
 
    //
    // Run the message-pump until the Tortilla process terminates
    //
    for(;;)
    {
        GetMessage(
            &msg,
            g_hwndAsynchronousSocketEngine,
            0,
            0);
        DispatchMessage(
            &msg);
    }
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
    HANDLE hThread;
    HANDLE hTcpSynEngineEvent;
    VOID* aObjects[2];
    BOOL fSuccess;

    DWORD dwNumberOfBytesRead;
    BYTE* abBuffer;
    FULL_IP_PACKET* pIp;
    FULL_TCP_PACKET* pTcp;
    FULL_DHCP_PACKET* pDhcp;
    FULL_ARP_PACKET* pArp;
    FULL_DNS_PACKET* pDns;

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
        L"Tortilla v1.1.0 Beta\n"
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
    g_pAsynchronousSockets = NULL;
    g_hAsiMutex = CreateMutex(
        NULL,
        FALSE,
        NULL);
    if (g_hAsiMutex == NULL)
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
            L"\nError in lwIP_init(): Failed to allocate memory\n");
        goto exit;
    }
    Log(
        Cyan,
        L" done\n");

    //
    // Initialize asynchronous socket engine
    //
    Log(
        Cyan,
        L"Initializing asynchronous socket engine...");
    hTcpSynEngineEvent = CreateEvent(
        NULL,
        TRUE,
        FALSE,
        NULL);
    if (hTcpSynEngineEvent == NULL)
    {
        Log(
            Red,
            L"\nError in wmain(): CreateEvent() failed (0x%08X)\n",
            GetLastError());
        goto exit;
    }
    fSuccess = FALSE;
    aObjects[0] = hTcpSynEngineEvent;
    aObjects[1] = &fSuccess;
    hThread = (HANDLE)_beginthreadex(
        NULL,
        0,
        StartAsynchronousSocketEngine,
        aObjects,
        0,
        NULL);
    if (hThread == 0)
    {
		Log(
			Red,
			L"\nError in wmain(): _beginthreadex() failed\n");
        goto exit;
    }
    CloseHandle(hThread);
    if (WAIT_OBJECT_0 != WaitForSingleObject(
        hTcpSynEngineEvent,
        INFINITE))
    {
		Log(
			Red,
			L"\nError in wmain(): WaitForSingleObject() failed (0x%08X)\n",
            GetLastError());
        goto exit;
    }
    if (!fSuccess)
    {
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

            HandleDnsOrTcpSyn(
                FALSE,
                abBuffer,
                dwNumberOfBytesRead);

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
        // If this is a DNS query, call HandleDnsOrTcpSyn()
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
            HandleDnsOrTcpSyn(
                TRUE,
                abBuffer,
                dwNumberOfBytesRead);

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
