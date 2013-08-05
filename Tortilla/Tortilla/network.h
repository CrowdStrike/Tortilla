/*!
    @file       network.h
    @author     Jason Geffner (jason@crowdstrike.com)
    @brief      Tortilla Client v1.0.1 Beta
   
    @details    This product is produced independently from the Tor(r)
                anonymity software and carries no guarantee from The Tor
                Project about quality, suitability or anything else.

                See LICENSE.txt file in top level directory for details.

    @copyright  CrowdStrike, Inc. Copyright (c) 2013.  All rights reserved. 
*/

#include <WinDNS.h>
#include "lwIP/udp.h"
#include "lwIP/dhcp.h"
#include "lwIP/tcp_impl.h"

#pragma pack(push)
#pragma pack(1)

typedef struct _FULL_IP_PACKET
{
    eth_hdr EthernetHeader;
    ip_hdr IpHeader;
} FULL_IP_PACKET;

typedef struct _FULL_DHCP_PACKET
{
    eth_hdr EthernetHeader;
    ip_hdr IpHeader;
    udp_hdr UdpHeader;
    dhcp_msg DhcpHeader;
} FULL_DHCP_PACKET;

typedef struct _DHCP_REPLY_OPTIONS
{
    struct
    {
        unsigned char ucOption;
        unsigned char cbValue;
        unsigned char aucValue[1];
    } MESSAGE_TYPE;

    struct
    {
        unsigned char ucOption;
        unsigned char cbValue;
        unsigned char aucValue[4];
    } SUBNET_MASK;

    struct
    {
        unsigned char ucOption;
        unsigned char cbValue;
        unsigned char aucValue[4];
    } ROUTERS;

    struct
    {
        unsigned char ucOption;
        unsigned char cbValue;
        unsigned char aucValue[4];
    } LEASE_TIME;

    struct
    {
        unsigned char ucOption;
        unsigned char cbValue;
        unsigned char aucValue[4];
    } SERVER_IDENTIFIER;

    struct
    {
        unsigned char ucOption;
        unsigned char cbValue;
        unsigned char aucValue[4];
    } DOMAIN_NAME_SERVERS;

    unsigned char ucEnd;

} DHCP_REPLY_OPTIONS;

typedef struct _FULL_DHCP_PACKET_REPLY
{
    FULL_DHCP_PACKET fullDhcpPacket;
    DHCP_REPLY_OPTIONS dhcpReplyOptions;
} FULL_DHCP_PACKET_REPLY;

typedef struct _FULL_ARP_PACKET
{
    eth_hdr EthernetHeader;
    etharp_hdr ArpHeader;
} FULL_ARP_PACKET;

typedef struct _FULL_DNS_PACKET
{
    eth_hdr EthernetHeader;
    ip_hdr IpHeader;
    udp_hdr UdpHeader;
    DNS_HEADER DnsHeader;
} FULL_DNS_PACKET;

typedef struct _DNS_ANSWER_RECORD
{
    unsigned short CompressedName;
    DNS_WIRE_RECORD DnsWireRecord;
    // char Rdata[];
} DNS_ANSWER_RECORD;

typedef struct _FULL_TCP_PACKET
{
    eth_hdr EthernetHeader;
    ip_hdr IpHeader;
    tcp_hdr TcpHeader;
} FULL_TCP_PACKET;

#pragma pack(pop)

// From https://gitweb.torproject.org/tor.git/blob_plain/HEAD:/src/or/or.h
#define SOCKS_COMMAND_CONNECT       0x01
#define SOCKS_COMMAND_RESOLVE       0xF0
#define SOCKS_COMMAND_RESOLVE_PTR   0xF1

// From http://wiki.wireshark.org/Development/LibpcapFileFormat
typedef struct pcap_hdr_s {
    UINT32 magic_number;   /* magic number */
    UINT16 version_major;  /* major version number */
    UINT16 version_minor;  /* minor version number */
    INT32  thiszone;       /* GMT to local correction */
    UINT32 sigfigs;        /* accuracy of timestamps */
    UINT32 snaplen;        /* max length of captured packets, in octets */
    UINT32 network;        /* data link type */
} pcap_hdr_t;
typedef struct pcaprec_hdr_s {
    UINT32 ts_sec;         /* timestamp seconds */
    UINT32 ts_usec;        /* timestamp microseconds */
    UINT32 incl_len;       /* number of octets of packet saved in file */
    UINT32 orig_len;       /* actual length of packet */
} pcaprec_hdr_t;
