/*
**  igmpproxy - IGMP proxy based multicast router 
**  
**  Copyright (C) 2005 Johnny Egeland <johnny@rlo.org>
**  Copyright (C) 2016 Victor Toni <victor.toni@gmail.com>
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation; either version 2 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
**
**----------------------------------------------------------------------------
**
**  This software is derived work from the following software. The original
**  source code has been modified from it's original state by the author
**  of igmpproxy.
**
**  smcroute 0.92 - Copyright (C) 2001 Carsten Schill <carsten@cschill.de>
**  - Licensed under the GNU General Public License, version 2
**  
**  mrouted 3.9-beta3 - COPYRIGHT 1989 by The Board of Trustees of 
**  Leland Stanford Junior University.
**  - Original license can be found in the Stanford.txt file.
**
*/

/**
*   igmplog.c - Log details about IGMP requests and reports
*/

#include "igmpproxy.h"

#include "igmpv3.h"

/**
*   Finds the textual name of the supplied IGMP request.
*/
const char *igmp_packet_kind( unsigned int type, unsigned int code ) {
    static char unknown[20];

    switch (type) {
    case IGMP_MEMBERSHIP_QUERY:     return  "Membership query  ";
    case IGMP_V1_MEMBERSHIP_REPORT: return  "V1 member report  ";
    case IGMP_V2_MEMBERSHIP_REPORT: return  "V2 member report  ";
    case IGMP_V3_MEMBERSHIP_REPORT: return  "V3 member report  ";
    case IGMP_V2_LEAVE_GROUP:       return  "Leave message     ";
    
    default:
        sprintf(unknown, "unk: 0x%02x/0x%02x    ", type, code);
        return unknown;
    }
}

/**
*   Finds the textual name of the supplied IGMP report.
*/
const char *igmp_report_kind( unsigned int type ) {
    static char unknown[20];

    switch (type) {
    case IGMPV3_MODE_IS_INCLUDE:    return  "Mode Include      ";
    case IGMPV3_CHANGE_TO_INCLUDE:  return  "Change to include ";
    case IGMPV3_MODE_IS_EXCLUDE:    return  "Mode Exclude      ";
    case IGMPV3_CHANGE_TO_EXCLUDE:  return  "Change to Exclude ";
    case IGMPV3_ALLOW_NEW_SOURCES:  return  "Allow New Sources ";
    case IGMPV3_BLOCK_OLD_SOURCES:  return  "Block Old Sources ";

    default:
        sprintf(unknown, "unk: 0x%02x ", type);
        return unknown;
    }
}

/**
*   Finds the textual name of the supplied IP protocol type.
*/
const char *ip_protocol_kind( u_char ip_p ) {
    static char unknown[20];

    /*
    * Protocols according to RFC 1700
    */
    switch (ip_p) {
    case IPPROTO_HOPOPTS:   return "IP6 hop-by-hop options";
    case IPPROTO_IGMP:      return "IGMP";
/*
    case IPPROTO_GGP:       return "GGP";
*/
    case IPPROTO_IPIP:      return "IPv4 encapsulation";
/*
    case IPPROTO_ST:        return "Stream protocol II";
*/
    case IPPROTO_EGP:       return "Exterior gateway protocol";
/*
    case IPPROTO_PIGP:      return "Private interior gateway";
    case IPPROTO_RCCMON:    return "BBN RCC Monitoring";
    case IPPROTO_NVPII:     return "Network voice protocol";
    case IPPROTO_PUP:       return "PUP";
    case IPPROTO_ARGUS:     return "Argus";
    case IPPROTO_EMCON:     return "EMCON";
    case IPPROTO_XNET:      return "Cross Net Debugger";
    case IPPROTO_CHAOS:     return "Chaos";
    case IPPROTO_MUX:       return "Multiplexing";
    case IPPROTO_MEAS:      return "DCN Measurement Subsystems";
    case IPPROTO_HMP:       return "Host Monitoring";
    case IPPROTO_PRM:       return "Packet Radio Measurement";
*/
    case IPPROTO_IDP:       return "xns idp";
/*
    case IPPROTO_TRUNK1:    return "Trunk-1";
    case IPPROTO_TRUNK2:    return "Trunk-2";
    case IPPROTO_LEAF1:     return "Leaf-1";
    case IPPROTO_LEAF2:     return "Leaf-2";
    case IPPROTO_RDP:       return "Reliable Data";
    case IPPROTO_IRTP:      return "Reliable Transaction";
    case IPPROTO_TP:        return "tp-4 w/ class negotiation";
    case IPPROTO_BLT:       return "Bulk Data Transfer";
    case IPPROTO_NSP:       return "Network Services";
    case IPPROTO_INP:       return "Merit Internodal";
    case IPPROTO_SEP:       return "Sequential Exchange";
    case IPPROTO_3PC:       return "Third Party Connect";
    case IPPROTO_IDPR:      return "InterDomain Policy Routing";
    case IPPROTO_XTP:       return "XTP";
    case IPPROTO_DDP:       return "Datagram Delivery";
    case IPPROTO_CMTP:      return "Control Message Transport";
    case IPPROTO_TPXX:      return "TP++ Transport";
    case IPPROTO_IL:        return "IL transport protocol";
    case IPPROTO_SDRP:      return "Source Demand Routing";
*/
    case IPPROTO_ROUTING:   return "IP6 routing header";
    case IPPROTO_FRAGMENT:  return "IP6 fragmentation header";
/*
    case IPPROTO_IDRP:      return "InterDomain Routing";
*/
    case IPPROTO_RSVP:      return "Resource Reservation";

    case IPPROTO_GRE:       return "General Routing Encap.";
/*
    case IPPROTO_MHRP:      return "Mobile Host Routing";
    case IPPROTO_BHA:       return "BHA";
*/
    case IPPROTO_ESP:       return "IP6 Encap Sec. Payload";
    case IPPROTO_AH:        return "IP6 Auth Header";
/*
    case IPPROTO_INLSP:     return "Integ. Net Layer Security";
    case IPPROTO_SWIPE:     return "IP with encryption";
    case IPPROTO_NHRP:      return "Next Hop Resolution";
    case IPPROTO_MOBILE:    return "IP Mobility";
    case IPPROTO_TLSP:      return "Transport Layer Security";
    case IPPROTO_SKIP:      return "SKIP";
*/
    case IPPROTO_ICMPV6:    return "ICMP6";
    case IPPROTO_NONE:      return "IP6 no next header";

    case IPPROTO_DSTOPTS:   return "IP6 destination option";
/*
    case IPPROTO_AHIP:      return "any host internal protocol";
    case IPPROTO_CFTP:      return "CFTP";
    case IPPROTO_HELLO:     return "\"Hello\" routing protocol";
    case IPPROTO_SATEXPAK:  return "SATNET/Backroom EXPAK";
    case IPPROTO_KRYPTOLAN: return "Kryptolan";
    case IPPROTO_RVD:       return "Remote Virtual Disk";
    case IPPROTO_IPPC:      return "Pluribus Packet Core";
    case IPPROTO_ADFS:      return "Any distributed FS";
    case IPPROTO_SATMON:    return "Satnet Monitoring";
    case IPPROTO_VISA:      return "VISA Protocol";
    case IPPROTO_IPCV:      return "Packet Core Utility";
    case IPPROTO_CPNX:      return "Comp. Prot. Net. Executive";
    case IPPROTO_CPHB:      return "Comp. Prot. HeartBeat";
    case IPPROTO_WSN:       return "Wang Span Network";
    case IPPROTO_PVP:       return "Packet Video Protocol";
    case IPPROTO_BRSATMON:  return "BackRoom SATNET Monitoring";
    case IPPROTO_ND:        return "Sun net disk proto (temp.)";
    case IPPROTO_WBMON:     return "WIDEBAND Monitoring";
    case IPPROTO_WBEXPAK:   return "WIDEBAND EXPAK";
    case IPPROTO_EON:       return "ISO cnlp";
    case IPPROTO_VMTP:      return "VMTP";
    case IPPROTO_SVMTP:     return "Secure VMTP";
    case IPPROTO_VINES:     return "Banyon VINES";
    case IPPROTO_TTP:       return "TTP";
    case IPPROTO_IGP:       return "NSFNET-IGP";
    case IPPROTO_DGP:       return "Dissimilar gateway prot.";
    case IPPROTO_TCF:       return "TCF";
    case IPPROTO_IGRP:      return "Cisco/GXS IGRP";
    case IPPROTO_OSPFIGP:   return "OSPFIGP";
    case IPPROTO_SRPC:      return "Strite RPC protocol";
    case IPPROTO_LARP:      return "Locus Address Resoloution";
*/
    case IPPROTO_MTP:       return "Multicast Transport";
/*  
    case IPPROTO_AX25:      return "AX.25 Frames";
    case IPPROTO_IPEIP:     return "IP encapsulated in IP";
    case IPPROTO_MICP:      return "Mobile Int.ing control";
    case IPPROTO_SCCSP:     return "Semaphore Comm. security";
    case IPPROTO_ETHERIP:   return "Ethernet IP encapsulation";
    case IPPROTO_ENCAP:     return "Encapsulation header";
    case IPPROTO_APES:      return "Any Private Encr. scheme";
    case IPPROTO_GMTP:      return "GMTP";
    case IPPROTO_IPCOMP:    return "IPComp(payload compression)";
    case IPPROTO_SCTP:      return "SCTP";
    case IPPROTO_MH:        return "IPv6 Mobility Header";
*/
    case IPPROTO_UDPLITE:   return "UDP-Lite";
/*
    case IPPROTO_HIP:       return "IP6 Host Identity Protocol";
    case IPPROTO_SHIM6:     return "IP6 Shim6 Protocol";
*/    
    // 101-254: Partly Unassigned
    case IPPROTO_PIM:       return "Protocol Independent Mcast";
/*
    case IPPROTO_CARP:      return "CARP";
    case IPPROTO_PGM:       return "PGM";
    case IPPROTO_MPLS:      return "MPLS-in-IP";
    case IPPROTO_PFSYNC:    return "PFSYNC";
*/    
    default:
        sprintf(unknown, "unk: 0x%02x", ip_p);
        return unknown;
    }
}

/**
 * Log received IGMP packet that is sitting in the input
 * packet buffer.
 */
void log_received_IGMP( int recvlen ) {
    if ( LogLevel < LOG_TRACE ) {
        // we really want to log the reports only in DEBUG mode
        return;
    }

    if (recvlen < sizeof(struct ip)) {
        my_log(LOG_TRACE, 0,
            "IGMP: received packet too short (%u bytes) for IP header (needed: %u)",
            recvlen,
            sizeof(struct ip)
        );
        return;
    }

    register uint32_t src;
    struct ip *ip;
    struct igmp *igmp;
    int ipdatalen, iphdrlen;

    ip        = (struct ip *)recv_buf;
    src       = ip->ip_src.s_addr;

    iphdrlen  = ip->ip_hl << 2;
    ipdatalen = ip_data_len(ip);

    if ( iphdrlen + ipdatalen != recvlen )
    {
        log_IP ( ip );
        my_log(LOG_TRACE, 0, "IGMP: received packet");
        my_log(LOG_TRACE, 0, "    - received packet from %s shorter (%u bytes) than hdr+data length (%u+%u)",
            inetFmt(src, s1), recvlen, iphdrlen, ipdatalen
        );
        return;
    }

    igmp = (struct igmp *)(recv_buf + iphdrlen);

    log_IGMP( ip, igmp );
}

/**
 * Log received IGMP packet and the associated IP header
 */
void log_IGMP( struct ip *ip, struct igmp *igmp ) {
    if ( LogLevel < LOG_TRACE ) {
        // we really want to log the reports only in DEBUG mode
        return;
    }

    register uint32_t src, group;
    struct igmpv3_report *igmpv3;
    int ipdatalen, iphdrlen;

    src       = ip->ip_src.s_addr;

    iphdrlen  = ip->ip_hl << 2;
    ipdatalen = ip_data_len(ip);

    if ( ipdatalen < IGMP_MINLEN )
    {
        log_IP ( ip );
        my_log(LOG_TRACE, 0, "IGMP:");
        my_log(LOG_TRACE, 0, "   - received IP data field too short (%u bytes) for IGMP, from %s",
            ipdatalen, inetFmt(src, s1)
        );
        return;
    }

    group = igmp->igmp_group.s_addr;

    log_IP( ip ); 

    my_log(LOG_TRACE, 0, "IGMP: %s", igmp_packet_kind(igmp->igmp_type, igmp->igmp_code) );
    my_log(LOG_TRACE, 0, "    Type: %x", igmp->igmp_type );
    my_log(LOG_TRACE, 0, "    Code: %x", igmp->igmp_code );
    my_log(LOG_TRACE, 0, "    Checksum: 0x%02x", igmp->igmp_cksum );
    if(!group) {
        my_log(LOG_TRACE, 0, "    Group: %s", inetFmt( group, s1 ) );
    } else {
        my_log(LOG_TRACE, 0, "    Group: No group" );
    }

    switch (igmp->igmp_type) {
    case IGMP_V1_MEMBERSHIP_REPORT:
    case IGMP_V2_MEMBERSHIP_REPORT:
        return;

    case IGMP_V3_MEMBERSHIP_REPORT:
        log_IGMPv3_report( ip, igmp );
        return;

    case IGMP_V2_LEAVE_GROUP:
        return;

    case IGMP_MEMBERSHIP_QUERY:
        return;

    default:
        my_log(LOG_TRACE, 0,
            "    - unknown IGMP message type 0x%02x",
            igmp->igmp_type
        );
        return;
    }
}

/**
 * Log received IGMPv3 report packet
 */
void log_IGMPv3_report( struct ip *ip, struct igmp *igmp ) {
    if ( LogLevel < LOG_TRACE ) {
        // we really want to log the reports only in DEBUG mode
        return;
    }

    register uint32_t src;
    uint16_t ipdatalen;
        
    ipdatalen = ip_data_len( ip );
    if ( ipdatalen <= IGMPV3_MINLEN ) {
        my_log(LOG_TRACE, 0, "IGMPv3: %s", igmp_packet_kind(igmp->igmp_type, igmp->igmp_code) );
        my_log(LOG_TRACE, 0, "   - received IP data field too short (%u bytes) for IGMPv3, from %s",
            ipdatalen, inetFmt(src, s1)
        );
    }

    register uint32_t gsrc, group;

    struct igmpv3_report *igmpv3;
    struct igmpv3_grec *grec;
    struct in_addr *grec_src;
    uint16_t ngrec, nsrcs;

    igmpv3 = (struct igmpv3_report *)(igmp);
    ngrec = ntohs(igmpv3->igmp_ngrec);

    my_log(LOG_TRACE, 0, "Num Group Records: %d", ngrec);
    
    grec = &igmpv3->igmp_grec[0];
    for (uint16_t i=0; i< ngrec; i++) {
        if ((uint8_t *)igmpv3 + ipdatalen < (uint8_t *)grec + sizeof(*grec)) {
            break;
        }

        group = grec->grec_mca.s_addr;
        my_log(LOG_TRACE, 0, "Group Record : %s %s", 
                inetFmt(group, s3),
                igmp_report_kind(grec->grec_type)
        );

        my_log(LOG_TRACE, 0, "    Multicast Address: %s", 
                inetFmt(group, s3)
        );

        nsrcs = ntohs(grec->grec_nsrcs);
        my_log(LOG_TRACE, 0, "    Num Src : %d", 
                nsrcs
        );

        grec_src = &grec->grec_src[0];
        for (uint16_t j=0; j< nsrcs; j++) {
            if ((uint8_t *)igmpv3 + ipdatalen < (uint8_t *)grec_src + sizeof(*grec_src)) {
                break;
            }
            gsrc = grec_src->s_addr;
            my_log(LOG_TRACE, 0, "    Source Address: %s",
                    inetFmt(gsrc, s3)
            );

            grec_src++;
        }

        grec = (struct igmpv3_grec *)
            (&grec->grec_src[nsrcs] + grec->grec_auxwords * 4);
    }
}

/**
 * Log received IP header
 */
void log_IP ( struct ip *ip ) {
    if ( LogLevel < LOG_TRACE ) {
        // we really want to log the reports only in DEBUG mode
        return;
    }

    register uint32_t src, dst;
    int ipdatalen, iphdrlen;

    src       = ip->ip_src.s_addr;
    dst       = ip->ip_dst.s_addr;

    iphdrlen  = ip->ip_hl << 2;
    ipdatalen = ip_data_len(ip);

    my_log(LOG_TRACE, 0, "Internet Protocol,  Src Addr: %s, Dst Addr: %s",
            inetFmt( src, s1 ),
            inetFmt( dst, s2 )
    );
    my_log(LOG_TRACE, 0, "    Version: %u", ip->ip_v );
    my_log(LOG_TRACE, 0, "    Header length: %u", iphdrlen );
    my_log(LOG_TRACE, 0, "    Total Length: %u", ip->ip_len );
    my_log(LOG_TRACE, 0, "    Identification: 0x%04x (%u)", ip->ip_id, ip->ip_id );
    my_log(LOG_TRACE, 0, "    Fragment offset: %u", ip->ip_off );
    my_log(LOG_TRACE, 0, "    Time to live: %u", ip->ip_ttl );
    my_log(LOG_TRACE, 0, "    Protocol: %s (0x%02x)", ip_protocol_kind( ip->ip_p ), ip->ip_p );

    my_log(LOG_TRACE, 0, "    Header Checksum: 0x%04x", ip->ip_sum );

/*    
    // FIXME: for some reason the local calculation of the checksum does not work...

    // make local copy to zero the checksum for local calculation
    struct ip ipCopy = *ip;
    ipCopy.ip_sum = 0;

    uint16_t ip_sum = inetChksum( (void *) &ipCopy, iphdrlen );
    my_log(LOG_TRACE, 0, "    Header Checksum: 0x%02x (inetChksum)", ip_sum );

    ip_sum = ip_checksum( ip );
    my_log(LOG_TRACE, 0, "    Header Checksum: 0x%02x (ip_checksum)", ip_sum );

    if (ip_sum == ip->ip_sum ) {
        my_log(LOG_TRACE, 0, "    Header Checksum: 0x%02x (correct)", ip->ip_sum );
    } else {
        my_log(LOG_TRACE, 0, "    Header Checksum: 0x%02x (false, should be: 0x%02x)", ip->ip_sum, ip_sum );
    }
*/
}
