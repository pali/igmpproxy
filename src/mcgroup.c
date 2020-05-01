/*
**  igmpproxy - IGMP proxy based multicast router
**  Copyright (C) 2005 Johnny Egeland <johnny@rlo.org>
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
**  - Licensed under the GNU General Public License, either version 2 or
**    any later version.
**
**  mrouted 3.9-beta3 - Copyright (C) 2002 by The Board of Trustees of
**  Leland Stanford Junior University.
**  - Licensed under the 3-clause BSD license, see Stanford.txt file.
**
*/
/**
*   mcgroup contains functions for joining and leaving multicast groups.
*
*/

#include "igmpproxy.h"


/**
*   Common function for joining or leaving a MCast group.
*/
int joinleave( int Cmd, int UdpSock, struct IfDesc *IfDp, uint32_t mcastaddr, uint32_t originAddr ) {
    const char *CmdSt = Cmd == 'j' ? "join" : "leave";

    {
        my_log( LOG_NOTICE, 0, "%sMcGroup: %s on %s from %s", CmdSt,
            inetFmt( mcastaddr, s1 ), IfDp ? IfDp->Name : "<any>", originAddr != 0 ?  inetFmt( originAddr, s2 ) : "<any>" );
    }

    int ret;

    if(originAddr == 0) {
        struct ip_mreq CtlReq;
        memset(&CtlReq, 0, sizeof(CtlReq));
        CtlReq.imr_multiaddr.s_addr = mcastaddr;
        CtlReq.imr_interface.s_addr = IfDp->InAdr.s_addr;

        ret = setsockopt( UdpSock, IPPROTO_IP,
          Cmd == 'j' ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP,
          (void *)&CtlReq, sizeof( CtlReq ) );
    }
    else {
        struct ip_mreq_source CtlReq;
        memset(&CtlReq, 0, sizeof(CtlReq));
        CtlReq.imr_multiaddr.s_addr = mcastaddr;
        CtlReq.imr_interface.s_addr = IfDp->InAdr.s_addr;
        CtlReq.imr_sourceaddr.s_addr = originAddr;

        ret = setsockopt( UdpSock, IPPROTO_IP,
          Cmd == 'j' ? IP_ADD_SOURCE_MEMBERSHIP : IP_DROP_SOURCE_MEMBERSHIP,
          (void *)&CtlReq, sizeof( CtlReq ) );
    }
    
    if( ret )
    {
        int mcastGroupExceeded = (Cmd == 'j' && errno == ENOBUFS);
        my_log( LOG_WARNING, errno, "MRT_%s_MEMBERSHIP failed", Cmd == 'j' ? "ADD" : "DROP" );
        if (mcastGroupExceeded) {
            my_log(LOG_WARNING, 0, "Maximum number of multicast groups were exceeded");
#ifdef __linux__
            my_log(LOG_WARNING, 0, "Check settings of '/sbin/sysctl net.ipv4.igmp_max_memberships'");
#endif
        }
        return 1;
    }

    return 0;
}

/**
*   Joins the MC group with the address 'McAdr' on the interface 'IfName'.
*   The join is bound to the UDP socket 'UdpSock', so if this socket is
*   closed the membership is dropped.
*
*   @return 0 if the function succeeds, 1 if parameters are wrong or the join fails
*/
int joinMcGroup( int UdpSock, struct IfDesc *IfDp, uint32_t mcastaddr, uint32_t originAddr ) {
    return joinleave( 'j', UdpSock, IfDp, mcastaddr, originAddr );
}

/**
*   Leaves the MC group with the address 'McAdr' on the interface 'IfName'.
*
*   @return 0 if the function succeeds, 1 if parameters are wrong or the join fails
*/
int leaveMcGroup( int UdpSock, struct IfDesc *IfDp, uint32_t mcastaddr, uint32_t originAddr ) {
    return joinleave( 'l', UdpSock, IfDp, mcastaddr, originAddr );
}
