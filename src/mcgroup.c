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


// Socket for sending join or leave requests.
static int mcGroupSock = 0;

/**
*   Common function for joining or leaving a MCast group.
*/
static int sendJoinLeave(struct IfDesc *IfDp, int optname, uint32_t mcastaddr) {
    struct ip_mreq CtlReq;

    memset(&CtlReq, 0, sizeof(CtlReq));
    CtlReq.imr_multiaddr.s_addr = mcastaddr;
    CtlReq.imr_interface.s_addr = IfDp->InAdr.s_addr;

    my_log(LOG_NOTICE, 0, "mcgroup_send%s: %s on %s",
            optname == IP_ADD_MEMBERSHIP ? "Join" : "Leave", inetFmt( mcastaddr, s1 ), IfDp->Name);

    if (!mcGroupSock) {
        mcGroupSock = openUdpSocket(INADDR_ANY, 0);
    }

    if (setsockopt(mcGroupSock, IPPROTO_IP, optname, (void *)&CtlReq, sizeof( CtlReq )))
    {
        my_log( LOG_WARNING, errno, "MRT_%s_MEMBERSHIP failed",
                optname == IP_ADD_MEMBERSHIP ? "ADD" : "DROP" );
        return 1;
    }

    return 0;
}

/**
*   Joins the MC group with the address 'McAdr' on the interface 'IfName'.
*
*   @return 0 if the function succeeds, 1 if parameters are wrong or the join fails
*/
int mcgroup_sendJoin(struct IfDesc *IfDp, uint32_t mcastaddr) {
    return sendJoinLeave(IfDp, IP_ADD_MEMBERSHIP, mcastaddr);
}

/**
*   Leaves the MC group with the address 'McAdr' on the interface 'IfName'.
*
*   @return 0 if the function succeeds, 1 if parameters are wrong or the join fails
*/
int mcgroup_sendLeave(struct IfDesc *IfDp, uint32_t mcastaddr) {
    return sendJoinLeave(IfDp, IP_DROP_MEMBERSHIP, mcastaddr);
}
