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
*/

#include "igmpproxy.h"


/**
*   Returns plain text representation of the sa_family flag of the given 
*   struct ifreq (or "AF_UNKOWN" if not yet mapped).
*/
const char* get_sa_family_str( const sa_family_t sa_family ) {
    switch( sa_family ) {
    case AF_INET:
        return "AF_INET";
    case AF_INET6:
        return "AF_INET6";
    default:
        return "AF_UNKNOWN";
    }
}

struct sockaddr_in* sockaddr2sockaddr_in(const struct sockaddr* sockaddrPt) {
    struct sockaddr_in *sockaddr_inPt = ((struct sockaddr_in *) sockaddrPt);

    return sockaddr_inPt;
}

struct in_addr sockaddr2in_addr(const struct sockaddr* sockaddrPt) {
    struct sockaddr_in *sockaddr_inPt = sockaddr2sockaddr_in(sockaddrPt);

    return sockaddr_inPt->sin_addr;
}
