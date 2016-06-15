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
**  - Licensed under the GNU General Public License, version 2
**  
**  mrouted 3.9-beta3 - COPYRIGHT 1989 by The Board of Trustees of 
**  Leland Stanford Junior University.
**  - Original license can be found in the Stanford.txt file.
**
*/
/**
*   mroute-api.c
*
*   This module contains the interface routines to the Linux mrouted API
*/


#include "igmpproxy.h"

// MAX_MC_VIFS from mclab.h must have same value as MAXVIFS from mroute.h
#if MAX_MC_VIFS != MAXVIFS
# error "constants don't match, correct mclab.h"
#endif
     
// need an IGMP socket as interface for the mrouted API
// - receives the IGMP messages
int         MRouterFD;          /* socket for all network I/O  */
char        *recv_buf;          /* input packet buffer         */
char        *send_buf;          /* output packet buffer        */


// my internal virtual interfaces descriptor vector  
static struct VifDesc {
    struct IfDesc *IfDp;
} VifDescVc[ MAXVIFS ];


struct VifDesc *get_free_vif();


/*
** Initialises the mrouted API and locks it by this exclusively.
**     
** returns: - 0 if the functions succeeds     
**          - the errno value for non-fatal failure condition
*/
int enableMRouter(void) {
    int Va = 1, socket_type;

    socket_type = SOCK_RAW;

#ifdef SOCK_CLOEXEC
    // use only if available
    socket_type |= SOCK_CLOEXEC;
#endif

    if ( (MRouterFD  = socket(AF_INET, socket_type, IPPROTO_IGMP)) < 0 ) {
        my_log( LOG_ERR, errno, "IGMP socket open" );
    } else {
        my_log( LOG_DEBUG, 0, "IGMP socket opened" );
    }

    if ( setsockopt( MRouterFD, IPPROTO_IP, MRT_INIT, 
                     (void *)&Va, sizeof( Va ) ) ) {
        return errno;
    } else {
        my_log( LOG_DEBUG, 0, "MRT_INIT successful" );
    }

    return 0;
}

/*
** Diables the mrouted API and relases by this the lock.
**          
*/
void disableMRouter(void) {
    if ( setsockopt( MRouterFD, IPPROTO_IP, MRT_DONE, NULL, 0 ) 
         || close( MRouterFD )
       ) {
        MRouterFD = 0;
        my_log( LOG_ERR, errno, "MRT_DONE/close" );
    }

    MRouterFD = 0;
}

/*
 * aimwang: delVIF()
 */
void delVIF( struct IfDesc *IfDp ) {
    struct vifctl VifCtl;
    struct VifDesc *VifDp;

    if (-1 == IfDp->vifindex) {
        my_log( LOG_DEBUG, 0, "delVIF: No VIF to remove, Ix %d, %s (IP: %s)", 
            IfDp->vifindex, IfDp->Name, inetFmt(IfDp->InAdr.s_addr, s1) );
        return;
    }
    
    VifDp = VifDescVc + IfDp->vifindex;
    
    /*
    **  invalid pointer
    */
    if ( VifDp >= VCEP( VifDescVc ) ) {
        my_log( LOG_ERR, EFAULT, "delVIF: Not a valid address for VIF: %d", IfDp->vifindex );
    }
    
    VifCtl.vifc_vifi = IfDp->vifindex;

    my_log( LOG_DEBUG, 0, "delVIF: Removing VIF (MRT_DEL_VIF), Ix %d Fl 0x%x IP 0x%08x %s, Threshold: %d, Ratelimit: %d", 
         IfDp->vifindex, IfDp->Flags, IfDp->InAdr.s_addr, IfDp->Name, IfDp->threshold, IfDp->ratelimit);

    if ( setsockopt( MRouterFD, IPPROTO_IP, MRT_DEL_VIF,
                     (char *)&VifCtl, sizeof( VifCtl ) ) ) {
        my_log( LOG_WARNING, errno, "delVIF: MRT_DEL_VIF failed" );
    } else {
        // update data for success
        IfDp->vifindex = -1;
        VifDp->IfDp = NULL;
    }
}



/*
** Adds the interface '*IfDp' as virtual interface to the mrouted API
** 
*/
void addVIF( struct IfDesc *IfDp ) {
    struct vifctl VifCtl;
    struct VifDesc *VifDp;

    int vifindex;

    /* search existing VifDesc
     */
    VifDp = get_vif_by_if( IfDp );
    if ( NULL == VifDp ) {
        /* search free or existing VifDesc
         */
        VifDp = get_free_vif();
    } else {
        my_log( LOG_WARNING, 0, "addVIF: VIF #%d is already in use by IF %s (IP: %s)", 
                VifDp - VifDescVc, 
                IfDp->Name, 
                inetFmt(IfDp->InAdr.s_addr, s1)
        );
    }

    /* no more space
     */
    if ( NULL == VifDp ) {
        my_log( LOG_DEBUG, 0, "addVIF: No more VIFs! Could not add VIF, Ix %d, %s (IP: %s)", 
            IfDp->vifindex, IfDp->Name, inetFmt(IfDp->InAdr.s_addr, s1) );
        my_log( LOG_ERR, ENOMEM, "addVIF: out of VIF space" );
    }

    vifindex = VifDp - VifDescVc;
    
    VifCtl.vifc_vifi        = vifindex; 
    VifCtl.vifc_flags       = 0;                        // no tunnel, no source routing, register ?
    VifCtl.vifc_threshold   = IfDp->threshold;   // Packet TTL must be at least 1 to pass them
    VifCtl.vifc_rate_limit  = IfDp->ratelimit;   // Ratelimit

    VifCtl.vifc_lcl_addr.s_addr = IfDp->InAdr.s_addr;
    VifCtl.vifc_rmt_addr.s_addr = INADDR_ANY;

    my_log( LOG_DEBUG, 0, "Adding VIF (MRT_ADD_VIF), Ix %d Fl 0x%x IP %15s %s, Threshold: %d, Ratelimit: %d", 
         VifCtl.vifc_vifi, VifCtl.vifc_flags,  inetFmt(VifCtl.vifc_lcl_addr.s_addr, s1), IfDp->Name,
         VifCtl.vifc_threshold, VifCtl.vifc_rate_limit);

    struct SubnetList *currSubnet;
    for(currSubnet = IfDp->allowednets; currSubnet; currSubnet = currSubnet->next) {
        my_log(LOG_DEBUG, 0, "        Network for [%s] : %s",
            IfDp->Name,
            inetFmts(currSubnet->subnet_addr, currSubnet->subnet_mask, s1)
        );
    }

    if ( setsockopt( MRouterFD, IPPROTO_IP, MRT_ADD_VIF, 
                     (char *)&VifCtl, sizeof( VifCtl ) ) ) {
        my_log( LOG_ERR, errno, "MRT_ADD_VIF: [%s]·:·%s",
            IfDp->Name,
            inetFmt(currSubnet->subnet_addr, s1)
        );
    }
    
    // Set the index...
    IfDp->vifindex = vifindex;

    // assgin IF to VIF
    VifDp->IfDp = IfDp;
}

/*
** Adds the multicast routed '*Dp' to the kernel routes
**
** returns: - 0 if the function succeeds
**          - the errno value for non-fatal failure condition
*/
int addMRoute( struct MRouteDesc *Dp ) {
    struct mfcctl CtlReq;
    int rc;

    CtlReq.mfcc_origin    = Dp->OriginAdr;
    CtlReq.mfcc_mcastgrp  = Dp->McAdr;
    CtlReq.mfcc_parent    = Dp->InVif;

    /* copy the TTL vector
     */

    memcpy( CtlReq.mfcc_ttls, Dp->TtlVc, sizeof( CtlReq.mfcc_ttls ) );

    {
        char FmtBuO[ 32 ], FmtBuM[ 32 ];

        my_log( LOG_DEBUG, 0, "Adding MFC (MRT_ADD_MFC): %s -> %s, InpVIf: %d", 
             fmtInAdr( FmtBuO, CtlReq.mfcc_origin ), 
             fmtInAdr( FmtBuM, CtlReq.mfcc_mcastgrp ),
             (int)CtlReq.mfcc_parent
           );
    }

    rc = setsockopt( MRouterFD, IPPROTO_IP, MRT_ADD_MFC,
            (void *)&CtlReq, sizeof( CtlReq ) );
    if (rc) {
        my_log( LOG_WARNING, errno, "MRT_ADD_MFC" );
    }

    return rc;
}

/*
** Removes the multicast routed '*Dp' from the kernel routes
**
** returns: - 0 if the function succeeds
**          - the errno value for non-fatal failure condition
*/
int delMRoute( struct MRouteDesc *Dp )
{
    struct mfcctl CtlReq;
    int rc;

    CtlReq.mfcc_origin    = Dp->OriginAdr;
    CtlReq.mfcc_mcastgrp  = Dp->McAdr;
    CtlReq.mfcc_parent    = Dp->InVif;

    /* clear the TTL vector
     */
    memset( CtlReq.mfcc_ttls, 0, sizeof( CtlReq.mfcc_ttls ) );

    {
        char FmtBuO[ 32 ], FmtBuM[ 32 ];

        my_log( LOG_DEBUG, 0, "Removing MFC (MRT_DEL_MFC): %s -> %s, InpVIf: %d", 
             fmtInAdr( FmtBuO, CtlReq.mfcc_origin ), 
             fmtInAdr( FmtBuM, CtlReq.mfcc_mcastgrp ),
             (int)CtlReq.mfcc_parent
           );
    }

    rc = setsockopt( MRouterFD, IPPROTO_IP, MRT_DEL_MFC,
            (void *)&CtlReq, sizeof( CtlReq ) );
    if (rc) {
        my_log( LOG_WARNING, errno, "MRT_DEL_MFC" );
    }

    return rc;
}

/*
** Returns for the virtual interface index for '*IfDp'
**
** returns: - the vitrual interface index if the interface is registered
**          - -1 if no virtual interface exists for the interface 
**          
*/
struct VifDesc *get_vif_by_if( const struct IfDesc *IfDp ) {
    struct VifDesc *Dp;

    for ( Dp = VifDescVc; Dp < VCEP( VifDescVc ); Dp++ ) {
        if ( Dp->IfDp == IfDp ) {
            return Dp;
        }
    }

    return NULL;
}

/*
** Returns the first virtual interface for '*IfDp'
**
** returns: - the free vitrual interface
**          - NULL if no free virtual interface exists
*/
struct VifDesc *get_free_vif()
{
    struct VifDesc *Dp;

    for ( Dp = VifDescVc; Dp < VCEP( VifDescVc ); Dp++ ) {
        if ( NULL == Dp->IfDp) {
            return Dp;
        }
    }

    return NULL;
}


