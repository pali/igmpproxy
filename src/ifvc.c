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

#include "igmpproxy.h"

struct IfDesc IfDescVc[ MAX_IF ], *IfDescEp = IfDescVc;


/** Set all downstream IF as IF_STATE_LOST to abe able to check
 *  if IF still exists or is gone.
 */
void looseDownstreamIfs( void ) {
    struct IfDesc *Dp;

    // aimwang: set all downstream IF as lost, for check IF exist or gone.
    for ( Dp = IfDescVc; Dp < IfDescEp; Dp++ ) {
        if ( Dp->state == IF_STATE_DOWNSTREAM ) {
            Dp->state = IF_STATE_LOST;
        }
    }
}

/** Set IF with IF_STATE_LOST to IF_STATE_HIDDEN,
 *  leave the multicast group and delete the VIF.
 */
void hideLostIf ( struct IfDesc *Dp ) {
    if ( IF_STATE_LOST == Dp->state ) {
        my_log(LOG_NOTICE, 0, "%s [Downstream -> Hidden]", Dp->Name);
        Dp->state = IF_STATE_HIDDEN;
        leaveMcGroup( getMcGroupSock(), Dp, allrouters_group );
        delVIF( Dp );
    }
}

/** Enable IF with IF_STATE_HIDDEN as IF_STATE_DOWNSTREAM,
 *  add the VIF and join the multicast group.
 */
void enableHiddenIf ( struct IfDesc *Dp ) {
    // when IF become enabled from downstream, addVIF to enable its VIF
    if ( Dp->state == IF_STATE_HIDDEN ) {
        my_log(LOG_NOTICE, 0, "%s [Hidden -> Downstream]", Dp->Name);
        Dp->state = IF_STATE_DOWNSTREAM;
        addVIF( Dp );
        joinMcGroup( getMcGroupSock(), Dp, allrouters_group );
    }
}

/* aimwang: add for detect interface and rebuild IfVc record */
/***************************************************
 * TODO:    Only need run me when detect downstream changed.
 *          For example: /etc/ppp/ip-up & ip-down can touch a file /tmp/ppp_changed
 *          So I can check if the file exist then run me and delete the file.
 ***************************************************/
void rebuildIfVc () {
    struct ifaddrs *ifap;     // pointer to iterate the if linked list
    struct IfDesc *Dp;

    my_log(LOG_DEBUG, 0, "rebuildIfVc: Starting...");

    // get the config
    struct Config *config = getCommonConfig();

    /* get If vector
     */
    if (getifaddrs(&ifap) < 0) {
       my_log( LOG_ERR, errno, "rebuildIfVc: getifaddrs() failed" );
    }

    // aimwang: set all downstream IF as lost, for check IF exist or gone.
    looseDownstreamIfs();

    /* loop over interfaces and copy interface info to IfDescVc
     */
    {
        struct ifaddrs *ifa;     // pointer to iterate the if linked list
        char FmtBu[ 32 ];
 
        int Ix;

        // Temp keepers of interface params...
        uint32_t addr, subnet, mask;

        struct SubnetList *allowednet, *currsubnet;

        for (ifa = ifap; ifa; ifa = ifa->ifa_next) {

            for (Dp = IfDescVc; Dp < IfDescEp; Dp++) {
                if (0 == strcmp(Dp->Name, ifa->ifa_name)) {
                    break;
                }
            }

            if (Dp == IfDescEp) {
                strncpy( Dp->Name, ifa->ifa_name, sizeof( IfDescEp->Name ) );
            }

            if ( NULL == ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET ) {
                if (Dp == IfDescEp) {
                    IfDescEp++;
                }
                Dp->InAdr.s_addr = 0;  /* mark as non-IP interface */
                continue;
            }

            // Get the interface adress...
            Dp->InAdr = sockaddr2in_addr(ifa->ifa_addr);
            addr = Dp->InAdr.s_addr;

            // Get the subnet mask...
            mask = sockaddr2in_addr(ifa->ifa_netmask).s_addr;
            subnet = addr & mask;

            Dp->Flags = ifa->ifa_flags;

            if (0x10d1 == Dp->Flags) {
                addr = sockaddr2in_addr(ifa->ifa_dstaddr).s_addr;
                subnet = addr & mask;
            }

            if (Dp == IfDescEp) {
                // Insert the verified subnet as an allowed net...
                Dp->allowednets = (struct SubnetList *)malloc(sizeof(struct SubnetList));
                if(IfDescEp->allowednets == NULL) {
                    my_log(LOG_ERR, 0, "rebuildIfVc: Out of memory !");
                }
                Dp->allowednets->next = NULL;
                Dp->state         = IF_STATE_DOWNSTREAM;
                Dp->robustness    = DEFAULT_ROBUSTNESS;
                Dp->threshold     = DEFAULT_THRESHOLD;   /* ttl limit */
                Dp->ratelimit     = DEFAULT_RATELIMIT; 
            }

            // Set the network address for the IF..
            Dp->allowednets->subnet_mask = mask;
            Dp->allowednets->subnet_addr = subnet;

            // Set the state for the IF...
            if (Dp->state == IF_STATE_LOST) {
                Dp->state         = IF_STATE_DOWNSTREAM;
            }

            // when IF become enabeld from downstream, addVIF to enable its VIF
            if (Dp->state == IF_STATE_HIDDEN) {
                my_log(LOG_NOTICE, 0, "rebuildIfVc: %s [Hidden -> Downstream]", Dp->Name);
                Dp->state = IF_STATE_DOWNSTREAM;
                addVIF(Dp);
                joinMcGroup(getMcGroupSock(), Dp, allrouters_group);
            }

            // addVIF when found new IF
            if (Dp == IfDescEp) {
                my_log(LOG_NOTICE, 0, "rebuildIfVc: %s [New]", Dp->Name);
                Dp->state = config->defaultInterfaceState;
                addVIF(Dp);
                joinMcGroup(getMcGroupSock(), Dp, allrouters_group);
                IfDescEp++;
            }
        }

        // Debug log the result...
        my_log( LOG_DEBUG, 0, "rebuildIfVc: Interface %s Addr: %s, Flags: 0x%04x, Network: %s",
             Dp->Name,
             fmtInAdr( FmtBu, Dp->InAdr ),
             Dp->Flags,
             inetFmts( subnet, mask, s1 )
        );
    }

    // aimwang: search not longer exist IF, set as hidden and call delVIF
    for (Dp = IfDescVc; Dp < IfDescEp; Dp++) {
        if (IF_STATE_LOST == Dp->state) {
            my_log(LOG_NOTICE, 0, "rebuildIfVc: %s [Downstream -> Hidden]", Dp->Name);
            Dp->state = IF_STATE_HIDDEN;
            leaveMcGroup( getMcGroupSock(), Dp, allrouters_group );
            delVIF(Dp);
        }
    }

    freeifaddrs( ifap );
}

/*
** Builds up a vector with the interface of the machine. Calls to the other functions of 
** the module will fail if they are called before the vector is build.
**          
*/
void buildIfVc(void) {
    struct ifaddrs *ifap, *ifa;     // pointer to iterate the if linked list

    my_log(LOG_DEBUG, 0, "buildIfVc: Starting...");

    // get the config
    struct Config *config = getCommonConfig();

    /* get If vector
     */
    if (getifaddrs(&ifap) < 0) {
       my_log( LOG_ERR, errno, "buildIfVc: getifaddrs() failed" );
    }

    /* loop over interfaces and copy interface info to IfDescVc
     */
    {
        // Temp keepers of interface params...
        uint32_t addr, subnet, mask;

        for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
            char FmtBu[ 32 ];

            if (IfDescEp >= &IfDescVc[ MAX_IF ]) {
                my_log(LOG_WARNING, 0, "buildIfVc: Too many interfaces, skipping %s", ifa->ifa_name);
                continue;
            }

            strncpy( IfDescEp->Name, ifa->ifa_name, sizeof( IfDescEp->Name ) );

            // Currently don't set any allowed nets...
            //IfDescEp->allowednets = NULL;

            // Set the Vif index to -1 by default.
            IfDescEp->vifindex = -1;

            /* don't retrieve more info for non-IP interfaces
             */
            if ( NULL == ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET ) {
                if ( NULL == ifa->ifa_addr ) {
                    // Log the skipped interface...
                    my_log( LOG_DEBUG, 0, "buildIfVc: Interface is non-IP: %s",
                            ifa->ifa_name
                    );
                } else {
                    const char* sa_family_str = get_sa_family_str( ifa->ifa_addr->sa_family );

                    // Log the skipped interface...
                    my_log( LOG_DEBUG, 0, "buildIfVc: Interface is non-IP: %s, sa_family: %s (%u)",
                            ifa->ifa_name,
                            sa_family_str,
                            ifa->ifa_addr->sa_family
                    );
                }

                IfDescEp->InAdr.s_addr = 0;  /* mark as non-IP interface */
                IfDescEp++;
                continue;
            }

            // Get the interface adress...
            IfDescEp->InAdr = sockaddr2in_addr(ifa->ifa_addr);
            addr = IfDescEp->InAdr.s_addr;

            // Get the subnet mask...
            mask = sockaddr2in_addr(ifa->ifa_netmask).s_addr;
            subnet = addr & mask;

            /* get if flags
            **
            ** typical flags:
            ** lo    0x0049 -> Running, Loopback, Up
            ** ethx  0x1043 -> Multicast, Running, Broadcast, Up
            ** ipppx 0x0091 -> NoArp, PointToPoint, Up 
            ** grex  0x00C1 -> NoArp, Running, Up
            ** ipipx 0x00C1 -> NoArp, Running, Up
            */
            IfDescEp->Flags = ifa->ifa_flags;

            // aimwang: when pppx get dstaddr for use
            if (0x10d1 == IfDescEp->Flags) {
                addr = sockaddr2in_addr(ifa->ifa_dstaddr).s_addr;
                subnet = addr & mask;
            }

            // Insert the verified subnet as an allowed net...
            IfDescEp->allowednets = (struct SubnetList *)malloc(sizeof(struct SubnetList));
            if(IfDescEp->allowednets == NULL) {
                my_log(LOG_ERR, 0, "buildIfVc: Out of memory !");
            }

            // Create the network address for the IF..
            IfDescEp->allowednets->next = NULL;
            IfDescEp->allowednets->subnet_mask = mask;
            IfDescEp->allowednets->subnet_addr = subnet;

            // Set the default params for the IF...
            IfDescEp->state         = config->defaultInterfaceState;
            IfDescEp->robustness    = DEFAULT_ROBUSTNESS;
            IfDescEp->threshold     = DEFAULT_THRESHOLD;   /* ttl limit */
            IfDescEp->ratelimit     = DEFAULT_RATELIMIT; 
            

            // Debug log the result...
            my_log( LOG_DEBUG, 0, "buildIfVc: Interface %s Addr: %s, Flags: 0x%04x, Network: %s",
                 IfDescEp->Name,
                 fmtInAdr( FmtBu, IfDescEp->InAdr ),
                 IfDescEp->Flags,
                 inetFmts( subnet,mask, s1 )
            );

            IfDescEp++;
        }
    }

    freeifaddrs( ifap );
}

/*
** Returns a pointer to the IfDesc of the interface 'IfName'
**
** returns: - pointer to the IfDesc of the requested interface
**          - NULL if no interface 'IfName' exists
**          
*/
struct IfDesc *getIfByName( const char *IfName ) {
    struct IfDesc *Dp;

    for ( Dp = IfDescVc; Dp < IfDescEp; Dp++ ) {
        if ( ! strcmp( IfName, Dp->Name ) ) {
            return Dp;
        }
    }

    return NULL;
}

/*
** Returns a pointer to the IfDesc of the interface 'Ix'
**
** returns: - pointer to the IfDesc of the requested interface
**          - NULL if no interface 'Ix' exists
**          
*/
struct IfDesc *getIfByIx( unsigned Ix ) {
    struct IfDesc *Dp = &IfDescVc[ Ix ];
    return Dp < IfDescEp ? Dp : NULL;
}

/**
*   Returns a pointer to the IfDesc whose subnet matches
*   the supplied IP adress. The IP must match a interfaces
*   subnet, or any configured allowed subnet on a interface.
*/
struct IfDesc *getIfByAddress( uint32_t ipaddr ) {

    struct IfDesc       *Dp;
    struct SubnetList   *currsubnet;
    struct IfDesc       *res = NULL;
    uint32_t            last_subnet_mask = 0;

    for ( Dp = IfDescVc; Dp < IfDescEp; Dp++ ) {
        // Loop through all registered allowed nets of the VIF...
        for(currsubnet = Dp->allowednets; currsubnet != NULL; currsubnet = currsubnet->next) {
            // Check if the ip falls in under the subnet....
            if(currsubnet->subnet_mask > last_subnet_mask && (ipaddr & currsubnet->subnet_mask) == currsubnet->subnet_addr) {
                res = Dp;
                last_subnet_mask = currsubnet->subnet_mask;
            }
        }
    }

    return res;
}


/**
*   Returns a pointer to the IfDesc whose subnet matches
*   the supplied IP adress. The IP must match a interfaces
*   subnet, or any configured allowed subnet on a interface.
*/
struct IfDesc *getIfByVifIndex( unsigned vifindex ) {
    struct IfDesc       *Dp;
    if( vifindex > 0 ) {
        for ( Dp = IfDescVc; Dp < IfDescEp; Dp++ ) {
            if(Dp->vifindex == vifindex) {
                return Dp;
            }
        }
    }

    return NULL;
}


/**
*   Function that checks if a given ipaddress is a valid
*   address for the supplied VIF.
*/
int isAdressValidForIf( struct IfDesc* intrface, uint32_t ipaddr ) {
    struct SubnetList   *currsubnet;

    if( intrface == NULL ) {
        return 0;
    }
    // Loop through all registered allowed nets of the VIF...
    for( currsubnet = intrface->allowednets; currsubnet != NULL; currsubnet = currsubnet->next ) {
        // Check if the ip falls in under the subnet....
        if((ipaddr & currsubnet->subnet_mask) == (currsubnet->subnet_addr& currsubnet->subnet_mask)) {
            return 1;
        }
    }

    return 0;
}

