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


struct SubnetList *create_allowednet( struct ifaddrs *ifa );
void delete_subnetlist( struct SubnetList *subnet );


/** Set all downstream IF as IF_STATE_LOST to abe able to check
 *  if IF still exists or is gone.
 */
void loose_downstream_ifs( void ) {
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
void hide_lost_downstream_if( struct IfDesc *Dp ) {
    if ( IF_STATE_LOST == Dp->state ) {
        my_log(LOG_NOTICE, 0, "%s [Downstream -> Hidden]", Dp->Name);
        Dp->state = IF_STATE_HIDDEN;
        leaveMcGroup( getMcGroupSock(), Dp, allrouters_group );
        delVIF( Dp );
        delete_subnetlist(Dp->allowednets);
    }
}

/** Enable IF with IF_STATE_HIDDEN as IF_STATE_DOWNSTREAM,
 *  add the VIF and join the multicast group.
 */
void enable_hidden_downstream_if( struct ifaddrs *ifa, struct IfDesc *Dp ) {
    // when IF become enabled from downstream, addVIF to enable its VIF
    if ( Dp->state == IF_STATE_HIDDEN ) {
        // Create the network address for the IF..
        Dp->allowednets = create_allowednet(ifa);

        my_log(LOG_NOTICE, 0, "%s [Hidden -> Downstream]", Dp->Name);
        Dp->state = IF_STATE_DOWNSTREAM;
        addVIF( Dp );
        joinMcGroup( getMcGroupSock(), Dp, allrouters_group );
    }
}

/*
** Deletes a SubnetList and frees use memory.
*/
void delete_subnetlist( struct SubnetList *subnet ) {
    my_log(LOG_TRACE, 0, "delete_subnetlist: Starting...");

    char FmtBu[ 32 ];    

    struct SubnetList *tmp;
    while (subnet) {
        tmp = subnet->next;
        // Debug log the result...
        my_log( LOG_TRACE, 0, "delete_subnetlist: Network: %s",
            inetFmts( subnet->subnet_addr, subnet->subnet_mask, s1 )
        );
        free(subnet);
        subnet = tmp;
    }

    my_log(LOG_TRACE, 0, "delete_subnetlist: ...done.");
}

/*
** Build the SubnetList structure from an ifaddrs.
*/
struct SubnetList *create_allowednet( 
    struct ifaddrs *ifa
) {
    my_log(LOG_TRACE, 0, "create_allowednets: Starting...");

    // Temp keepers of interface params...
    uint32_t addr, subnet, mask;

    struct in_addr in_addr;

    // Get the interface adress...
    in_addr = sockaddr2in_addr(ifa->ifa_addr);
    addr = in_addr.s_addr;

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
    if (0x10d1 ==  ifa->ifa_flags) {
        my_log( LOG_TRACE, 0, "create_allowednet: Interface %s is PPP (Flags: 0x%04x)",
             ifa->ifa_name,
             ifa->ifa_flags
        );
        addr = sockaddr2in_addr(ifa->ifa_dstaddr).s_addr;
        subnet = addr & mask;
    }

    // Insert the verified subnet as an allowed net...
    struct SubnetList *allowednet = (struct SubnetList *)malloc(sizeof(struct SubnetList));
    if(allowednet == NULL) {
        my_log(LOG_ERR, 0, "create_allowednet: Out of memory !");
    }

    // Create the network address for the IF..
    allowednet->next = NULL;
    allowednet->subnet_mask = mask;
    allowednet->subnet_addr = subnet;

    // Debug log the result...
    char FmtBu[ 32 ];    
    my_log( LOG_TRACE, 0, "create_allowednet: Addr: %s, Network: %s",
           fmtInAdr( FmtBu, in_addr ),
           inetFmts( subnet, mask, s1 )
    );

    my_log(LOG_TRACE, 0, "create_allowednet: ...done.");

    return allowednet;
}

/*
** Builds up the interface of the machine. Calls to the other functions of 
** the module will fail if they are called before the vector is build.
**          
*/
void buildIf( 
    struct ifaddrs *ifa, 
    struct IfDesc *Dp, 
    int state
) {
    my_log(LOG_TRACE, 0, "buildIf: Starting...");

    char FmtBu[ 32 ];
    
    strncpy( Dp->Name, ifa->ifa_name, sizeof( Dp->Name ) );

    // Currently don't set any allowednets...
    //IfDescEp->allowednets = NULL;

    // Set the Vif index to -1 by default.
    IfDescEp->vifindex = -1;

    // Get the interface adress...
    IfDescEp->InAdr = sockaddr2in_addr(ifa->ifa_addr);

    /* get if flags
    **
    ** typical flags:
    ** lo    0x0049 -> Running, Loopback, Up
    ** ethx  0x1043 -> Multicast, Running, Broadcast, Up
    ** ipppx 0x0091 -> NoArp, PointToPoint, Up 
    ** grex  0x00C1 -> NoArp, Running, Up
    ** ipipx 0x00C1 -> NoArp, Running, Up
    */
    Dp->Flags = ifa->ifa_flags;

    // Create the network address for the IF..
    Dp->allowednets = create_allowednet(ifa);

    // Set the default params for the IF...
    Dp->state         = state;
    Dp->robustness    = DEFAULT_ROBUSTNESS;
    Dp->threshold     = DEFAULT_THRESHOLD;   /* ttl limit */
    Dp->ratelimit     = DEFAULT_RATELIMIT; 

    // Debug log the result...
    my_log( LOG_DEBUG, 0, "buildIf: Interface %s Addr: %s, Flags: 0x%04x, Network: %s",
           Dp->Name,
           fmtInAdr( FmtBu, Dp->InAdr ),
           Dp->Flags,
           inetFmts( Dp->allowednets->subnet_addr, Dp->allowednets->subnet_mask, s1 )
    );

    my_log(LOG_TRACE, 0, "buildIf: ...done.");
}


/* aimwang: add for detect interface and rebuild IfVc record */
/***************************************************
 * TODO:    Only need run me when detect downstream changed.
 *          For example: /etc/ppp/ip-up & ip-down can touch a file /tmp/ppp_changed
 *          So I can check if the file exist then run me and delete the file.
 ***************************************************/
void rebuildIfVc () {
    struct ifaddrs *ifap;   // pointer to iterate the if linked list
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
    loose_downstream_ifs();

    /* loop over interfaces and copy interface info to IfDescVc
     */
    {
        struct ifaddrs *ifa;     // pointer to iterate the if linked list

        char FmtBu[ 32 ];
 

        // Temp keepers of interface params...
        uint32_t addr, subnet, mask;

        for (ifa = ifap; ifa; ifa = ifa->ifa_next) {

            /* don't retrieve more info for non-IP interfaces
             */
            if ( NULL == ifa->ifa_addr ) {  // IF has no IP set, skipping
                // Log the skipped interface...
                my_log( LOG_DEBUG, 0, "rebuildIfVc: Interface is non-IP: %s, skipping",
                        ifa->ifa_name
                );
                    
                continue;
            }
            if ( ifa->ifa_addr->sa_family != AF_INET ) {    // not an IP interface, skipping
                const char* sa_family_str = get_sa_family_str( ifa->ifa_addr->sa_family );

                // Log the skipped interface...
                my_log( LOG_DEBUG, 0, "rebuildIfVc: Interface is non-IP: %s, sa_family: %s (%u), skipping",
                        ifa->ifa_name,
                        sa_family_str,
                        ifa->ifa_addr->sa_family
                );

                continue;
            }

            // search existing IF by name
            for (Dp = IfDescVc; ((Dp < IfDescEp) && (Dp < &IfDescVc[ MAX_IF ])); Dp++) {
                if (0 == strcmp(Dp->Name, ifa->ifa_name)) {
                    my_log(LOG_TRACE, 0, "rebuildIfVc: Found match for interface %s", ifa->ifa_name);
                    break;
                }
            }

            // we reached the end, means we have a new entry
            // and have to move the end pointer
            if (Dp == IfDescEp) {
                // no more space to attach newly found devices 
                if (IfDescEp >= &IfDescVc[ MAX_IF ]) {
                    my_log(LOG_WARNING, 0, "rebuildIfVc: Too many interfaces, skipping %s", ifa->ifa_name);
                    continue;
                }

                buildIf( ifa, Dp, IF_STATE_DOWNSTREAM );

                // addVIF when found new IF
                my_log(LOG_NOTICE, 0, "rebuildIfVc: %s [New]", Dp->Name);
                addVIF(Dp);
                joinMcGroup(getMcGroupSock(), Dp, allrouters_group);

                IfDescEp++;

                continue;
            };

            // Set the state for the IF...
            if (Dp->state == IF_STATE_LOST) {
                Dp->state = IF_STATE_DOWNSTREAM;
            } else {
                enable_hidden_downstream_if( ifa, Dp );
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

    // aimwang: search no longer existing IF, set as hidden and call delVIF
    for (Dp = IfDescVc; Dp < IfDescEp; Dp++) {
        hide_lost_downstream_if( Dp );
    }

    freeifaddrs( ifap );
}

/*
** Builds up a vector with the interface of the machine. Calls to the other functions of 
** the module will fail if they are called before the vector is build.
**          
*/
void buildIfVc(void) {
    struct ifaddrs *ifap;   // pointer to iterate the if linked list

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
        struct ifaddrs *ifa;     // pointer to iterate the if linked list

        // Temp keepers of interface params...
        uint32_t addr, subnet, mask;

        for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
            char FmtBu[ 32 ];

            if (IfDescEp >= &IfDescVc[ MAX_IF ]) {
                my_log(LOG_WARNING, 0, "buildIfVc: Too many interfaces, skipping %s", ifa->ifa_name);
                continue;
            }

            /* don't retrieve more info for non-IP interfaces
             */
            if ( NULL == ifa->ifa_addr ) {  // IF has no IP set, skipping
                // Log the skipped interface...
                my_log( LOG_DEBUG, 0, "buildIfVc: Interface is non-IP: %s",
                        ifa->ifa_name
                );
                    
                continue;
            }
            if ( ifa->ifa_addr->sa_family != AF_INET ) {    // not an IP interface, skipping
                const char* sa_family_str = get_sa_family_str( ifa->ifa_addr->sa_family );

                // Log the skipped interface...
                my_log( LOG_DEBUG, 0, "buildIfVc: Interface is non-IP: %s, sa_family: %s (%u)",
                        ifa->ifa_name,
                        sa_family_str,
                        ifa->ifa_addr->sa_family
                );

                continue;
            }

            buildIf( ifa, IfDescEp, config->defaultInterfaceState );

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

