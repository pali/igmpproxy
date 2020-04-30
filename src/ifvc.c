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

#include "igmpproxy.h"

/* We need a temporary copy to not break strict aliasing rules */
static inline uint32_t s_addr_from_sockaddr(const struct sockaddr *addr) {
    struct sockaddr_in addr_in;
    memcpy(&addr_in, addr, sizeof(addr_in));
    return addr_in.sin_addr.s_addr;
}

struct IfDescP {
    struct IfDesc       *S;
    struct IfDesc       *E;
    unsigned int        nrint;
};
struct IfDescP IfDescP = { NULL, NULL, 0 };

/* aimwang: add for detect interface and rebuild IfVc record */
/***************************************************
 * TODO:    Only need run me when detect downstream changed.
 *          For example: /etc/ppp/ip-up & ip-down can touch a file /tmp/ppp_changed
 *          So I can check if the file exist then run me and delete the file.
 ***************************************************/
void rebuildIfVc () {
    struct IfDesc *Dp;
    unsigned int NrInt=IfDescP.nrint, If;

    my_log(LOG_DEBUG, 0, "rebuildIfVc: Starting rebuild");

    // Create a copy of the old IfDesc Table for comparisson.
    struct IfDesc *IfDescC =(struct IfDesc*)calloc(NrInt,sizeof(struct IfDesc));
    if(IfDescC == NULL) my_log(LOG_ERR, 0, "Out of memory !");
    IfDescC = memcpy ( IfDescC, IfDescP.S, NrInt*sizeof(struct IfDesc) );
    if(IfDescC == NULL) my_log(LOG_ERR, 0, "Out of memory !");

    // Build new IfDesc Table.
    buildIfVc();

    // Check for dissappeared interfaces and call delVif
    for (struct IfDesc *TmpIfDescC=IfDescC;TmpIfDescC<IfDescC+NrInt;TmpIfDescC++) {
        for (Dp=IfDescP.S; Dp<IfDescP.E; Dp++) if ( strcmp ( Dp->Name, TmpIfDescC->Name ) ) break;
        if ( Dp == IfDescP.E ) delVIF(TmpIfDescC);
    }

    // Call configureVifs to link the new IfDesc table.
    configureVifs();

    // Check for new interfaces, call addVIF and join mc routers groups if downstream
    for (Dp=IfDescP.S; Dp<IfDescP.E; Dp++) {
        struct IfDesc *TmpIfDescC;
        for (TmpIfDescC=IfDescC;TmpIfDescC<IfDescC+NrInt;TmpIfDescC++) if ( strcmp ( Dp->Name, TmpIfDescC->Name ) ) break;
        if ( TmpIfDescC == IfDescC+NrInt ) {
            addVIF(Dp);
            if( Dp->InAdr.s_addr && ! (Dp->Flags & IFF_LOOPBACK) && Dp->state == IF_STATE_DOWNSTREAM) {
                my_log(LOG_DEBUG, 0, "rebuildIfVc: Joining all-routers group %s on vif %s",
                    inetFmt(allrouters_group,s1),inetFmt(Dp->InAdr.s_addr,s2));

                // k_join(allrouters_group, Dp->InAdr.s_addr);
                joinMcGroup( getMcGroupSock(), Dp, allrouters_group );

                my_log(LOG_DEBUG, 0, "reBuildIfvc: Joining all igmpv3 multicast routers group %s on vif %s",
                    inetFmt(alligmp3_group,s1),inetFmt(Dp->InAdr.s_addr,s2));
                joinMcGroup( getMcGroupSock(), Dp, alligmp3_group );
            }
        }
    }

    // release the temporary copy of old IfDesc Table.
    free (IfDescC);
}

/*
** Builds up a vector with the interface of the machine. Calls to the other functions of
** the module will fail if they are called before the vector is build.
**
*/
void buildIfVc() {
    // Get the config.
    struct Config *config = getCommonConfig();

    unsigned int NrInt=0;
    struct ifaddrs *IfAddrsP, *TmpIfAddrsP;

    if ( (getifaddrs (&IfAddrsP)) == -1 ) {
        my_log ( LOG_ERR, errno, "buildIfVc: getifaddr() failed, cannot enumerate interfaces" );
        exit (1);
    }

    // Check nr of interfaces in system.
    TmpIfAddrsP=IfAddrsP;
    while (TmpIfAddrsP) {
        TmpIfAddrsP = TmpIfAddrsP->ifa_next;
        NrInt+=1;
    }
    IfDescP.nrint=NrInt;
    my_log (LOG_DEBUG, 0 , "buildIfVc: Found %u interface(s) on system", NrInt);

    // Allocate memory for IfDesc Table. Free first if struct is already filled.
    if ( IfDescP.S != NULL ) {
        for (struct IfDesc *Dp = IfDescP.S; Dp < IfDescP.E; Dp++) free(Dp->allowednets);
        free(IfDescP.S);
    }
    struct IfDesc *IfDescA =(struct IfDesc*)calloc(IfDescP.nrint,sizeof(struct IfDesc));
    if(IfDescA == NULL) my_log(LOG_ERR, 0, "Out of memory !");
    IfDescP.S=IfDescA;
    IfDescP.E=IfDescA;

    // loop over interfaces and copy interface info to IfDescP
    TmpIfAddrsP=IfAddrsP;
    while (TmpIfAddrsP) {
        // Temp keepers of interface params...
        uint32_t addr, subnet, mask;
        char FmtBu[ 32 ];

        strncpy( IfDescP.E->Name, TmpIfAddrsP->ifa_name, sizeof( IfDescP.E->Name ) );

        // Set the index to -1 by default.
        IfDescP.E->index = (unsigned int)-1;

        // don't retrieve more info for non-IP interfaces
        if ( TmpIfAddrsP->ifa_addr->sa_family != AF_INET ) {
            IfDescP.E->InAdr.s_addr = 0;  /* mark as non-IP interface */
            IfDescP.E++;
            TmpIfAddrsP = TmpIfAddrsP->ifa_next;
            continue;
        }

        // Get the interface adress...
        IfDescP.E->InAdr.s_addr = s_addr_from_sockaddr(TmpIfAddrsP->ifa_addr);
        addr = IfDescP.E->InAdr.s_addr;


        // Get the subnet mask...
        mask = s_addr_from_sockaddr(TmpIfAddrsP->ifa_netmask);
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
        IfDescP.E->Flags = TmpIfAddrsP->ifa_flags;

        // aimwang: when pppx get dstaddr for use
        if (0x10d1 == IfDescP.E->Flags) {
            addr = s_addr_from_sockaddr(TmpIfAddrsP->ifa_dstaddr);
            subnet = addr & mask;
        }

        // Insert the verified subnet as an allowed net...
        IfDescP.E->allowednets = (struct SubnetList *)malloc(sizeof(struct SubnetList));
        if(IfDescP.E->allowednets == NULL) my_log(LOG_ERR, 0, "Out of memory !");

        // Create the network address for the IF..
        IfDescP.E->allowednets->next = NULL;
        IfDescP.E->allowednets->subnet_mask = mask;
        IfDescP.E->allowednets->subnet_addr = subnet;

        // Set the default params for the IF...
        IfDescP.E->state         = config->defaultInterfaceState;
        IfDescP.E->robustness    = DEFAULT_ROBUSTNESS;
        IfDescP.E->threshold     = DEFAULT_THRESHOLD;   /* ttl limit */
        IfDescP.E->ratelimit     = DEFAULT_RATELIMIT;

        // Debug log the result...
        my_log( LOG_DEBUG, 0, "buildIfVc: Interface %s Addr: %s, Flags: 0x%04x, Network: %s",
             IfDescP.E->Name,
             fmtInAdr( FmtBu, IfDescP.E->InAdr ),
             IfDescP.E->Flags,
             inetFmts(subnet,mask, s1));

        IfDescP.E++;
        TmpIfAddrsP = TmpIfAddrsP->ifa_next;
    }
    
    // Free the getifadds struct.
    free (IfAddrsP);
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

    for ( Dp = IfDescP.S; Dp < IfDescP.E; Dp++ )
        if ( ! strcmp( IfName, Dp->Name ) )
            return Dp;

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
    struct IfDesc *Dp = IfDescP.S+Ix;
    return Dp < IfDescP.E ? Dp : NULL;
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

    for ( Dp = IfDescP.S; Dp < IfDescP.E; Dp++ ) {
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
    if(vifindex>0) {
        for ( Dp = IfDescP.S; Dp < IfDescP.E; Dp++ ) {
            if(Dp->index == vifindex) {
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

    if(intrface == NULL) {
        return 0;
    }

    // Loop through all registered allowed nets of the VIF...
    for(currsubnet = intrface->allowednets; currsubnet != NULL; currsubnet = currsubnet->next) {
        // Check if the ip falls in under the subnet....
        if((ipaddr & currsubnet->subnet_mask) == (currsubnet->subnet_addr& currsubnet->subnet_mask)) {
            return 1;
        }
    }
    return 0;
}
