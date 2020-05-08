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
*   igmpproxy.c - The main file for the IGMP proxy application.
*
*   February 2005 - Johnny Egeland
*/

/* getopt() and clock_getime() */
#ifndef __FreeBSD__
    #ifndef _POSIX_C_SOURCE
    #define _POSIX_C_SOURCE 200112L
    #endif
#endif

#include "igmpproxy.h"

static const char Usage[] =
"Usage: igmpproxy [-h] [-n] [-d] [-v [-v]] <configfile>\n"
"\n"
"   -h   Display this help screen\n"
"   -n   Do not run as a daemon\n"
"   -d   Run in debug mode. Output all messages on stderr. Implies -n.\n"
"   -v   Be verbose. Give twice to see even debug messages.\n"
"\n"
PACKAGE_STRING "\n"
;

// Local function Prototypes
static void signalHandler(int);
int     igmpProxyInit(void);
void    igmpProxyCleanUp(void);
void    igmpProxyRun(void);

// Global vars...
static int sighandled = 0;
#define GOT_SIGINT  0x01
#define GOT_SIGHUP  0x02
#define GOT_SIGUSR1 0x04
#define GOT_SIGUSR2 0x08

// Holds the indeces of the upstream IF...
int     upStreamIfIdx[MAX_UPS_VIFS];

/**
*   Program main method. Is invoked when the program is started
*   on commandline. The number of commandline arguments, and a
*   pointer to the arguments are received on the line...
*/
int main( int ArgCn, char *ArgVc[] ) {

    int c;
    bool NotAsDaemon = false;

    srand(time(NULL) * getpid());

    // Parse the commandline options and setup basic settings..
    while ((c = getopt(ArgCn, ArgVc, "vdnh")) != -1) {
        switch (c) {
        case 'n':
            NotAsDaemon = true;
            break;
        case 'd':
            Log2Stderr = true;
            NotAsDaemon = true;
            break;
        case 'v':
            if (LogLevel == LOG_INFO)
                LogLevel = LOG_DEBUG;
            else
                LogLevel = LOG_INFO;
            break;
        case 'h':
            fputs(Usage, stderr);
            exit(0);
            break;
        default:
            exit(1);
            break;
        }
    }

    if (optind != ArgCn - 1) {
        fputs("You must specify the configuration file.\n", stderr);
        exit(1);
    }
    configFilePath = ArgVc[optind];

    // Chech that we are root
    if (geteuid() != 0) {
       fprintf(stderr, "igmpproxy: must be root\n");
       exit(1);
    }

    openlog("igmpproxy", LOG_PID, LOG_USER);

    // Write debug notice with file path...
    my_log(LOG_DEBUG, 0, "Searching for config file at '%s'" , configFilePath);

    do {

        // Loads the config file...
        if( ! loadConfig( configFilePath ) ) {
            my_log(LOG_ERR, 0, "Unable to load config file...");
            break;
        }

        // Initializes the deamon.
        if ( !igmpProxyInit() ) {
            my_log(LOG_ERR, 0, "Unable to initialize IGMPproxy.");
            break;
        }

        if ( !NotAsDaemon ) {

            // Only daemon goes past this line...
            if (fork()) exit(0);

            // Detach daemon from terminal
            if ( close( 0 ) < 0 || close( 1 ) < 0 || close( 2 ) < 0
                || open( "/dev/null", 0 ) != 0 || dup2( 0, 1 ) < 0 || dup2( 0, 2 ) < 0
                || setpgid( 0, 0 ) < 0
            ) {
                my_log( LOG_ERR, errno, "failed to detach daemon" );
            }
        }

        // Go to the main loop.
        igmpProxyRun();

        // Clean up
        igmpProxyCleanUp();

    } while ( false );

    // Inform that we are exiting.
    my_log(LOG_INFO, 0, "Shutdown complete....");

    exit(0);
}

/**
*   Handles the initial startup of the daemon.
*/
int igmpProxyInit(void) {
    struct sigaction sa;
    int Err;

    sa.sa_handler = signalHandler;
    sa.sa_flags = 0;    /* Interrupt system calls */
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    // Loads configuration for Physical interfaces...
    buildIfVc();

    // Configures IF states and settings
    configureVifs();

    switch ( Err = enableMRouter() ) {
    case 0: break;
    case EADDRINUSE: my_log( LOG_ERR, EADDRINUSE, "MC-Router API already in use" ); break;
    default: my_log( LOG_ERR, Err, "MRT_INIT failed" );
    }

    createVifs(NULL);
    
    // Initialize IGMP
    initIgmp();
    // Initialize Routing table
    initRouteTable();
    // Initialize timer
    free_all_callouts();

    return 1;
}

/**
*   Clean up all on exit...
*/
void igmpProxyCleanUp(void) {
    my_log( LOG_DEBUG, 0, "clean handler called" );

    free_all_callouts();    // No more timeouts.
    clearRoutes(NULL);      // Remove all routes.
    disableMRouter();       // Disable the multirout API
}

/**
*   Main daemon loop.
*/
void igmpProxyRun(void) {
    // Get the config.
    struct Config *config = getCommonConfig();
    // Set some needed values.
    register int recvlen;
    int     MaxFD, Rt, secs, rescanvif_timer = -1, rescanconf_timer = -1;
    fd_set  ReadFDS;
    socklen_t dummy = 0;
    struct  timespec  curtime, lasttime, difftime, *timeout = &difftime;

    // First thing we send a membership query in downstream VIF's...
    sendGeneralMembershipQuery();

    // Initialize timer vars
    difftime.tv_nsec = 0;
    clock_gettime(CLOCK_MONOTONIC, &curtime);
    lasttime = curtime;

    // Loop until the end...
    for (;;) {

        // Process signaling...
        if (sighandled) {
            if (sighandled & GOT_SIGINT) {
                sighandled &= ~GOT_SIGINT;
                my_log(LOG_NOTICE, 0, "Got a interrupt signal. Exiting.");
                break;
            }
            if (sighandled & GOT_SIGHUP) {
                sighandled &= ~GOT_SIGHUP;

                // Write debug notice with file path...
                my_log(LOG_DEBUG, 0, "SIGHUP: Reloading config file at '%s'" , configFilePath);

                reloadConfig();
            }
        }

        // Set rescanvif or rescanconf timer.
        if (!config->rescanConf && config->rescanVif > 0 && timer_leftTimer(rescanvif_timer) == -1) {
            rescanvif_timer=timer_setTimer(config->rescanVif, (timer_f)rebuildIfVc, NULL);
        }
        if (config->rescanConf > 0 && timer_leftTimer(rescanconf_timer) == -1) {
            rescanconf_timer=timer_setTimer(config->rescanConf, (timer_f)reloadConfig, NULL);
        }

        // Timeout = 1s - difference between current and last time age_callout queue with .01s grace.
        // This will make sure age_callout_queue is run once every s (timer resolution) +- 0.01s.
        // If aging queues takes > .01s on very slow systems or when queue is very large, 
        // this will become less accurate by about the time it takes to age the queue + time to process a request.
        clock_gettime(CLOCK_MONOTONIC, &curtime);
        difftime.tv_sec = curtime.tv_sec - lasttime.tv_sec;
        if (curtime.tv_nsec >= lasttime.tv_nsec ) {
            timeout->tv_nsec = 999999999 - (curtime.tv_nsec - lasttime.tv_nsec);
        } else {
            timeout->tv_nsec = 999999999 - (1000000000 - lasttime.tv_nsec + curtime.tv_nsec); difftime.tv_sec--;
        }
        if ( difftime.tv_sec > 0 || timeout->tv_nsec < 10000000 ) {
            timeout->tv_nsec = 999999999; timeout->tv_sec = 0;
            lasttime = curtime;
            age_callout_queue(curtime);
        }

        // Prepare for select.
        MaxFD = MRouterFD;

        FD_ZERO( &ReadFDS );
        FD_SET( MRouterFD, &ReadFDS );

        // wait for input
        Rt = pselect( MaxFD +1, &ReadFDS, NULL, NULL, timeout, NULL );

        // log and ignore failures
        if( Rt < 0 ) {
            my_log( LOG_WARNING, errno, "select() failure" );
            continue;
        }
        else if( Rt > 0 ) {

            // Read IGMP request, and handle it...
            if( FD_ISSET( MRouterFD, &ReadFDS ) ) {

                recvlen = recvfrom(MRouterFD, recv_buf, RECV_BUF_SIZE,
                                   0, NULL, &dummy);
                if (recvlen < 0) {
                    if (errno != EINTR) my_log(LOG_ERR, errno, "recvfrom");
                    continue;
                }

                acceptIgmp(recvlen);
            }
        }
    }
}

/*
 * Signal handler.  Take note of the fact that the signal arrived
 * so that the main loop can take care of it.
 */
static void signalHandler(int sig) {
    switch (sig) {
    case SIGINT:
    case SIGTERM:
        sighandled |= GOT_SIGINT;
        break;
    case SIGHUP:
        sighandled |= GOT_SIGHUP;
        break;
        /* XXX: Not in use.
        case SIGUSR1:
            sighandled |= GOT_SIGUSR1;
            break;

        case SIGUSR2:
            sighandled |= GOT_SIGUSR2;
            break;
        */
    }
}
