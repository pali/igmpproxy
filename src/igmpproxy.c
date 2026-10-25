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
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
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

    int c, devnull = -1;
    bool NotAsDaemon = false;

    struct Config *config = NULL;
    struct passwd *pw = NULL;

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
    char *configFilePath = ArgVc[optind];

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

        // Open /dev/null before chrooting.
        if (!NotAsDaemon) {
            devnull = open("/dev/null", O_RDWR);
            if (devnull == -1)
                my_log(LOG_ERR, 0, "unable to open /dev/null");
        }

        config = getCommonConfig();

        if (config->user[0]) {
            pw = getpwnam(config->user);
            if (pw == NULL)
                my_log(LOG_ERR, 0, "unknown user %s", config->user);
        }

        if (config->chroot[0])
            if (chroot(config->chroot) != 0 || chdir("/") != 0)
                my_log(LOG_ERR, 0, "unable to chroot to %s",
                  config->chroot);

        if (pw != NULL)
            if (setgroups(1, &pw->pw_gid) != 0 ||
              setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) != 0 ||
              setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) != 0)
                my_log(LOG_ERR, 0, "unable to drop privileges to %s",
                  config->user);

        if ( !NotAsDaemon ) {

            // Only daemon goes past this line...
            if (fork()) exit(0);

            // Detach daemon from terminal
            if ( close( 0 ) < 0 || close( 1 ) < 0 || close( 2 ) < 0 ||
              dup2( devnull, 0 ) < 0 || dup2( devnull, 1 ) < 0 ||
              dup2( devnull, 2 ) < 0 || setpgid( 0, 0 ) < 0 ) {
                my_log( LOG_ERR, errno, "failed to detach daemon" );
            }
            if (devnull > 2)
                close(devnull);
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

    // Loads configuration for Physical interfaces...
    buildIfVc();

    // Configures IF states and settings
    configureVifs();

    switch ( Err = enableMRouter() ) {
    case 0: break;
    case EADDRINUSE: my_log( LOG_ERR, EADDRINUSE, "MC-Router API already in use" ); break;
    default: my_log( LOG_ERR, Err, "MRT_INIT failed" );
    }

    /* create VIFs for all IP, non-loop interfaces
     */
    {
        unsigned Ix;
        struct IfDesc *Dp;
        int     vifcount = 0, upsvifcount = 0;

        // init array to "not set"
        for ( Ix = 0; Ix < MAX_UPS_VIFS; Ix++)
        {
            upStreamIfIdx[Ix] = -1;
        }

        for ( Ix = 0; (Dp = getIfByIx(Ix)); Ix++ ) {

            if ( Dp->InAdr.s_addr && ! (Dp->Flags & IFF_LOOPBACK) ) {
                if(Dp->state == IF_STATE_UPSTREAM) {
                    if (upsvifcount < MAX_UPS_VIFS -1)
                    {
                        my_log(LOG_DEBUG, 0, "Found upstrem IF #%d, will assing as upstream Vif %d",
                            upsvifcount, Ix);
                        upStreamIfIdx[upsvifcount++] = Ix;
                    } else {
                        my_log(LOG_ERR, 0, "Cannot set VIF #%d as upstream as well. Mac upstream Vif count is %d",
                            Ix, MAX_UPS_VIFS);
                    }
                }

                if (Dp->state != IF_STATE_DISABLED) {
                    addVIF( Dp );
                    vifcount++;
                }
            }
        }

        if(0 == upsvifcount) {
            my_log(LOG_ERR, 0, "There must be at least 1 Vif as upstream.");
        }
    }

    // Initialize IGMP
    initIgmp();
    // Initialize Routing table
    initRouteTable();
    // Initialize timer
    callout_init();

    return 1;
}

/**
*   Clean up all on exit...
*/
void igmpProxyCleanUp(void) {
    my_log( LOG_DEBUG, 0, "clean handler called" );

    free_all_callouts();    // No more timeouts.
    clearAllRoutes();       // Remove all routes.
    disableMRouter();       // Disable the multirout API
}

/* Keep the second-resolution callout queue on real monotonic time. A short
 * interface-rescan timeout must not age it by the next timer's full delay.
 * Catch up after callbacks before accepting input that may create new timers.
 */
static void ageCallouts(struct timespec *lasttime, long *remainder) {
    struct timespec now;
    time_t elapsed;
    long nsec;

    for (;;) {
        if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
            my_log(LOG_ERR, errno, "clock_gettime");
        elapsed = now.tv_sec - lasttime->tv_sec;
        nsec = now.tv_nsec - lasttime->tv_nsec + *remainder;
        if (nsec >= 1000000000L) {
            elapsed++;
            nsec -= 1000000000L;
        } else if (nsec < 0) {
            elapsed--;
            nsec += 1000000000L;
        }
        *lasttime = now;
        *remainder = nsec;
        if (elapsed == 0 && timer_nextTimer() != 0)
            break;
        age_callout_queue(elapsed);
    }
}

static struct timespec *nextTimeout(struct timespec *tv, int rescan,
                                    long remainder) {
    int secs = timer_nextTimer();

    if (secs < 0 && !rescan)
        return NULL;
    tv->tv_sec = secs < 0 ? 3 : secs;
    tv->tv_nsec = 0;
    if (secs > 0 && remainder) {
        tv->tv_sec--;
        tv->tv_nsec = 1000000000L - remainder;
    }
    if (rescan && tv->tv_sec >= 3) {
        tv->tv_sec = 3;
        tv->tv_nsec = 0;
    }
    return tv;
}

/**
*   Main daemon loop.
*/
void igmpProxyRun(void) {
    // Get the config.
    struct Config *config = getCommonConfig();
    // Set some needed values.
    register int recvlen;
    int     MaxFD, Rt, select_errno;
    fd_set  ReadFDS;
    socklen_t dummy = 0;
    struct  timespec  lasttime, tv;
    struct  timespec  *timeout;
    long remainder = 0;

    // Initialize timer vars
    if (clock_gettime(CLOCK_MONOTONIC, &lasttime) < 0)
        my_log(LOG_ERR, errno, "clock_gettime");

    // First thing we send a membership query in downstream VIF's...
    sendGeneralMembershipQuery();

    // Loop until the end...
    for (;;) {

        // Process signaling...
        if (sighandled) {
            if (sighandled & GOT_SIGINT) {
                sighandled &= ~GOT_SIGINT;
                my_log(LOG_NOTICE, 0, "Got a interrupt signal. Exiting.");
                break;
            }
        }

        ageCallouts(&lasttime, &remainder);

        /* aimwang: call rebuildIfVc */
        if (config->rescanVif)
            rebuildIfVc();

        // Prepare timeout...
        timeout = nextTimeout(&tv, config->rescanVif, remainder);

        // Prepare for select.
        MaxFD = MRouterFD;

        FD_ZERO( &ReadFDS );
        FD_SET( MRouterFD, &ReadFDS );

        // wait for input
        Rt = pselect( MaxFD +1, &ReadFDS, NULL, NULL, timeout, NULL );
        select_errno = errno;

        /* Advance old timers before acceptIgmp() can schedule new ones.
         * EINTR and receive errors must not suspend the callout clock.
         */
        ageCallouts(&lasttime, &remainder);

        // log and ignore failures
        if( Rt < 0 ) {
            if (select_errno != EINTR)
                my_log( LOG_WARNING, select_errno, "select() failure" );
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
        /* XXX: Not in use.
        case SIGHUP:
            sighandled |= GOT_SIGHUP;
            break;

        case SIGUSR1:
            sighandled |= GOT_SIGUSR1;
            break;

        case SIGUSR2:
            sighandled |= GOT_SIGUSR2;
            break;
        */
    }
}
