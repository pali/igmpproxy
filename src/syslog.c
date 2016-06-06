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
#include <sys/time.h>

int LogLevel = LOG_WARNING;
bool Log2Stderr = false;

void print_log_prefix( int Severity );

void my_log( int Severity, int Errno, const char *FmtSt, ... ) {
    char LogMsg[ 128 ];

    va_list ArgPt;
    unsigned Ln;
    va_start( ArgPt, FmtSt );
    Ln = vsnprintf( LogMsg, sizeof( LogMsg ), FmtSt, ArgPt );
    if( Errno > 0 ) {
        snprintf( LogMsg + Ln, sizeof( LogMsg ) - Ln,
                "; Errno(%d): %s", Errno, strerror(Errno) );
    }
    va_end( ArgPt );

    if (Severity <= LogLevel) {
        if (Log2Stderr) {

            print_log_prefix( Severity );
            fprintf(stderr, "%s\n", LogMsg);
        } else if (Severity <= LOG_DEBUG) {
            // we log only known severity levels to syslog
            syslog(Severity, "%s", LogMsg);
        }
    }

    if( Severity <= LOG_ERR ) {
        exit( -1 );
    }
}

void print_log_prefix( int Severity )
{
    const char SeverityVc[][ 6 ] = {
        "EMERG", "ALERT", "CRITI", "ERROR", 
        "Warn ", "Notic", "Info ", "Debug", "Trace", "Init "
    };

    const char *SeverityPt = Severity < 0 || Severity >= (int) VCMC( SeverityVc ) ? 
                       "*****" : SeverityVc[ Severity ];

    struct timeval curTime;
    gettimeofday(&curTime, NULL);
    int milli = curTime.tv_usec / 1000;
    char currentTime[84] = "";
    strftime(currentTime, 84, "%H:%M:%S", localtime(&curTime.tv_sec));

    // now we have something like:
    // [Trace] 14:37,628 
    fprintf(stderr, "[%5s] %s,%03d ", SeverityPt, currentTime, milli);
}
