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
*   confread.c
*
*   Generic config file reader. Used to open a config file,
*   and read the tokens from it. The parser is really simple,
*   and does no backlogging. This means that no form of
*   text escaping and qouting is currently supported.
*   '#' chars are read as comments, and the comment lasts until
*   a newline or EOF
*
*/

#include "igmpproxy.h"

#define READ_BUFFER_SIZE    512     // Inputbuffer size...
#define MAX_TOKEN_LENGTH    30

static struct {
    FILE            *confFilePtr;       // File handle pointer
    char            *iBuffer;           // Inputbuffer for reading...
    unsigned int    bufPtr;             // Buffer position pointer.
    unsigned int    readSize;           // Number of bytes in buffer after last read...
    char    cToken[MAX_TOKEN_LENGTH];   // Token buffer...
    short   validToken;
} conf;

/**
*   Opens config file specified by filename.
*/
int openConfigFile(char *filename) {

    // Set the buffer to null initially...
    conf.iBuffer = NULL;

    // Open the file for reading...
    conf.confFilePtr = fopen(filename, "r");

    // On error, return false
    if(conf.confFilePtr == NULL) {
        return 0;
    }

    // Allocate memory for inputbuffer...
    conf.iBuffer = (char*) malloc( sizeof(char) * READ_BUFFER_SIZE );

    if(conf.iBuffer == NULL) {
        closeConfigFile();
        return 0;
    }

    // Reset bufferpointer and readsize
    conf.bufPtr = 0;
    conf.readSize = 0;

    return 1;
}

/**
*   Closes the currently open config file.
*/
void closeConfigFile(void) {
    // Close the file.
    if(conf.confFilePtr != NULL) {
        fclose(conf.confFilePtr);
    }
    // Free input buffer memory...
    if(conf.iBuffer != NULL) {
        free(conf.iBuffer);
    }
}

/**
*   Returns the next token from the configfile. The function
*   return NULL if there are no more tokens in the file.
*/
char *nextConfigToken(void) {

    conf.validToken = 0;

    // If no file or buffer, return NULL
    if(conf.confFilePtr == NULL || conf.iBuffer == NULL) {
        return NULL;
    }

    {
        unsigned int tokenPtr       = 0;
        unsigned short finished     = 0;
        unsigned short commentFound = 0;

        // Outer buffer fill loop...
        while ( !finished ) {
            // If readpointer is at the end of the buffer, we should read next chunk...
            if(conf.bufPtr == conf.readSize) {
                // Fill up the buffer...
                conf.readSize = fread (conf.iBuffer, sizeof(char), READ_BUFFER_SIZE, conf.confFilePtr);
                conf.bufPtr = 0;

                // If the readsize is 0, we should just return...
                if(conf.readSize == 0) {
                    return NULL;
                }
            }

            // Inner char loop...
            while ( conf.bufPtr < conf.readSize && !finished ) {

                //printf("Char %s", iBuffer[bufPtr]);

                // Break loop on \0
                if(conf.iBuffer[conf.bufPtr] == '\0') {
                    break;
                }

                if( commentFound ) {
                    if( conf.iBuffer[conf.bufPtr] == '\n' ) {
                        commentFound = 0;
                    }
                } else {

                    // Check current char...
                    switch(conf.iBuffer[conf.bufPtr]) {
                    case '#':
                        // Found a comment start...
                        commentFound = 1;
                        break;

                    case '\n':
                    case '\r':
                    case '\t':
                    case ' ':
                        // Newline, CR, Tab and space are end of token, or ignored.
                        if(tokenPtr > 0) {
                            conf.cToken[tokenPtr] = '\0';    // EOL
                            finished = 1;
                        }
                        break;

                    default:
                        // Append char to token...
                        conf.cToken[tokenPtr++] = conf.iBuffer[conf.bufPtr];
                        break;
                    }
                }

                // Check end of token buffer !!!
                if(tokenPtr == MAX_TOKEN_LENGTH - 1) {
                    // Prevent buffer overrun...
                    conf.cToken[tokenPtr] = '\0';
                    finished = 1;
                }

                // Next char...
                conf.bufPtr++;
            }
            // If the readsize is less than buffersize, we assume EOF.
            if(conf.readSize < READ_BUFFER_SIZE && conf.bufPtr == conf.readSize) {
                if (tokenPtr > 0)
                    finished = 1;
                else
                    return NULL;
            }
        }
        if(tokenPtr>0) {
            conf.validToken = 1;
            return conf.cToken;
        }
    }
    return NULL;
}


/**
*   Returns the currently active token, or null
*   if no tokens are available.
*/
char *getCurrentConfigToken(void) {
    return conf.validToken ? conf.cToken : NULL;
}
