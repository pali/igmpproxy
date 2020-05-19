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

/* the code below implements a callout queue */
static int id = 0;
static struct timeOutQueue  *queue = NULL; /* pointer to the beginning of timeout queue */

struct timeOutQueue {
    int                     id;
    timer_f                 func;   // function to call
    void                    *data;  // Data for function
    long                    time;   // Time for event
    struct timeOutQueue     *next;  // Next event in queue
};

// Method for dumping the Queue to the log.
static void debugQueue(void);

/**
*   Clears all scheduled timeouts...
*/
void free_all_callouts(void) {
    struct timeOutQueue *p;

    for (p = queue ? queue->next : NULL; queue; queue = p, p = queue->next) {
        free(queue);   // Alloced by timer_setTimer()
    }
}

/**
 *  Execute all expired timers, using .5s grace.
 */
void age_callout_queue(struct timespec curtime) {
    struct timeOutQueue *ptr = queue;
    int i = 1;
 
    if (curtime.tv_sec == 0) clock_gettime (CLOCK_MONOTONIC, &curtime);
    while (ptr && ((ptr->time <= curtime.tv_sec) || (curtime.tv_nsec >= 500000000 && ptr->time <= curtime.tv_sec-1))) {
        my_log(LOG_DEBUG, 0, "About to call timeout %d (#%d)", ptr->id, i);
        struct timeOutQueue *tmp = ptr;
        if (ptr->func) {
            ptr->func(ptr->data);
        }
        queue = ptr = ptr->next;
        free(tmp);  // Alloced by timer_setTimer()
        i++;
    }
}

/**
 *  Inserts a timer in queue.
 *  @param delay - Number of seconds the timeout should happen in.
 *  @param action - The function to call on timeout.
 *  @param data - Pointer to the function data to supply...
 */
int timer_setTimer(int delay, timer_f action, void *data) {
    struct timeOutQueue  *ptr = queue, *node;
    struct timespec curtime;
    int i = 1;

    // create a node. Freed by free_all_callouts() and age_callout_queue().
    node = (struct timeOutQueue *)malloc(sizeof(struct timeOutQueue));
    if (! node) {
        my_log(LOG_WARNING, 0, "Malloc Failed in timer_settimer\n");
        return -1;
    }
    clock_gettime(CLOCK_MONOTONIC, &curtime);   
    node->func = action;
    node->data = data;
    node->time = curtime.tv_sec + delay;
    node->id   = ++id;

    if (! queue) {
        // if the queue is empty, insert the node and return.
        queue = node;
    } else {
        // chase the queue looking for the right place. 
        for (i++; ptr->next && node->time >= ptr->next->time; ptr = ptr->next, i++);
        if (ptr == queue && node->time < ptr->time) {
           // Start of queue, insert.
           queue = node;
           node->next = ptr;
        } else {
           node->next = ptr->next;
           ptr->next = node;
        }
    }
    debugQueue();
    my_log(LOG_DEBUG, 0, "Created timeout %d (#%d) - delay %d secs", node->id, i, delay);
    return node->id;
}

/**
*   returns the time until the timer is scheduled
*/
int timer_leftTimer(int timer_id) {
    struct timeOutQueue *ptr;
    struct timespec curtime;

    if (!timer_id || !queue) return -1;
    for (ptr = queue; ptr; ptr = ptr->next) {
        if (ptr->id == timer_id) {
            clock_gettime(CLOCK_MONOTONIC, &curtime);
            return (ptr->time - curtime.tv_sec);
        }
    }
    return -1;
}

/**
 * debugging utility
 */
static void debugQueue(void) {
    struct timeOutQueue  *ptr; 
    int i;

    for (i = 1, ptr = queue; ptr; ptr = ptr->next, i++) {
        my_log(LOG_DEBUG, 0, "(%d - Id:%d, Time:%d) ", i, ptr->id, ptr->time);
    }
}
