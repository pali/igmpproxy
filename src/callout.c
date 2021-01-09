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
static unsigned long id = 1;
static struct timeOutQueue  *queue = NULL;

struct timeOutQueue {
    unsigned long           id;
    char                    name[32];   // name of the timer
    timer_f                 func;       // function to call
    void                   *data;       // Argument for function.
    struct timespec         time;       // Time for event
    struct timeOutQueue    *next;       // Next event in queue
};

// Method for dumping the Queue to the log.
static void debugQueue(void);

/**
*   Clears all scheduled timeouts...
*/
void timer_freeQueue(void) {
    struct timeOutQueue *p;

    for (p = queue; queue; queue = p) {
        p = p->next;
        free(queue);        // Alloced by timer_setTimer()
    }
    my_log(LOG_DEBUG, 0, "timer_freeQueue: All Timeouts removed, Queue is empty.");
}

/**
*   Execute all expired timers, return ns until next timer if scheduled in less than 1s.
*/
unsigned int timer_ageQueue() {
    struct timeOutQueue *ptr;
    unsigned long i = 1;

    for (ptr = queue; ptr && ((curtime.tv_sec > ptr->time.tv_sec) || (curtime.tv_sec == ptr->time.tv_sec && curtime.tv_nsec > ptr->time.tv_nsec)); ptr = queue) {
        my_log(LOG_DEBUG, 0, "About to call timeout %d (#%d) - %s - Missed by %dus", ptr->id, i++, ptr->name, (ptr->time.tv_nsec > curtime.tv_nsec ? 1000000000 - ptr->time.tv_nsec + curtime.tv_nsec: curtime.tv_nsec - ptr->time.tv_nsec) / 1000);
        ptr->func(ptr->data);
        queue = ptr->next;
        free(ptr);     // Alloced by timer_setTimer()
        debugQueue();
    }

    diftime.tv_sec  = curtime.tv_nsec > queue->time.tv_nsec ? queue->time.tv_sec - curtime.tv_sec - 1 : queue->time.tv_sec - curtime.tv_sec;
    diftime.tv_nsec = curtime.tv_nsec > queue->time.tv_nsec ? 1000000000 - curtime.tv_nsec + queue->time.tv_nsec: queue->time.tv_nsec - curtime.tv_nsec;
    return diftime.tv_sec == 0 ? diftime.tv_nsec : 0;
}

/**
*   Inserts a timer in queue.
*   @param delay - Number of seconds the timeout should happen in.
*   @param name - Name for the timer.
*   @param action - The function to call on timeout.
*   @param data - Pointer to the function data to supply.
*/
unsigned int timer_setTimer(int delay, const char *name, timer_f action, void *data) {
    struct timeOutQueue  *ptr = queue, *node;
    unsigned long i = 1;

    node = (struct timeOutQueue *)malloc(sizeof(struct timeOutQueue));  // Freed by timer_freeQueue(), timer_ageQueue() or timer_clearTimer()
    if (! node) {
        my_log(LOG_ERR, 0, "timer_setTimer: Out of memory.");
    }
    clock_gettime(CLOCK_MONOTONIC, &curtime);
    strcpy(node->name, name);
    node->func = action;
    node->data = data;
    node->time.tv_sec = curtime.tv_sec + delay;
    node->time.tv_nsec = curtime.tv_nsec;
    node->id   = id++;
    node->next = NULL;

    if (! queue) {
        // if the queue is empty, insert the node and return.
        queue = node;
    } else {
        // chase the queue looking for the right place. 
        for (i++; ptr->next && (node->time.tv_sec > ptr->next->time.tv_sec ||
                               (node->time.tv_sec == ptr->next->time.tv_sec && node->time.tv_nsec >= ptr->next->time.tv_nsec)); ptr = ptr->next, i++);
        if (ptr == queue && (node->time.tv_sec < ptr->time.tv_sec || (node->time.tv_sec == ptr->time.tv_sec && node->time.tv_nsec < ptr->time.tv_nsec))) {
           // Start of queue, insert.
           i--;
           queue = node;
           node->next = ptr;
        } else {
           node->next = ptr->next;
           ptr->next = node;
        }
    }

    debugQueue();
    my_log(LOG_DEBUG, 0, "Created timeout %d (#%d): %s - delay %d secs", node->id, i, node->name, delay);
    return node->id;
}

/**
*   Removes a timer from the queue.
*/
void *timer_clearTimer(unsigned long timer_id) {
    struct timeOutQueue *ptr = NULL, *fptr = NULL;
    void *data = NULL;
    unsigned long i = 1;

    if (queue->id == timer_id) {
        fptr = queue;
        queue = queue->next;
    } else {
        for (i++, ptr = queue; ptr->next && ptr->next->id != timer_id; ptr = ptr->next, i++);
        fptr = ptr->next;
        ptr->next = ptr->next ? ptr->next->next : NULL;
    }
    if (fptr) {
        clock_gettime(CLOCK_MONOTONIC, &curtime);
        debugQueue();
        my_log(LOG_DEBUG, 0, "Removed timeout %d (#%d): %s", i, fptr->id, fptr->name);
        data = fptr->data;
        free(fptr);        // Alloced by timer_setTimer()
    }

    // Return pointer to the cleared timer's data, the caller may need it.
    return data;
}

/**
*   Returns the time until the timer is scheduled (-1 if timer not found).
*/
struct timespec timer_getTime(unsigned long timer_id) {
    struct timeOutQueue *ptr;
    for (ptr = queue; ptr && ptr->id != timer_id; ptr = ptr->next);
    return ptr ? ptr->time : (struct timespec){ -1, -1 };
}

/**
*   Debugging utility
*/
static void debugQueue() {
    struct timeOutQueue  *ptr;
    unsigned long i;

    for (i = 1, ptr = queue; ptr; ptr = ptr->next, i++) {
        my_log(LOG_DEBUG, 0, "%d [%4ds] - Id:%6d - %s", i, ptr->time.tv_sec - curtime.tv_sec, ptr->id, ptr->name);
    }
}
