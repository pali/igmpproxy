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
static struct timeOutQueue  *queue = 0; /* pointer to the beginning of timeout queue */

struct timeOutQueue {
    struct timeOutQueue    *next;   // Next event in queue
    int                     id;
    timer_f                 func;   // function to call
    void                    *data;  // Data for function
    int                     time;   // Time offset for next event
};


/**
 * debugging utility
 */
static void debugQueue(void) {
    struct timeOutQueue  *ptr;

    for (ptr = queue; ptr; ptr = ptr->next) {
        my_log(LOG_DEBUG, 0, "(Id:%d, Time:%d) ", ptr->id, ptr->time);
    }
}

/**
*   Initializes the callout queue
*/
void timer_init(void) {
    queue = NULL;
}

/**
*   Clears all scheduled timeouts...
*/
void timer_destroy(void) {
    struct timeOutQueue *p;

    while (queue) {
        p = queue;
        queue = queue->next;
        free(p);
    }
}


/**
 * elapsed_time seconds have passed; perform all the events that should
 * happen.
 */
void timer_executePassedTimers(int elapsed_time) {
    struct timeOutQueue *ptr;
    struct timeOutQueue *_queue = NULL;
    struct timeOutQueue *last = NULL;
    int i = 0;

    for (ptr = queue; ptr; ptr = ptr->next) {
        if (ptr->time > elapsed_time) {
            ptr->time -= elapsed_time;
            break;
        } else {
            elapsed_time -= ptr->time;
            if (_queue == NULL)
                _queue = ptr;
            last = ptr;
         }
    }

    queue = ptr;
    if (last) {
        last->next = NULL;
    }

    /* process existing events */
    for (ptr = _queue; ptr; ptr = _queue, i++) {
        _queue = _queue->next;
        my_log(LOG_DEBUG, 0, "About to call timeout %d (#%d)", ptr->id, i);
        if (ptr->func)
             ptr->func(ptr->data);
        free(ptr);
    }
}

/**
 * Return in how many seconds age_callout_queue() would like to be called.
 * Return -1 if there are no events pending.
 */
int timer_nextTimer(void) {
    if (queue) {
        if (queue->time < 0) {
            my_log(LOG_WARNING, 0, "timer_nextTimer top of queue says %d", 
                queue->time);
            return 0;
        }
        return queue->time;
    }
    return -1;
}

/**
 *  Inserts a timer in queue.
 *  @param delay - Number of seconds the timeout should happen in.
 *  @param action - The function to call on timeout.
 *  @param data - Pointer to the function data to supply...
 */
int timer_setTimer(int delay, timer_f action, void *data) {
    struct timeOutQueue  *ptr, *node, *prev;
    int i = 0;

    /* create a node */
    node = (struct timeOutQueue *)malloc(sizeof(struct timeOutQueue));
    if (node == 0) {
        my_log(LOG_WARNING, 0, "Malloc Failed in timer_settimer\n");
        return -1;
    }
    node->func = action;
    node->data = data;
    node->time = delay;
    node->next = 0;
    node->id   = ++id;

    prev = ptr = queue;

    /* insert node in the queue */

    /* if the queue is empty, insert the node and return */
    if (!queue) {
        queue = node;
    }
    else {
        /* chase the pointer looking for the right place */
        while (ptr) {
            if (delay < ptr->time) {
                // We found the correct node
                node->next = ptr;
                if (ptr == queue) {
                    queue = node;
                }
                else {
                    prev->next = node;
                }
                ptr->time -= node->time;
                my_log(LOG_DEBUG, 0,
                    "Created timeout %d (#%d) - delay %d secs",
                    node->id, i, node->time);
                debugQueue();
                return node->id;
            } else {
                // Continur to check nodes.
                delay -= ptr->time; node->time = delay;
                prev = ptr;
                ptr = ptr->next;
            }
            i++;
        }
        prev->next = node;
    }
    my_log(LOG_DEBUG, 0, "Created timeout %d (#%d) - delay %d secs",
            node->id, i, node->time);
    debugQueue();

    return node->id;
}