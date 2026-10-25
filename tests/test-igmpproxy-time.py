#!/usr/bin/env python3
"""Host tests of patched IGMPproxy timekeeping and its real callout queue.

Pass a prepared igmpproxy source directory. No network/device access is used.
"""
import pathlib
import subprocess
import sys
import tempfile
import unittest

SOURCE = pathlib.Path(sys.argv.pop(1))


class CalloutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='hg-igmp-time-')
        cls.root = pathlib.Path(cls.tmp.name)
        source = (SOURCE / 'src/igmpproxy.c').read_text()
        helpers = source.split('static void ageCallouts(', 1)[1]
        helpers = 'static void ageCallouts(' + helpers.split('/**', 1)[0]
        callout = (SOURCE / 'src/callout.c').read_text().replace(
            '#include "igmpproxy.h"', '')
        prelude = r'''
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
typedef void (*timer_f)(void *);
static struct timespec fake_now;
static int fired;
static void my_log(int level, int err, const char *format, ...) {
    (void)err; (void)format;
    assert(level != LOG_ERR);
}
static int fake_clock_gettime(clockid_t id, struct timespec *now) {
    assert(id == CLOCK_MONOTONIC);
    *now = fake_now;
    return 0;
}
#define clock_gettime fake_clock_gettime
'''
        main = r'''
static void fire(void *data) { (void)data; fired++; }
static void slow_fire(void *data) {
    (void)data;
    fired++;
    fake_now.tv_sec += 2;
}
int main(int argc, char **argv) {
    struct timespec last = {0}, tv;
    long remainder = 0;
    assert(argc == 2);
    callout_init();
    if (!strcmp(argv[1], "short-wait")) {
        timer_setTimer(100, fire, NULL);
        assert(nextTimeout(&tv, 1, 0)->tv_sec == 3);
        fake_now.tv_sec = 3;
        ageCallouts(&last, &remainder);
        assert(!fired && timer_nextTimer() == 97);
    } else if (!strcmp(argv[1], "deadline")) {
        timer_setTimer(125, fire, NULL);
        assert(nextTimeout(&tv, 0, 0)->tv_sec == 125);
        fake_now.tv_sec = 124;
        ageCallouts(&last, &remainder);
        assert(!fired && timer_nextTimer() == 1);
        fake_now.tv_sec++;
        ageCallouts(&last, &remainder);
        assert(fired == 1 && timer_nextTimer() == -1);
    } else if (!strcmp(argv[1], "carry")) {
        timer_setTimer(10, fire, NULL);
        last.tv_nsec = 900000000;
        fake_now = (struct timespec){1, 100000000};
        ageCallouts(&last, &remainder);
        assert(remainder == 200000000 && timer_nextTimer() == 10);
        fake_now.tv_nsec = 900000000;
        ageCallouts(&last, &remainder);
        assert(remainder == 0 && timer_nextTimer() == 9);
        nextTimeout(&tv, 0, 250000000);
        assert(tv.tv_sec == 8 && tv.tv_nsec == 750000000);
    } else if (!strcmp(argv[1], "empty-refill")) {
        assert(nextTimeout(&tv, 0, 0) == NULL);
        assert(nextTimeout(&tv, 1, 0)->tv_sec == 3);
        timer_setTimer(2, fire, NULL);
        assert(nextTimeout(&tv, 0, 0) == &tv && tv.tv_sec == 2);
    } else if (!strcmp(argv[1], "zero")) {
        timer_setTimer(0, fire, NULL);
        assert(nextTimeout(&tv, 0, 750000000)->tv_sec == 0);
        assert(tv.tv_nsec == 0);
        ageCallouts(&last, &remainder);
        assert(fired == 1);
    } else if (!strcmp(argv[1], "new-timer")) {
        fake_now.tv_sec = 100;
        ageCallouts(&last, &remainder);
        timer_setTimer(10, fire, NULL);
        ageCallouts(&last, &remainder);
        assert(timer_nextTimer() == 10 && !fired);
        fake_now.tv_sec = 109;
        ageCallouts(&last, &remainder);
        assert(!fired);
        fake_now.tv_sec++;
        ageCallouts(&last, &remainder);
        assert(fired == 1);
    } else if (!strcmp(argv[1], "callback-time")) {
        timer_setTimer(1, slow_fire, NULL);
        timer_setTimer(3, fire, NULL);
        fake_now.tv_sec = 1;
        ageCallouts(&last, &remainder);
        assert(fired == 2 && last.tv_sec == 3);
    } else {
        assert(0);
    }
    free_all_callouts();
    return 0;
}
'''
        c = cls.root / 'test.c'
        c.write_text(prelude + callout + helpers + main)
        cls.binary = cls.root / 'test'
        subprocess.run(['cc', '-std=gnu99', '-Wall', '-Wextra', '-Werror',
                        str(c), '-o', str(cls.binary)], check=True)
        cls.source = source

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_timekeeping(self):
        for case in ('short-wait', 'deadline', 'carry', 'empty-refill',
                     'zero', 'new-timer', 'callback-time'):
            with self.subTest(case=case):
                subprocess.run([str(self.binary), case], check=True)

    def test_main_loop_order(self):
        loop = self.source.split('void igmpProxyRun(void)', 1)[1]
        waited = loop.split('Rt = pselect(', 1)[1]
        self.assertLess(waited.index('ageCallouts(&lasttime, &remainder)'),
                        waited.index('acceptIgmp(recvlen)'))
        self.assertLess(waited.index('ageCallouts(&lasttime, &remainder)'),
                        waited.index('if( Rt < 0 )'))
        self.assertIn('nextTimeout(&tv, config->rescanVif, remainder)', loop)
        self.assertNotIn('lasttime.tv_sec + secs', loop)


if __name__ == '__main__':
    unittest.main()
