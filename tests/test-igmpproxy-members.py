#!/usr/bin/env python3
"""Compile real insertRoute/bitmap code against host-only routing stubs."""
import pathlib
import subprocess
import sys
import tempfile
import unittest

SOURCE = pathlib.Path(sys.argv.pop(1))


class Members(unittest.TestCase):
    def test_report_order_and_leave(self):
        source = (SOURCE / 'src/rttable.c').read_text()
        structures = source[source.index('#define MAX_ORIGINS'):source.index('/**\n*   Initializes')]
        insert = source[source.index('int insertRoute('):source.index('/**\n*   Activates a passive')]
        prelude = r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <syslog.h>
#define BIT_SET(x,n) ((x) |= 1U << (n))
#define BIT_CLR(x,n) ((x) &= ~(1U << (n)))
#define BIT_ZERO(x) ((x) = 0)
#define MAXVIFS 32
#define ROUTESTATE_NOTJOINED 0
#define ROUTESTATE_JOINED 1
#define my_log(...) ((void)0)
struct Config { unsigned int fastUpstreamLeave, downstreamHostsHashTableSize, robustnessValue; };
static struct Config conf = {1, 32, 2};
static struct Config *getCommonConfig(void) { return &conf; }
'''
        stubs = r'''
static struct RouteTable *findRoute(uint32_t group) {
    for (struct RouteTable *r = routing_table; r; r = r->nextroute)
        if (r->group == group) return r;
    return NULL;
}
int internUpdateKernelRoute(struct RouteTable *r, int active) { (void)r; (void)active; return 1; }
void logRouteTable(const char *s) { (void)s; }
static void sendJoinLeaveUpstream(struct RouteTable *r, int join) {
    if (r->vifBits) r->upstrState = join;
}
'''
        main = r'''
int main(void) {
    uint32_t g = htonl(0xef010101), a = 1, b = 2;
    assert(insertRoute(g, -1, 0));
    struct RouteTable *r = findRoute(g);
    assert(testNoDownstreamHost(&conf, r) && !r->vifBits && !r->upstrState);
    assert(insertRoute(g, 1, a));
    assert(!testNoDownstreamHost(&conf, r));
    clearDownstreamHost(&conf, r, a);
    assert(testNoDownstreamHost(&conf, r));
    assert(insertRoute(g, 1, a));
    /* Pick a distinct bitmap slot; hash collisions are an existing limitation. */
    while (murmurhash3(a ^ r->downstreamHostsHashSeed) % 256 ==
           murmurhash3(b ^ r->downstreamHostsHashSeed) % 256) b++;
    assert(insertRoute(g, 1, b));
    clearDownstreamHost(&conf, r, a);
    assert(!testNoDownstreamHost(&conf, r));
    clearDownstreamHost(&conf, r, b);
    assert(testNoDownstreamHost(&conf, r));
    assert(insertRoute(g + htonl(1), 1, a));
    r = findRoute(g + htonl(1));
    assert(!testNoDownstreamHost(&conf, r));
    assert(insertRoute(g + htonl(1), -1, 0));
    clearDownstreamHost(&conf, r, a);
    assert(testNoDownstreamHost(&conf, r));
    /* Zero source in an actual downstream report must not be suppressed. */
    assert(insertRoute(g + htonl(2), 1, 0));
    assert(!testNoDownstreamHost(&conf, findRoute(g + htonl(2))));
    conf.fastUpstreamLeave = 0;
    assert(insertRoute(g + htonl(3), -1, 0));
    assert(insertRoute(g + htonl(3), 1, a));
    while (routing_table) {
        r = routing_table; routing_table = r->nextroute; free(r);
    }
    return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='hg-igmp-members-') as tmp:
            path = pathlib.Path(tmp)
            (path / 'test.c').write_text(prelude + structures + stubs + insert + main)
            subprocess.run(['cc', '-std=gnu99', '-Wall', '-Wextra', '-Werror',
                            str(path / 'test.c'), '-o', str(path / 'test')], check=True)
            subprocess.run([str(path / 'test')], check=True)


if __name__ == '__main__':
    unittest.main()
