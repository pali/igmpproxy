#!/usr/bin/env python3
"""Compile actual MFC wrappers/update code with an injected kernel syscall."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SOURCE = Path(sys.argv.pop(1))


def function(source, signature):
    start = source.index(signature)
    return source[start:source.index('\n}\n', start) + 3]


class Routes(unittest.TestCase):
    def test_kernel_updates(self):
        route = (SOURCE / 'src/rttable.c').read_text()
        api = (SOURCE / 'src/mroute-api.c').read_text()
        structures = route[route.index('#define MAX_ORIGINS'):route.index('// Keeper for')]
        prelude = r'''
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <linux/mroute.h>
#define IF_STATE_UPSTREAM 1
#define BIT_TST(x,n) ((x) & (1U << (n)))
struct IfDesc { int state, index, threshold; };
struct MRouteDesc { struct in_addr OriginAdr, McAdr; short InVif; uint8_t TtlVc[MAXVIFS]; };
static int MRouterFD = 42, warnings, add_calls, del_calls, add_error, del_error;
static struct IfDesc interfaces[] = {{1, 0, 1}, {2, 1, 1}, {2, 2, 7}};
static struct mfcctl last;
static struct IfDesc *getIfByIx(unsigned index) {
    return index < 3 ? &interfaces[index] : NULL;
}
static char *fmtInAdr(char *buf, struct in_addr a) {
    assert(inet_ntop(AF_INET, &a, buf, 32));
    return buf;
}
static void my_log(int level, int err, const char *fmt, ...) {
    (void)err; (void)fmt;
    if (level == LOG_WARNING) warnings++;
}
static int fake_setsockopt(int fd, int level, int option, const void *value, socklen_t length) {
    assert(fd == MRouterFD && level == IPPROTO_IP && length == sizeof(last));
    assert(option == MRT_ADD_MFC || option == MRT_DEL_MFC);
    memcpy(&last, value, length);
    int error;
    if (option == MRT_ADD_MFC) { add_calls++; error = add_error; }
    else { del_calls++; error = del_error; }
    if (error) { errno = error; return -1; }
    return 0;
}
#define setsockopt fake_setsockopt
'''
        main = r'''
int main(void) {
    struct RouteTable r = {0};
    r.upstrVif = 0;
    r.group = htonl(0xef010101);
    assert(internUpdateKernelRoute(&r, 0) == 1 && del_calls == 0);
    r.originAddrs[0] = htonl(0xc6336401);
    r.originAddrs[1] = htonl(0xc6336402);
    del_error = ENOENT;
    assert(internUpdateKernelRoute(&r, 0) == 1);
    assert(del_calls == 2 && warnings == 0);
    assert(last.mfcc_origin.s_addr == r.originAddrs[1]);
    assert(last.mfcc_mcastgrp.s_addr == r.group && last.mfcc_parent == 0);
    for (unsigned i = 0; i < MAXVIFS; i++) assert(last.mfcc_ttls[i] == 0);
    del_error = 0;
    assert(internUpdateKernelRoute(&r, 0) == 1 && del_calls == 4);
    del_error = EPERM;
    assert(internUpdateKernelRoute(&r, 0) == 0 && del_calls == 6 && warnings == 2);
    del_error = EIO;
    assert(internUpdateKernelRoute(&r, 0) == 0 && del_calls == 8 && warnings == 4);
    r.vifBits = 1U << 2;
    assert(internUpdateKernelRoute(&r, 1) == 1 && add_calls == 2);
    assert(last.mfcc_ttls[0] == 0 && last.mfcc_ttls[1] == 0 && last.mfcc_ttls[2] == 7);
    add_error = EIO;
    assert(internUpdateKernelRoute(&r, 1) == 0 && add_calls == 4 && warnings == 6);
    r.upstrVif = -1;
    assert(internUpdateKernelRoute(&r, 0) == 1 && del_calls == 8);
    return 0;
}
'''
        code = prelude + structures + function(api, 'int addMRoute(') + function(api, 'int delMRoute(')
        code += function(route, 'int internUpdateKernelRoute(struct RouteTable *route, int activate) {') + main
        with tempfile.TemporaryDirectory(prefix='hg-igmp-routes-') as tmp:
            path = Path(tmp)
            (path / 'test.c').write_text(code)
            subprocess.run(['cc', '-std=gnu99', '-Wall', '-Wextra', '-Werror',
                            str(path / 'test.c'), '-o', str(path / 'test')], check=True)
            subprocess.run([str(path / 'test')], check=True)


if __name__ == '__main__':
    unittest.main()
