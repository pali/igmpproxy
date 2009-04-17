AC_PREREQ([2.63])
AC_INIT([igmpproxy], [0.1-beta2], [johnnyege@users.sourceforge.net])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_SRCDIR([src/igmpproxy.c])
AC_CONFIG_HEADERS([config.h])
AC_PROG_CC_C99
AC_CHECK_MEMBERS([struct sockaddr.sa_len], [], [], [[#include <sys/socket.h>]])
AC_CONFIG_FILES([Makefile doc/Makefile src/Makefile])
AC_OUTPUT
