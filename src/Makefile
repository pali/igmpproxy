
#BINDIR=../bin
BINDIR=/usr/local/bin
ETCDIR=/etc
MANDIR=/usr/share/man


# CFLAGS=-g
CFLAGS=-O

default : build.h igmpproxy

all	: igmpproxy

clean	:
	rm -f *.o *.asm build.h igmpproxy  

install : 
	cp igmpproxy ${BINDIR}
	cp ../doc/igmpproxy.8 ${MANDIR}/man8
	cp ../doc/igmpproxy.conf.5 ${MANDIR}/man5
	if [ ! -e ${ETCDIR}/igmpproxy.conf ]; then cp igmpproxy.conf ${ETCDIR}; fi

igmpproxy : igmpproxy.o config.o confread.o request.o udpsock.o mcgroup.o rttable.o \
			igmp.o ifvc.o callout.o kern.o syslog.o lib.o mroute-api.o

build.h	:  
	echo '#define BUILD "' `date +%y%m%d` '"' >build.h


