# $Id: Makefile,v 1.4 2005/08/18 07:29:29 luca Exp $

CC?=		cc
CFLAGS?=	-Wall -O2 -D${WITH_IPV6}=YES
PREFIX?=	/usr/local

VER=		1.1

.ifdef WITH_IPV6
IPV6=-DWITH_IPV6
.endif

tinystats: tinystats.c
	${CC} ${CFLAGS} ${IPV6} -o tinystats tinystats.c

install: tinystats
	cp tinystats ${PREFIX}/bin

strip: install
	strip ${PREFIX}/bin/tinystats

clean:
	rm -f *~ *.core

clean-all: clean
	rm -f tinystats

tar: clean-all
	tar -zcf ../tinystats-${VER}.tar.gz -C .. --exclude CVS --exclude html tinystats
