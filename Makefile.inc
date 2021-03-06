# $RuOBSD: Makefile.inc,v 1.5 2004/04/20 03:42:35 form Exp $

CFLAGS+=-Wall -Werror -Wmissing-prototypes -Wstrict-prototypes -Winline
CFLAGS+=-Wshadow -Wpointer-arith -Wmissing-declarations -Wno-long-long
CFLAGS+=-Wno-format
CFLAGS+=-I${.CURDIR}/../include

BINDIR?=/usr/local/sbin

.if ${OS} == FreeBSD
MANDIR?=/usr/local/man/man
.endif

.if ${OS} == NetBSD
MANDIR?=/usr/local/man
.endif

.if ${OS} == OpenBSD
MANDIR?=/usr/local/man/cat
.endif

