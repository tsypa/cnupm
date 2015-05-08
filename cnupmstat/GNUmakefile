# $RuOBSD: GNUmakefile,v 1.3 2004/04/22 03:17:57 form Exp $

PROG=	cnupmstat
MAN=	cnupmstat.8

COPTS=	-Wno-format
LDADD=	-L../libcnupm -lcnupm

include ../GNUosdefs.inc

ifeq "$(OS)" "QNX"
LDADD+=	-lsocket
endif

ifeq "$(OS)" "SunOS"
LDADD+=	-lsocket
endif

include ../GNUmakefile.inc
