# $RuOBSD: GNUmakefile,v 1.2 2004/04/22 03:17:58 form Exp $

LIB=	cnupm
SRCS=	cnupm_daemon.c cnupm_family.c cnupm_pidfile.c cnupm_progname.c
SRCS+=	cnupm_protocol.c cnupm_restrict.c cnupm_ulval.c cnupm_version.c

include ../GNUosdefs.inc

ifeq "$(OS)" "Linux"
SRCS+=	setproctitle.c strlcat.c strlcpy.c
endif

ifeq "$(OS)" "QNX"
SRCS+=	setproctitle.c strlcat.c strlcpy.c
endif

ifeq "$(OS)" "SunOS"
SRCS+=	err.c errx.c inet_ntop.c setproctitle.c strlcat.c strlcpy.c
SRCS+=	warn.c warnx.c
endif

include ../GNUmakefile.inc
