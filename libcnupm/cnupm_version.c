/*	$RuOBSD: cnupm_version.c,v 1.1 2004/04/19 12:53:43 form Exp $	*/

/*
 * Copyright (c) 2004 Oleg Safiullin <form@pdp-11.org.ru>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#include "cnupm.h"

void
cnupm_version(int pcap)
{
#ifdef CNUPM_VERSION_PATCH
	(void)printf("%s v%u.%u.%u", __progname, CNUPM_VERSION_MAJOR,
	    CNUPM_VERSION_MINOR, CNUPM_VERSION_PATCH);
#else
	(void)printf("%s v%u.%u", __progname, CNUPM_VERSION_MAJOR,
	    CNUPM_VERSION_MINOR);
#endif
	if (pcap)
		(void)printf(", pcap v%u.%u\n", PCAP_VERSION_MAJOR,
		    PCAP_VERSION_MINOR);
	else
		(void)printf("\n");
	exit(0);
}
