.PATH: ../../smtpd

PROGS=	dup

SRCS_dup=	dup.c mbox.c rfc5322.c

CPPFLAGS=       -I../../smtpd
CFLAGS=         -Wall -W

NOMAN=          noman

test:
	sh regress.sh

.include <bsd.prog.mk>
