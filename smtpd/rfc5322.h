/*	$OpenBSD: rfc5322.h,v 1.4 2015/11/05 08:55:09 gilles Exp $	*/

/*
 * Copyright (c) 2018 Eric Faurot <eric@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

struct rfc5322_msg_result {
	const char	*error;
	const char	*hdr;
	const char	*value;
};

#define	RFC5322_MSG_ERR		-1
#define	RFC5322_MSG_NONE	0
#define	RFC5322_MSG_HDR		1
#define	RFC5322_MSG_HDR_CONT	2
#define	RFC5322_MSG_HDR_END	3
#define	RFC5322_MSG_HDRS_END	4
#define	RFC5322_MSG_BODY	5
#define	RFC5322_MSG_END		6

struct rfc5322_msg_ctx;

struct rfc5322_msg_ctx *rfc5322_msg_new(void);
void rfc5322_msg_free(struct rfc5322_msg_ctx *);
void rfc5322_msg_clear(struct rfc5322_msg_ctx *);
int rfc5322_msg_push(struct rfc5322_msg_ctx *, const char *);
int rfc5322_msg_next(struct rfc5322_msg_ctx *, struct rfc5322_msg_result *);
int rfc5322_msg_bufferize_header(struct rfc5322_msg_ctx *);
