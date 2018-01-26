/*	$OpenBSD: rfc5322.c,v 1.7 2016/02/04 22:35:17 eric Exp $	*/

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

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "rfc5322.h"

struct buf {
	char	*buf;
	size_t	 bufsz;
	size_t	 buflen;
	size_t	 bufmax;
};

static int buf_alloc(struct buf *, size_t);
static int buf_grow(struct buf *, size_t);
static int buf_cat(struct buf *, const char *);

struct rfc5322_msg_ctx {
	const char	*line;

	int		 in_msg;
	int		 in_hdrs;
	int		 in_hdr;

	int		 next;

	const char	*currhdr;
	int		 bufferize;

	struct buf	 hdr;
	struct buf	 val;
};

struct rfc5322_msg_ctx *
rfc5322_msg_new(void)
{
	struct rfc5322_msg_ctx *ctx;

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL)
		return NULL;

	rfc5322_msg_clear(ctx);
	ctx->hdr.bufmax = 1024;
	ctx->val.bufmax = 65536;

	return ctx;
}

void
rfc5322_msg_free(struct rfc5322_msg_ctx *ctx)
{
	free(ctx->hdr.buf);
	free(ctx->val.buf);
	free(ctx);
}

void
rfc5322_msg_clear(struct rfc5322_msg_ctx *ctx)
{
	ctx->line = NULL;
	ctx->in_msg = 1;
	ctx->in_hdrs = 1;
	ctx->in_hdr = 0;
	ctx->next = 0;
}

int
rfc5322_msg_push(struct rfc5322_msg_ctx *ctx, const char *line)
{
	if (ctx->line)
		return -1;
	ctx->line = line;
	return 0;
}

int
rfc5322_msg_bufferize_header(struct rfc5322_msg_ctx *ctx)
{
	if (ctx->bufferize)
		return -1;

	if (ctx->currhdr == NULL)
		return -1;

	if (buf_cat(&ctx->val, ctx->currhdr) == -1)
		return -1;

	ctx->bufferize = 1;

	return 0;
}

int
rfc5322_msg_next(struct rfc5322_msg_ctx *ctx, struct rfc5322_msg_result *res)
{
	size_t len;
	const char *pos, *line;

	memset(res, 0, sizeof(*res));

	ctx->currhdr = NULL;

	if (ctx->next) {
		ctx->next = 0;
		return RFC5322_MSG_NONE;
	}

	if (!ctx->in_msg) {
		res->error = "end of message";
		return -1;
	}

	line = ctx->line;

	if (ctx->in_hdr) {
		/* Check for folded header */
		if (line && (line[0] == ' ' || line[0] == '\t')) {
			/* header continuation */
			ctx->line = NULL;
			ctx->next = 1;
			res->hdr = ctx->hdr.buf;
			res->value = line;
			if (ctx->bufferize) {
				if (buf_cat(&ctx->val, "\n") == -1 ||
				    buf_cat(&ctx->val, line) == -1) {
					res->error = "out of memory";
					return -1;
				}
			}
			return RFC5322_MSG_HDR_CONT;
		}

		ctx->in_hdr = 0;
		res->hdr = ctx->hdr.buf;
		if (ctx->bufferize) {
			res->value = ctx->val.buf;
			ctx->val.buflen = 0;
			ctx->bufferize = 0;
		}
		return RFC5322_MSG_HDR_END;
	}

	if (ctx->in_hdrs) {
		/* Check for new header */
		if (line && (pos = strchr(line, ':'))) {
			len = pos - line;
			if (buf_grow(&ctx->hdr, len + 1) == -1) {
				res->error = "out of memory";
				return -1;
			}
			(void)memcpy(ctx->hdr.buf, line, len);
			ctx->hdr.buf[len] = '\0';
			ctx->hdr.buflen = len + 1;
			ctx->in_hdr = 1;
			ctx->line = NULL;
			ctx->next = 1;
			ctx->currhdr = pos + 1;
			res->hdr = ctx->hdr.buf;
			res->value = pos + 1;
			return RFC5322_MSG_HDR;
		}

		ctx->in_hdrs = 0;
		return RFC5322_MSG_HDRS_END;
	}

	if (line) {
		ctx->line = NULL;
		ctx->next = 1;
		res->value = line;
		return RFC5322_MSG_BODY;
	}

	ctx->in_msg = 0;
	ctx->next = 1;
	return RFC5322_MSG_END;
}

static int
buf_alloc(struct buf *b, size_t need)
{
	char *buf;
	size_t alloc;

	if (b->buf && b->bufsz >= need)
		return 0;

	if (need >= b->bufmax) {
		errno = ERANGE;
		return -1;
	}

#define N 256
	alloc = N * (need / N) + ((need % N) ? N : 0);
#undef N
	buf = reallocarray(b->buf, alloc, 1);
	if (buf == NULL)
		return -1;

	b->buf = buf;
	b->bufsz = alloc;

	return 0;
}

static int
buf_grow(struct buf *b, size_t sz)
{
	if (SIZE_T_MAX - b->buflen <= sz) {
		errno = ERANGE;
		return -1;
	}

	return buf_alloc(b, b->buflen + sz);
}

static int
buf_cat(struct buf *b, const char *s)
{
	size_t len = strlen(s);

	if (buf_grow(b, len + 1) == -1)
		return -1;

	(void)memmove(b->buf + b->buflen, s, len + 1);
	b->buflen += len;
	return 0;
}
