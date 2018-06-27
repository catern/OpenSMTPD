/*
 * Copyright (c) 2016 Eric Faurot <eric@openbsd.org>
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

#include <err.h>
#include <stdio.h>
#include <string.h>

#include "rfc5322.h"

void mbox_parse(char *);
void mail_parse(char *);
void msg_new(const char *);
void msg_line(const char *);
void msg_end(void);
void msg_process(void);

struct rfc5322_parser *parser;

int bufferize = 0;
int mbox = 0;
int verbose = 0;

int
main(int argc, char **argv)
{
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-b"))
			bufferize = 1 - bufferize;
		else if (!strcmp(argv[i], "-m"))
			mbox = 1 - mbox;
		else if (!strcmp(argv[i], "-v"))
			verbose += 1;
		else if (mbox)
			mbox_parse(argv[i]);
		else
			mail_parse(argv[i]);
	}

	return 0;
}

void
msg_new(const char *line)
{
	if (mbox)
		printf("%s\n", line);
	parser = rfc5322_parser_new();
}

void
msg_line(const char *line)
{
	if (rfc5322_push(parser, line) == -1)
		errx(1, "rfc5322_push");
	msg_process();
}

void
msg_end(void)
{
	if (rfc5322_push(parser, NULL) == -1)
		errx(1, "rfc5322_push");
	msg_process();
	rfc5322_free(parser);
}

const char *results[] = {
	"RFC5322_NONE",
	"RFC5322_HEADER_START",
	"RFC5322_HEADER_CONT",
	"RFC5322_HEADER_END",
	"RFC5322_END_OF_HEADERS",
	"RFC5322_BODY_START",
	"RFC5322_BODY",
	"RFC5322_END_OF_MESSAGE"
};

void
msg_process(void)
{
	struct rfc5322_result res;
	int r;

	for(;;) {
		r = rfc5322_next(parser, &res);
		if (r == -1) {
			err(1, "parse error");
			return;
		}

		if (verbose)
			printf("%s\n", results[r]);

		switch (r) {
		case RFC5322_NONE:
			return;

		case RFC5322_HEADER_START:
			if (bufferize) {
				if (rfc5322_bufferize_header(parser) == -1)
					err(1, "rfc5322_bufferize_header");
			}
			else
				printf("%s:%s\n", res.hdr, res.value);
			break;

		case RFC5322_HEADER_CONT:
			if (bufferize)
				;
			else
				printf("%s\n", res.value);
			break;

		case RFC5322_HEADER_END:
			if (res.value)
				printf("%s:%s\n", res.hdr, res.value);
			break;

		case RFC5322_END_OF_HEADERS:
			break;

		case RFC5322_BODY_START:
		case RFC5322_BODY:
			if (mbox && !strncmp(res.value, "From ", 5))
				putchar('>');
			printf("%s\n", res.value);
			break;

		case RFC5322_END_OF_MESSAGE:
			return;

		default:
			errx(1, "rfc5322_next");
		}
	}
}
