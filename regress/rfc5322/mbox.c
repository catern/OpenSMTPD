/*
 * Copyright (c) 2017 Eric Faurot <eric@openbsd.org>
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

void msg_new(const char *);
void msg_line(const char *);
void msg_end(void);

void
mbox_parse(char *filename)
{
	FILE *fp;
	char *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;
	int lineno = 0, msg = 0;

	fp = fopen(filename, "r");
	if (fp == NULL)
		err(1, "fopen");

	for (;;) {

		linelen = getline(&line, &linesize, fp);
		if (ferror(fp))
			err(1, "getline");

		if (feof(fp)) {
			if (msg)
				msg_end();
			break;
		}

		lineno++;

		if (line[linelen - 1] == '\n')
			line[linelen - 1] = '\0';

		if (line[0] == 'F' && !strncmp(line, "From ", 5)) {
			if (msg)
				msg_end();
			msg_new(line);
			msg = 1;
			continue;
		}

		if (line[0] == '>' && !strncmp(line, ">From ", 6))
			msg_line(line + 1);
		else
			msg_line(line);
	}

	fclose(fp);
}

void
mail_parse(char *filename)
{
	FILE *fp;
	char *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;
	int lineno = 0;

	fp = fopen(filename, "r");
	if (fp == NULL)
		err(1, "fopen");

	msg_new(filename);

	for (;;) {

		linelen = getline(&line, &linesize, fp);
		if (ferror(fp))
			err(1, "getline");

		if (feof(fp))
			break;

		lineno++;
		if (line[linelen - 1] == '\n')
			line[linelen - 1] = '\0';

		msg_line(line);
	}

	fclose(fp);
	msg_end();
}
