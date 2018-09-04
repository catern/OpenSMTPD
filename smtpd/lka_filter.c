/*	$OpenBSD$	*/

/*
 * Copyright (c) 2018 Gilles Chehade <gilles@poolp.org>
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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include "smtpd.h"
#include "log.h"

static void	lka_filter_proceed(uint64_t reqid, int cmd, const char *param);
static void	lka_filter_reject(uint64_t reqid, int cmd, const char *message);
static int	lka_filter_execute(struct filter_rule *rule, uint64_t reqid, int cmd, const char *param);


void
lka_filter(uint64_t reqid, int cmd, const char *param)
{
	struct filter_rule	*rule;

	TAILQ_FOREACH(rule, &env->sc_filter_rules[cmd], entry)
	    if (! lka_filter_execute(rule, reqid, cmd, param))
		    return;

	lka_filter_proceed(reqid, cmd, param);
}

static void
lka_filter_proceed(uint64_t reqid, int cmd, const char *param)
{
	m_create(p_pony, IMSG_SMTP_FILTER, 0, 0, -1);
	m_add_id(p_pony, reqid);
	m_add_int(p_pony, cmd);
	m_add_int(p_pony, FILTER_PROCEED);
	m_add_string(p_pony, param);
	m_close(p_pony);
}

static void
lka_filter_reject(uint64_t reqid, int cmd, const char *message)
{
	m_create(p_pony, IMSG_SMTP_FILTER, 0, 0, -1);
	m_add_id(p_pony, reqid);
	m_add_int(p_pony, cmd);
	m_add_int(p_pony, FILTER_REJECT);
	m_add_string(p_pony, message);
	m_close(p_pony);
}

static int
lka_filter_execute_helo(struct filter_rule *rule, uint64_t reqid, int cmd, const char *param)
{
	if (rule->u.helo.table)
		if (table_lookup(rule->u.helo.table, NULL, param, K_DOMAIN, NULL) > 0)
			goto reject;

	if (rule->u.helo.regex)
		if (table_lookup(rule->u.helo.regex, NULL, param, K_REGEX, NULL) > 0)
			goto reject;

	return 1;

reject:
	lka_filter_reject(reqid, cmd, rule->reject);
	return 0;
}

static int
lka_filter_execute_ehlo(struct filter_rule *rule, uint64_t reqid, int cmd, const char *param)
{
	if (rule->u.ehlo.table)
		if (table_lookup(rule->u.ehlo.table, NULL, param, K_DOMAIN, NULL) > 0)
			goto reject;

	if (rule->u.helo.regex)
		if (table_lookup(rule->u.ehlo.regex, NULL, param, K_REGEX, NULL) > 0)
			goto reject;

	return 1;

reject:
	lka_filter_reject(reqid, cmd, rule->reject);
	return 0;
}

static int
lka_filter_execute_starttls(struct filter_rule *rule, uint64_t reqid, int cmd, const char *param)
{
	return 1;
}

static int
lka_filter_execute_auth(struct filter_rule *rule, uint64_t reqid, int cmd, const char *param)
{
	return 1;
}

static int
lka_filter_execute_mail_from(struct filter_rule *rule, uint64_t reqid, int cmd, const char *param)
{
	char	buffer[SMTPD_MAXMAILADDRSIZE];

	(void)strlcpy(buffer, param+1, sizeof(buffer));
	buffer[strcspn(buffer, ">")] = '\0';
	param = buffer;

	if (rule->u.mail_from.table)
		if (table_lookup(rule->u.mail_from.table, NULL, param, K_MAILADDR, NULL) > 0)
			goto reject;

	if (rule->u.helo.regex)
		if (table_lookup(rule->u.mail_from.regex, NULL, param, K_REGEX, NULL) > 0)
			goto reject;

	return 1;

reject:
	lka_filter_reject(reqid, cmd, rule->reject);
	return 0;
}

static int
lka_filter_execute_rcpt_to(struct filter_rule *rule, uint64_t reqid, int cmd, const char *param)
{
	char	buffer[SMTPD_MAXMAILADDRSIZE];

	(void)strlcpy(buffer, param+1, sizeof(buffer));
	buffer[strcspn(buffer, ">")] = '\0';
	param = buffer;

	if (rule->u.rcpt_to.table)
		if (table_lookup(rule->u.rcpt_to.table, NULL, param, K_DOMAIN, NULL) > 0)
			goto reject;

	if (rule->u.helo.regex)
		if (table_lookup(rule->u.rcpt_to.regex, NULL, param, K_REGEX, NULL) > 0)
			goto reject;

	return 1;

reject:
	lka_filter_reject(reqid, cmd, rule->reject);
	return 0;
}

static int
lka_filter_execute_data(struct filter_rule *rule, uint64_t reqid, int cmd, const char *param)
{
	return 1;
}

static int
lka_filter_execute_quit(struct filter_rule *rule, uint64_t reqid, int cmd, const char *param)
{
	return 1;
}

static int
lka_filter_execute_noop(struct filter_rule *rule, uint64_t reqid, int cmd, const char *param)
{
	return 1;
}

static int
lka_filter_execute_rset(struct filter_rule *rule, uint64_t reqid, int cmd, const char *param)
{
	return 1;
}


static int
lka_filter_execute(struct filter_rule *rule, uint64_t reqid, int cmd, const char *param)
{
	switch (cmd) {
	case FILTER_HELO:
		return lka_filter_execute_helo(rule, reqid, cmd, param);

	case FILTER_EHLO:
		return lka_filter_execute_ehlo(rule, reqid, cmd, param);

	case FILTER_STARTTLS:
		return lka_filter_execute_starttls(rule, reqid, cmd, param);

	case FILTER_AUTH:
		return lka_filter_execute_auth(rule, reqid, cmd, param);

	case FILTER_MAIL_FROM:
		return lka_filter_execute_mail_from(rule, reqid, cmd, param);

	case FILTER_RCPT_TO:
		return lka_filter_execute_rcpt_to(rule, reqid, cmd, param);

	case FILTER_DATA:
		return lka_filter_execute_data(rule, reqid, cmd, param);

	case FILTER_QUIT:
		return lka_filter_execute_quit(rule, reqid, cmd, param);

	case FILTER_NOOP:
		return lka_filter_execute_noop(rule, reqid, cmd, param);

	case FILTER_RSET:
		return lka_filter_execute_rset(rule, reqid, cmd, param);

	default:
		return 1;
	}
}
