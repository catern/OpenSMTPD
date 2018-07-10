/*	$OpenBSD: smtpf_session.c,v 1.1 2017/05/22 13:40:54 gilles Exp $	*/

/*
 * Copyright (c) 2017 Gilles Chehade <gilles@poolp.org>
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

#include <errno.h>
#include <imsg.h>
#include <limits.h>
#include <openssl/ssl.h>

#include "smtpd.h"
#include "log.h"

#define	SMTPF_LINEMAX		4096

struct smtpf_session {
	char				 name[32];
	const char			*filter;
	struct smtp_session		*smtp;
	struct smtpf_conn		*conn;
	TAILQ_ENTRY(smtpf_session)	 entry;
	int				 pending;
};

struct smtpf_conn {
	const char			*hostname;
	const char			*servname;
	struct event			 evt;
	struct addrinfo			*ai;
	struct io			*io;
	int				 ready;
	TAILQ_HEAD(, smtpf_session)	 sessions;

};

static struct smtpf_conn *_conn = NULL;

static void smtpf_cb_connect(int, short, void *);
static void smtpf_cb_getaddrinfo(void *, int, struct addrinfo *);
static void smtpf_connect(struct smtpf_conn *);
static void smtpf_close(struct smtpf_conn *);
static void smtpf_io(struct io *, int, void *);
static void smtpf_process_line(struct smtpf_conn *, char *);

static int smtpf_send_command(struct smtpf_session *, const char *);
static void smtpf_start_session(struct smtpf_session *);
static void smtpf_forward_response(struct smtpf_session *, const char *);
static void smtpf_process_request(struct smtpf_session *, const char *);
static void smtpf_handle_command(struct smtpf_session *, const char *);

void
smtpf_init(void)
{
	_conn = calloc(1, sizeof(*_conn));
	_conn->hostname = "localhost";
	_conn->servname = "2626";
	TAILQ_INIT(&_conn->sessions);

	smtpf_cb_connect(-1, 0, _conn);
}

struct smtpf_session *
smtpf_create_session(struct smtp_session *smtp, int32_t id, const char *filter)
{
	struct smtpf_session *sess;

	if (_conn == NULL)
		smtpf_init();

	sess = calloc(1, sizeof(*sess));
	sess->conn = _conn;
	sess->filter = filter;
	sess->smtp = smtp;
	snprintf(sess->name, sizeof(sess->name), "S%08x", id);
	TAILQ_INSERT_TAIL(&_conn->sessions, sess, entry);

	smtpf_start_session(sess);

	return sess;
}

void
smtpf_close_session(struct smtpf_session *sess)
{
	smtpf_send_command(sess, "CLOSE");
}

int
smtpf_send_request(struct smtpf_session *sess, const char *line)
{
	/*
	 * Send an SMTP request to smtpfd on behalf of the client.
	 */
	log_info("smtpfd <<< A[%s] %s", sess->name, line);
	return io_printf(sess->conn->io, "A:%s:%s\n", sess->name, line);
}

int
smtpf_send_response(struct smtpf_session *sess, const char *line)
{
	/*
	 * Send an SMTP response to smtpfd.
	 */
	log_info("smtpfd <<< B[%s] %s", sess->name, line);
	return io_printf(sess->conn->io, "B:%s:%s\n", sess->name, line);
}

static void
smtpf_cb_connect(int fd, short evt, void *arg)
{
	struct smtpf_conn *conn = arg;
	struct addrinfo hints;

	log_debug("connecting to smtpfd %s:%s", conn->hostname, conn->servname);

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;

	resolver_getaddrinfo(conn->hostname, conn->servname, &hints,
	    smtpf_cb_getaddrinfo, conn);
}

static void
smtpf_cb_getaddrinfo(void *arg, int gai_errno, struct addrinfo *ai)
{
	struct smtpf_conn *conn = arg;

	if (gai_errno) {
		log_warn("getaddrinfo: %s", gai_strerror(gai_errno));
		smtpf_close(conn);
		return;
	}

	conn->ai = ai;
	smtpf_connect(conn);
}

static void
smtpf_close(struct smtpf_conn *conn)
{
	struct smtpf_session *sess;
	struct timeval tv;

	while ((sess = TAILQ_FIRST(&conn->sessions))) {
		TAILQ_REMOVE(&conn->sessions, sess, entry);
		free(sess);
	}

	if (conn->io)
		io_free(conn->io);
	conn->io = NULL;

	if (conn->ai)
		freeaddrinfo(conn->ai);
	conn->ai = NULL;

	tv.tv_sec = 1;
	tv.tv_usec = 0;
	evtimer_set(&conn->evt, smtpf_cb_connect, conn);
	evtimer_add(&conn->evt, &tv);
}

static void
smtpf_connect(struct smtpf_conn *conn)
{
	struct addrinfo *ai = conn->ai;

	conn->ai = ai->ai_next;
	ai->ai_next = NULL;

	if (conn->io)
		io_free(conn->io);

	conn->io = io_new();
	io_set_callback(conn->io, smtpf_io, conn);
	io_connect(conn->io, ai->ai_addr, NULL);
	freeaddrinfo(ai);
}

static void
smtpf_io(struct io *io, int evt, void *arg)
{
	struct smtpf_session *sess;
	struct smtpf_conn *conn = arg;
	char *line;

	switch (evt) {
	case IO_CONNECTED:
		log_debug("smtpf: connected to %s:%s", conn->hostname, conn->servname);
		freeaddrinfo(conn->ai);
		conn->ai = NULL;
		conn->ready = 1;
		TAILQ_FOREACH(sess, &conn->sessions, entry)
			smtpf_start_session(sess);
		return;

	case IO_DATAIN:
		while ((line = io_getline(conn->io, NULL)))
			smtpf_process_line(conn, line);

		if (io_datalen(conn->io) > SMTPF_LINEMAX) {
			log_warnx("smtpf: line too long");
			break;
		}
		return;

	case IO_LOWAT:
		/* log_debug("smtpf: lowat"); */
		return;

	case IO_DISCONNECTED:
		log_debug("smtpf: disconnected");
		break;

	case IO_TIMEOUT:
		log_debug("smtpf: timeout");
		break;

	case IO_ERROR:
		log_warnx("smtpf: io error: %s", io_error(io));
		break;

	default:
		fatalx("%s: unexpected event %d", __func__, evt);
	}

	if (conn->ai)
		smtpf_connect(conn);
	else
	        smtpf_close(conn);
}


static void
smtpf_start_session(struct smtpf_session *sess)
{
	char cmd[1024];

	if (sess->conn->ready) {
		snprintf(cmd, sizeof(cmd), "OPEN %s", sess->filter);
		smtpf_send_command(sess, cmd);
	}
}

static int
smtpf_send_command(struct smtpf_session *sess, const char *line)
{
	log_info("smtpfd <<< SMTPF[%s] %s", sess->name, line);
	return io_printf(sess->conn->io, "SMTPF:%s:%s\n", sess->name, line);
}

static void
smtpf_process_line(struct smtpf_conn *conn, char *line)
{
	struct smtpf_session *sess;
	char *cmd, *name, *data;

	/* log_debug("%s: %s", __func__, line); */

	cmd = line;
	if ((name = strchr(cmd, ':')) == NULL) {
		log_warnx("%s: invalid line \"%s\"", __func__, line);
		return;
	}
	if ((data = strchr(name + 1, ':')) == NULL) {
		log_warnx("%s: invalid session name \"%s\"", __func__, name+1);
		return;
	}

	*name++ = '\0';
	*data++ = '\0';

	/* find the session */
	TAILQ_FOREACH(sess, &conn->sessions, entry)
		if (!strcmp(sess->name, name))
			break;

	if (sess == NULL) {
		log_warnx("%s: unknown session name \"%s\"", __func__, name);
		return;
	}

	if (!strcmp(cmd, "A"))
		smtpf_forward_response(sess, data);
	else if (!strcmp(cmd, "B"))
		smtpf_process_request(sess, data);
	else if (!strcmp(cmd, "SMTPF"))
		smtpf_handle_command(sess, data);
	else
		log_warn("%s: invalid command \"%s\"", __func__, cmd);
}

static void
smtpf_forward_response(struct smtpf_session *sess, const char *line)
{
	/*
	 * SMTP response from smtpfd intended for the client
	 */
	log_info("smtpfd >>> A[%s] %s", sess->name, line);

	smtp_forward(sess->smtp, line);
}

static void
smtpf_process_request(struct smtpf_session *sess, const char *line)
{
	/*
	 * SMTP request from smtpfd intended for the smtpd backend
	 */
	log_info("smtpfd >>> B[%s] %s", sess->name, line);

	smtp_process_command(sess->smtp, line);
}

static void
smtpf_handle_command(struct smtpf_session *sess, const char *line)
{
	/*
	 * Special command response from smtpfd
	 */
	log_info("smtpfd >>> SMTPF[%s] %s", sess->name, line);

	/* XXX handle response */
}
