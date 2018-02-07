/* vi: set ts=4 expandtab shiftwidth=4: */
/**
 * @file
 *
 * Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in README.h<BR>
 * Chip Overclock (coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 */

#include "com/diag/diminuto/diminuto_unittest.h"
#include "com/diag/diminuto/diminuto_log.h"
#include "com/diag/diminuto/diminuto_core.h"
#include "com/diag/diminuto/diminuto_terminator.h"
#include "com/diag/diminuto/diminuto_hangup.h"
#include "com/diag/diminuto/diminuto_fd.h"
#include "com/diag/diminuto/diminuto_mux.h"
#include "com/diag/diminuto/diminuto_delay.h"
#include "com/diag/diminuto/diminuto_ipc.h"
#include "com/diag/codex/codex.h"
#include "unittest-core.h"
#include "unittest-machine.h"
#include "unittest-handshake.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdbool.h>

typedef struct Stream {
	codex_state_t state;
	codex_header_t header;
	void * buffer;
	uint8_t * here;
	int length;
} stream_t;

typedef struct Client {
	codex_connection_t * ssl;
	int size;
	codex_indication_t indication;
	stream_t source;
	stream_t sink;
} client_t;

static const char * program = "unittest-handshake-server";
static const char * nearend = "49202";
static const char * expected = "client.prairiethorn.org";
static bool enforce = true;
static long seconds = -1; /* Unimplemented. */
static long octets = -1; /* Unimplemented. */
static size_t bufsize = 256;

static diminuto_mux_t mux = { 0 };
static diminuto_fd_map_t * map = (diminuto_fd_map_t *)0;
static codex_context_t * ctx = (codex_context_t *)0;
static codex_rendezvous_t * bio = (codex_rendezvous_t *)0;
static int rendezvous = -1;

static client_t * allocate(void)
{
	client_t * clientp = (client_t *)0;
	int fd = -1;
	int rc = -1;
	void ** here = (void **)0;

	clientp = (client_t *)malloc(sizeof(client_t));
	ASSERT(clientp != (client_t *)0);
	memset(clientp, 0, sizeof(client_t));

	clientp->ssl = codex_server_connection_new(ctx, bio);
	ASSERT(clientp->ssl != (codex_connection_t *)0);
	ASSERT(codex_connection_is_server(clientp->ssl));
	clientp->size = bufsize;

	clientp->indication = CODEX_INDICATION_NONE;

	clientp->source.state = CODEX_STATE_START;
	clientp->source.buffer = malloc(bufsize);
	ASSERT(clientp->source.buffer != (void *)0);

	clientp->sink.state = CODEX_STATE_IDLE;
	clientp->sink.buffer = malloc(bufsize);
	ASSERT(clientp->sink.buffer != (void *)0);

	fd = codex_connection_descriptor(clientp->ssl);
	ASSERT(fd >= 0);

	rc = diminuto_mux_register_read(&mux, fd);
	ASSERT(rc >= 0);

	rc = diminuto_mux_register_write(&mux, fd);
	ASSERT(rc >= 0);

	here = diminuto_fd_map_ref(map, fd);
	ASSERT(here != (void **)0);
	ASSERT(*here == (void *)0);
	*here = (void *)clientp;

	return clientp;
}

static client_t * release(client_t * client)
{
	int fd = -1;
	int rc = -1;
	void ** here = (void **)0;

	fd = codex_connection_descriptor(client->ssl);
	ASSERT(fd >= 0);

	here = diminuto_fd_map_ref(map, fd);
	ASSERT(here != (void **)0);
	ASSERT(*here != (void *)0);
	ASSERT(client == (client_t *)*here);
	*here = (void *)0;

	rc = diminuto_mux_unregister_read(&mux, fd);
	ASSERT(rc >= 0);

	rc = diminuto_mux_unregister_write(&mux, fd);
	ASSERT(rc >= 0);

	free(client->source.buffer);
	free(client->sink.buffer);

	if (client->source.state == CODEX_STATE_FINAL) {
		/* Do nothing. */
	} else if (client->sink.state == CODEX_STATE_FINAL) {
		/* Do nothing. */
	} else {
		rc = codex_connection_close(client->ssl);
		ASSERT(rc >= 0);
	}

	client->ssl = codex_connection_free(client->ssl);
	ASSERT(client->ssl == (codex_connection_t *)0);

	free(client);

	client = (client_t *)0;

	return client;
}

static bool process(client_t * client)
{
	bool success = false;
	void * temp = (void *)0;
	int rc = -1;

	switch (client->indication) {

	case CODEX_INDICATION_NONE:

		temp = client->sink.buffer;
		client->sink.buffer = client->source.buffer;
		client->sink.header = client->source.header;
		client->source.buffer = temp;

		client->source.state = CODEX_STATE_RESTART;
		client->sink.state = CODEX_STATE_RESTART;

		success = true;

		break;

	case CODEX_INDICATION_NEAREND:

		DIMINUTO_LOG_INFORMATION("%s: NEAREND client=%p\n", program, client);

		rc = codex_handshake_renegotiate(client->ssl);
		if (rc < 0) {
			break;
		}

		client->source.state = CODEX_STATE_START;
		client->sink.header = CODEX_INDICATION_DONE;
		client->sink.state = CODEX_STATE_RESTART;
		client->indication = CODEX_INDICATION_NONE;

		success = true;

		break;

	case CODEX_INDICATION_FAREND:

		DIMINUTO_LOG_INFORMATION("%s: FAREND client=%p\n", program, client);

		/*
		 * Drop into synchronous mode until the handshake is either complete or
		 * fails.
		 */

		client->sink.header = CODEX_INDICATION_READY;
		client->sink.state = CODEX_STATE_RESTART;
		DIMINUTO_LOG_INFORMATION("%s: WRITE client=%p header=%d\n", program, client, client->sink.header);
		do {
			client->sink.state = codex_machine_writer(client->sink.state, expected, client->ssl, &(client->sink.header), client->sink.buffer, client->sink.header, &(client->sink.here), &(client->sink.length));
		} while ((client->sink.state != CODEX_STATE_FINAL) && (client->sink.state != CODEX_STATE_COMPLETE));
		if (client->sink.state == CODEX_STATE_FINAL) {
			break;
		}

		/*
		 * Read until we get a DONE indication. The far end can write zero length
		 * packets it it needs to drive the OpenSSL actions and our reader
		 * machine will silently drop them. Likewise, we could write zero length
		 * packets and the far end's reader state machine will similarly
		 * silently drop them.
		 */

		client->source.state = CODEX_STATE_RESTART;
		do {
			client->source.state = codex_machine_reader(client->source.state, expected, client->ssl, &(client->source.header), (void *)0, 0, &(client->source.here), &(client->source.length));
		} while ((client->source.state != CODEX_STATE_FINAL) && (client->source.state != CODEX_STATE_COMPLETE));
		if (client->source.state == CODEX_STATE_FINAL) {
			break;
		}
		DIMINUTO_LOG_INFORMATION("%s: READ client=%p header=%d\n", program, client, client->source.header);

		if (client->source.header != CODEX_INDICATION_DONE) {
			break;
		}

		client->source.state = CODEX_STATE_START;
		client->indication = CODEX_INDICATION_NONE;

		success = true;

		break;

	default:
		FATAL(); /* Should never happen. */
		break;

	}

	return success;
}

int main(int argc, char ** argv)
{
	int rc = -1;
	ssize_t count = 0;
	int fd = -1;
	int bytes = -1;
	char * endptr = (char *)0;
	client_t * client = 0;
	void ** here = (void **)0;
    int opt = '\0';
    extern char * optarg;

	(void)diminuto_core_enable();

	diminuto_log_setmask();

    program = ((program = strrchr(argv[0], '/')) == (char *)0) ? argv[0] : program + 1;

    while ((opt = getopt(argc, argv, "B:Vb:e:n:s:v?")) >= 0) {

        switch (opt) {

        case 'B':
        	bufsize = strtoul(optarg, &endptr, 0);
        	break;

        case 'V':
        	enforce = false;
        	break;

        case 'b':
        	octets = strtol(optarg, &endptr, 0);
        	break;

        case 'e':
            expected = optarg;
            break;

        case 'n':
        	nearend = optarg;
        	break;

        case 's':
        	seconds = strtol(optarg, &endptr, 0);
        	break;

        case 'v':
        	enforce = true;
        	break;

        case '?':
        	fprintf(stderr, "usage: %s [ -B BUFSIZE ] [ -b BYTES ] [ -e EXPECTED ] [ -n NEAREND ] [ -s SECONDS ] [ -V | -v ]\n", program);
            return 1;
            break;

        }

    }

	count = diminuto_fd_maximum();
	ASSERT(count > 0);

	DIMINUTO_LOG_INFORMATION("%s: BEGIN B=%zu b=%ld e=\"%s\" n=\"%s\" s=%ld v=%d fdcount=%d\n", program, bufsize, octets, expected, nearend, seconds, enforce, count);

	map = diminuto_fd_map_alloc(count);
	ASSERT(map != (diminuto_fd_map_t *)0);

	rc = diminuto_terminator_install(0);
	ASSERT(rc >= 0);

	rc = diminuto_hangup_install(0);
	ASSERT(rc >= 0);

	diminuto_mux_init(&mux);

	rc = codex_initialize();
	ASSERT(rc == 0);

	rc = codex_parameters(COM_DIAG_CODEX_OUT_CRT_PATH "/" "dh.pem");
	ASSERT(rc == 0);

	ctx = codex_server_context_new(COM_DIAG_CODEX_OUT_CRT_PATH "/" "root.pem", (const char *)0, COM_DIAG_CODEX_OUT_CRT_PATH "/" "server.pem", COM_DIAG_CODEX_OUT_CRT_PATH "/" "server.pem");
	ASSERT(ctx != (codex_context_t *)0);

	bio = codex_server_rendezvous_new(nearend);
	ASSERT(bio != (codex_rendezvous_t *)0);

	rendezvous = codex_rendezvous_descriptor(bio);
	ASSERT(rendezvous >= 0);

	rc = diminuto_mux_register_accept(&mux, rendezvous);
	ASSERT(rc >= 0);

	while (!diminuto_terminator_check()) {

		if (diminuto_hangup_check()) {
			DIMINUTO_LOG_INFORMATION("%s: SIGHUP\n", program);
			for (fd = 0; fd < count; ++fd) {
				here = diminuto_fd_map_ref(map, fd);
				ASSERT(here != (void **)0);
				if (*here != (void *)0) {
					client = (client_t *)*here;
					client->indication = CODEX_INDICATION_NEAREND;
				}
			}
		}

		rc = diminuto_mux_wait(&mux, -1);
		if ((rc == 0) || ((rc < 0) && (errno == EINTR))) {
			diminuto_yield();
			continue;
		}
		ASSERT(rc > 0);

		while (true) {

			fd = diminuto_mux_ready_accept(&mux);
			if (fd < 0) {
				break;
			}
			ASSERT(fd == rendezvous);

			client = allocate();
			DIMINUTO_LOG_INFORMATION("%s: START client=%p\n", program, client);

		}

		while (true) {

			fd = diminuto_mux_ready_read(&mux);
			if (fd < 0) {
				break;
			}

			here = diminuto_fd_map_ref(map, fd);
			ASSERT(here != (void **)0);
			ASSERT(*here != (void *)0);
			client = (client_t *)*here;

			if (client->source.state == CODEX_STATE_IDLE) {
				continue;
			}

			client->source.state = codex_machine_reader(client->source.state, expected, client->ssl, &(client->source.header), client->source.buffer, client->size, &(client->source.here), &(client->source.length));

			if (client->source.state == CODEX_STATE_FINAL) {

				DIMINUTO_LOG_INFORMATION("%s: FINAL client=%p\n", program, client);
				client = release(client);
				continue;

			}

			if (client->source.state != CODEX_STATE_COMPLETE) {
				continue;
			}

			DIMINUTO_LOG_DEBUG("%s: READ client=%p bytes=%d state='%c' indication=%d\n", program, client, client->source.header, client->source.state, client->indication);

			if ((client->source.header == CODEX_INDICATION_FAREND) && (client->indication == CODEX_INDICATION_NONE)) {

				client->indication = CODEX_INDICATION_FAREND;
				client->source.state = CODEX_STATE_IDLE;

			} else if ((client->source.header == CODEX_INDICATION_READY) && (client->indication == CODEX_INDICATION_NEAREND)) {

				client->source.state = CODEX_STATE_IDLE;

			} else if ((client->source.header <= 0) && (client->indication == CODEX_INDICATION_NONE)) {

				client->source.state = CODEX_STATE_RESTART;
				continue;

			} else {

				client->source.state = CODEX_STATE_IDLE;

			}

			if (client->sink.state != CODEX_STATE_IDLE) {
				/* Do nothing. */
			} else if (process(client)) {
				/* Do nothing. */
			} else {

				DIMINUTO_LOG_INFORMATION("%s: FINAL client=%p\n", program, client);
				client = release(client);

			}

		}

		while (true) {

			fd = diminuto_mux_ready_write(&mux);
			if (fd < 0) {
				break;
			}

			here = diminuto_fd_map_ref(map, fd);
			ASSERT(here != (void **)0);
			ASSERT(*here != (void *)0);
			client = (client_t *)*here;

			if (client->sink.state == CODEX_STATE_IDLE) {
				continue;
			}

			client->sink.state = codex_machine_writer(client->sink.state, expected, client->ssl, &(client->sink.header), client->sink.buffer, client->sink.header, &(client->sink.here), &(client->sink.length));

			if (client->sink.state == CODEX_STATE_FINAL) {

				DIMINUTO_LOG_INFORMATION("%s: FINAL client=%p\n", program, client);
				client = release(client);
				continue;

			}

			if (client->sink.state != CODEX_STATE_COMPLETE) {
				continue;
			}

			DIMINUTO_LOG_DEBUG("%s: WRITE client=%p bytes=%d state='%c' indication=%d\n", program, client, client->sink.header, client->sink.state, client->indication);

			if (client->indication == CODEX_INDICATION_NONE) {

				client->sink.state = CODEX_STATE_IDLE;

			} else if (client->sink.header == CODEX_INDICATION_FAREND) {

				client->sink.state = CODEX_STATE_IDLE;

			} else if (client->indication == CODEX_INDICATION_NEAREND) {

				client->sink.header = CODEX_INDICATION_FAREND;
				client->sink.state = CODEX_STATE_RESTART;
				continue;

			} else {

				client->sink.state = CODEX_STATE_IDLE;

			}

			if (client->source.state != CODEX_STATE_IDLE) {
				/* Do nothing. */
			} else if (process(client)) {
				/* Do nothing. */
			} else {

				DIMINUTO_LOG_INFORMATION("%s: FINAL client=%p\n", program, client);
				client = release(client);

			}

		}

		diminuto_yield();

	}

	DIMINUTO_LOG_INFORMATION("%s: END\n", program);

	diminuto_mux_fini(&mux);

	fd = codex_rendezvous_descriptor(bio);
	ASSERT(fd >= 0);
	ASSERT(fd == rendezvous);

	rc = diminuto_mux_unregister_accept(&mux, fd);
	ASSERT(rc >= 0);

	bio = codex_server_rendezvous_free(bio);
	ASSERT(bio == (codex_rendezvous_t *)0);

	for (fd = 0; fd < count; ++fd) {

		here = diminuto_fd_map_ref(map, fd);
		ASSERT(here != (void **)0);
		if (*here == (void *)0) { continue; }
		client = (client_t *)*here;

		client = release(client);

	}

	diminuto_mux_fini(&mux);

	free(map);

	ctx = codex_context_free(ctx);
	EXPECT(ctx == (codex_context_t *)0);

	EXIT();
}

