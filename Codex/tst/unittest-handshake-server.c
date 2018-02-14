/* vi: set ts=4 expandtab shiftwidth=4: */
/**
 * @file
 *
 * Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in README.h<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
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
#include "com/diag/diminuto/diminuto_list.h"
#include "com/diag/diminuto/diminuto_containerof.h"
#include "com/diag/diminuto/diminuto_ipc6.h"
#include "com/diag/codex/codex.h"
#include "unittest-codex.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdbool.h>

typedef struct Buffer {
	diminuto_list_t node;
	codex_header_t header;
	uint8_t payload[0];
} buffer_t;

typedef struct Stream {
	codex_state_t state;
	buffer_t * buffer;
	uint8_t * here;
	size_t length;
} stream_t;

typedef struct Client {
	codex_connection_t * ssl;
	diminuto_list_t queue;
	stream_t source;
	stream_t sink;
	codex_indication_t indication;
} client_t;

static const char * program = "unittest-handshake-server";
static const char * nearend = "49202";
static const char * expected = "client.prairiethorn.org";
static bool enforce = true;
static long seconds = -1; /* Unimplemented. */
static long octets = -1; /* Unimplemented. */
static size_t bufsize = 256;
static const char * pathcaf = COM_DIAG_CODEX_OUT_CRT_PATH "/" "root.pem";
static const char * pathcap = (const char *)0;
static const char * pathcrt = COM_DIAG_CODEX_OUT_CRT_PATH "/" "server.pem";
static const char * pathkey = COM_DIAG_CODEX_OUT_CRT_PATH "/" "server.pem";
static const char * pathdhf = COM_DIAG_CODEX_OUT_CRT_PATH "/" "dh.pem";

static diminuto_list_t pool = { 0 };
static int malloced = 0;
static diminuto_mux_t mux = { 0 };
static diminuto_fd_map_t * map = (diminuto_fd_map_t *)0;
static codex_context_t * ctx = (codex_context_t *)0;
static codex_rendezvous_t * bio = (codex_rendezvous_t *)0;
static int rendezvous = -1;

static buffer_t * allocate(void)
{
	buffer_t * buffer = (buffer_t *)0;
	diminuto_list_t * that = (diminuto_list_t *)0;

	that = diminuto_list_dequeue(&pool);
	if (that != (diminuto_list_t *)0) {
		buffer = diminuto_containerof(buffer_t, node, that);
	} else {
		buffer = (buffer_t *)malloc(sizeof(buffer_t) + bufsize);
		ASSERT(buffer != (buffer_t *)0);
		diminuto_list_datainit(&(buffer->node), &(buffer->payload));
		buffer->header = 0;
		malloced += 1;
	}

	return buffer;
}

static buffer_t * release(buffer_t * buffer)
{
	ASSERT(diminuto_list_enqueue(&pool, &(buffer->node)) != (diminuto_list_t *)0);
	return (buffer_t *)0;
}

static buffer_t * enqueue(client_t * client, buffer_t * buffer)
{
	ASSERT(diminuto_list_enqueue(&(client->queue), &(buffer->node)) != (diminuto_list_t *)0);
	return (buffer_t *)0;
}

static buffer_t * dequeue(client_t * client)
{
	buffer_t * buffer = (buffer_t *)0;
	diminuto_list_t * that = (diminuto_list_t *)0;

	that = diminuto_list_dequeue(&(client->queue));
	if (that != (diminuto_list_t *)0) {
		buffer = diminuto_containerof(buffer_t, node, that);
	}

	return buffer;
}

static client_t * create(void)
{
	client_t * client = (client_t *)0;
	int fd = -1;
	int rc = -1;
	void ** here = (void **)0;

	client = (client_t *)malloc(sizeof(client_t));
	ASSERT(client != (client_t *)0);
	memset(client, 0, sizeof(client_t));

	client->ssl = codex_server_connection_new(ctx, bio);
	ASSERT(client->ssl != (codex_connection_t *)0);
	ASSERT(codex_connection_is_server(client->ssl));

	client->indication = CODEX_INDICATION_NONE;

	client->source.state = CODEX_STATE_START;
	client->source.buffer = (buffer_t *)0;
	/* Source always pulls from shared pool. */

	client->sink.state = CODEX_STATE_COMPLETE;
	client->sink.buffer = (buffer_t *)0;
	diminuto_list_nullinit(&(client->queue));

	fd = codex_connection_descriptor(client->ssl);
	ASSERT(fd >= 0);

	rc = diminuto_mux_register_read(&mux, fd);
	ASSERT(rc >= 0);

	rc = diminuto_mux_register_write(&mux, fd);
	ASSERT(rc >= 0);

	here = diminuto_fd_map_ref(map, fd);
	ASSERT(here != (void **)0);
	ASSERT(*here == (void *)0);
	*here = (void *)client;

	return client;
}

static client_t * destroy(client_t * client)
{
	int fd = -1;
	int rc = -1;
	void ** here = (void **)0;
	buffer_t * buffer = (buffer_t *)0;

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

	if (client->source.buffer != (buffer_t *)0) {
		client->source.buffer = release(client->source.buffer);
	}
	ASSERT(client->source.buffer == (buffer_t *)0);

	if (client->sink.buffer != (buffer_t *)0) {
		client->sink.buffer = release(client->sink.buffer);
	}
	ASSERT(client->sink.buffer == (buffer_t *)0);

	while ((buffer = dequeue(client)) != (buffer_t *)0) {
		buffer = release(buffer);
		ASSERT(buffer == (buffer_t *)0);
	}

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

static bool renegotiate(client_t * client)
{
	bool success = false;
	int rc = -1;
	codex_header_t header = 0;
	codex_state_t state = CODEX_STATE_IDLE;
	uint8_t * here = (uint8_t *)0;
	size_t length = 0;

	switch (client->indication) {

	case CODEX_INDICATION_READY:

		DIMINUTO_LOG_INFORMATION("%s: NEAREND client=%p\n", program, client);

		/*
		 * Drop into synchronous mode until the handshake is either complete or
		 * fails.
		 */

		rc = codex_handshake_renegotiate(client->ssl);
		if (rc < 0) {
			break;
		}

		/*
		 * Tell the far end that renegotiation is complete and the data stream
		 * can resume.
		 */

		header = CODEX_INDICATION_DONE;
		state = CODEX_STATE_RESTART;

		DIMINUTO_LOG_INFORMATION("%s: WRITE DONE client=%p header=%d state='%c' indication=%d\n", program, client, header, state, client->indication);

		do {
			state = codex_machine_writer(state, expected, client->ssl, &header, (void *)0, header, &here, &length);
		} while ((state != CODEX_STATE_FINAL) && (state != CODEX_STATE_COMPLETE));

		if (state == CODEX_STATE_FINAL) {
			client->source.state = CODEX_STATE_FINAL;
			break;
		}

		client->source.state = CODEX_STATE_START;
		client->sink.state = CODEX_STATE_COMPLETE;
		client->indication = CODEX_INDICATION_NONE;

		success = true;
		break;

	case CODEX_INDICATION_FAREND:

		DIMINUTO_LOG_INFORMATION("%s: FAREND client=%p\n", program, client);

		/*
		 * Drop into synchronous mode until the handshake is either complete or
		 * fails.
		 */

		header = CODEX_INDICATION_READY;
		state = CODEX_STATE_RESTART;

		DIMINUTO_LOG_INFORMATION("%s: WRITE READY client=%p header=%d state='%c' indication=%d\n", program, client, header, state, client->indication);

		do {
			state = codex_machine_writer(state, expected, client->ssl, &header, (void *)0, header, &here, &length);
		} while ((state != CODEX_STATE_FINAL) && (state != CODEX_STATE_COMPLETE));

		if (state == CODEX_STATE_FINAL) {
			client->sink.state = CODEX_STATE_FINAL;
			break;
		}

		/*
		 * Read until we get a DONE indication. The far end can write zero
		 * length packets it it needs to drive the OpenSSL algorithms and our
		 * reader machine will silently drop them. Likewise, we could write zero
		 * length packets and the far end's reader state machine will similarly
		 * silently drop them.
		 */

		state = CODEX_STATE_RESTART;

		do {
			state = codex_machine_reader(state, expected, client->ssl, &header, (void *)0, 0, &here, &length);
		} while ((state != CODEX_STATE_FINAL) && (state != CODEX_STATE_COMPLETE));

		if (state == CODEX_STATE_FINAL) {
			client->source.state = CODEX_STATE_FINAL;
			break;
		}

		DIMINUTO_LOG_INFORMATION("%s: READ DONE client=%p header=%d state='%c' indication=%d\n", program, client, header, state, client->indication);

		if (header != CODEX_INDICATION_DONE) {
			client->source.state = CODEX_STATE_FINAL;
			break;
		}

		client->source.state = CODEX_STATE_START;
		client->sink.state = CODEX_STATE_COMPLETE;
		client->indication = CODEX_INDICATION_NONE;

		success = true;
		break;

	default:
		DIMINUTO_LOG_ERROR("%s: FATAL client=%p indication=%d\n", program, client, client->indication);
		FATAL();
		break;

	}

	return success;
}

int main(int argc, char ** argv)
{
	int rc = -1;
	ssize_t count = 0;
	char * endptr = (char *)0;
    int opt = '\0';
    extern char * optarg;

	(void)diminuto_core_enable();

	diminuto_log_setmask();

    program = ((program = strrchr(argv[0], '/')) == (char *)0) ? argv[0] : program + 1;

    while ((opt = getopt(argc, argv, "B:C:D:K:P:R:Vb:e:n:s:v?")) >= 0) {

        switch (opt) {

        case 'B':
        	bufsize = strtoul(optarg, &endptr, 0);
        	break;

        case 'C':
        	pathcrt = optarg;
        	break;

        case 'D':
        	pathdhf = optarg;
			break;

        case 'K':
        	pathkey = optarg;
        	break;

        case 'P':
        	pathcap = optarg;
        	break;

        case 'R':
        	pathcaf = optarg;
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
        	fprintf(stderr, "usage: %s [ -B BUFSIZE ] [ -C CERTIFICATEFILE ] [ -D DHPARMSFILE ] [ -K PRIVATEKEYFILE ] [ -P CERTIFICATESPATH ] [ -R ROOTFILE ] [ -b BYTES ] [ -e EXPECTED ] [ -n NEAREND ] [ -s SECONDS ] [ -V | -v ]\n", program);
            return 1;
            break;

        }

    }

	count = diminuto_fd_maximum();
	ASSERT(count > 0);

	DIMINUTO_LOG_INFORMATION("%s: BEGIN B=%zu C=\"%s\" D=\"%s\" K=\"%s\" P=\"%s\" R=\"%s\" b=%ld e=\"%s\" n=\"%s\" s=%ld v=%d fdcount=%d\n", program, bufsize, pathcrt, pathdhf, pathkey, (pathcap == (const char *)0) ? "" : pathcap, pathcaf, octets, expected, nearend, seconds, enforce, count);

	diminuto_list_nullinit(&pool);

	map = diminuto_fd_map_alloc(count);
	ASSERT(map != (diminuto_fd_map_t *)0);

	rc = diminuto_terminator_install(0);
	ASSERT(rc >= 0);

	rc = diminuto_hangup_install(0);
	ASSERT(rc >= 0);

	diminuto_mux_init(&mux);

	rc = codex_initialize();
	ASSERT(rc == 0);

	rc = codex_parameters(pathdhf);
	ASSERT(rc == 0);

	ctx = codex_server_context_new(pathcaf, pathcap, pathcrt, pathkey);
	ASSERT(ctx != (codex_context_t *)0);

	bio = codex_server_rendezvous_new(nearend);
	ASSERT(bio != (codex_rendezvous_t *)0);

	rendezvous = codex_rendezvous_descriptor(bio);
	ASSERT(rendezvous >= 0);

	rc = diminuto_mux_register_accept(&mux, rendezvous);
	ASSERT(rc >= 0);

	while (!diminuto_terminator_check()) {
		int fd = -1;

		if (diminuto_hangup_check()) {
			void ** here = (void **)0;
			client_t * client = (client_t *)0;

			DIMINUTO_LOG_INFORMATION("%s: SIGHUP\n", program);
			for (fd = 0; fd < count; ++fd) {
				here = diminuto_fd_map_ref(map, fd);
				ASSERT(here != (void **)0);
				if (*here != (void *)0) {
					client = (client_t *)*here;
					if (client->indication == CODEX_INDICATION_NONE) {
						client->indication = CODEX_INDICATION_NEAREND;
					}
				}
			}

		}

		rc = diminuto_mux_wait(&mux, -1);
		if ((rc == 0) || ((rc < 0) && (errno == EINTR))) {
			diminuto_yield();
			continue;
		}
		ASSERT(rc > 0);

		do {

			while ((fd = diminuto_mux_ready_accept(&mux)) >= 0) {
				client_t * client = (client_t *)0;
				int rc = -1;
				diminuto_ipv6_t addressne = { 0 };
				diminuto_port_t portne = 0;
				diminuto_ipv6_t addressfe = { 0 };
				diminuto_port_t portfe = 0;
				char bufferne[sizeof("XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX")];
				char bufferfe[sizeof("XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX")];

				ASSERT(fd == rendezvous);
				client = create();
				if (client == (client_t *)0) {
					continue;
				}
				fd = codex_connection_descriptor(client->ssl);
				rc = diminuto_ipc6_nearend(fd, &addressne, &portne);
				EXPECT(rc == 0);
				rc = diminuto_ipc6_farend(fd, &addressfe, &portfe);
				EXPECT(rc == 0);
				DIMINUTO_LOG_INFORMATION("%s: START client=%p nearend=%s:%d farend=%s:%d\n", program, client, diminuto_ipc6_address2string(addressne, bufferne, sizeof(bufferne)), portne, diminuto_ipc6_address2string(addressfe, bufferfe, sizeof(bufferfe)), portfe);

			}

			while ((fd = diminuto_mux_ready_read(&mux)) >= 0) {
				void ** here = (void **)0;
				client_t * client = (client_t *)0;

				here = diminuto_fd_map_ref(map, fd);
				ASSERT(here != (void **)0);
				client = (client_t *)*here;
				ASSERT(client != (client_t *)0);

				if (client->source.state == CODEX_STATE_IDLE) {
					continue;
				}

				if (client->source.buffer == (buffer_t *)0) {
					client->source.buffer = allocate();
				}
				ASSERT(client->source.buffer != (buffer_t *)0);

				client->source.state = codex_machine_reader(client->source.state, expected, client->ssl, &(client->source.buffer->header), &(client->source.buffer->payload), bufsize, &(client->source.here), &(client->source.length));

				if (client->source.state == CODEX_STATE_FINAL) {

					DIMINUTO_LOG_INFORMATION("%s: FINAL client=%p\n", program, client);
					client = destroy(client);
					continue;

				}

				if (client->source.state != CODEX_STATE_COMPLETE) {
					continue;
				}

				if (client->source.buffer->header > 0) {

					DIMINUTO_LOG_DEBUG("%s: READ DATA client=%p header=%d state='%c' indication=%d\n", program, client, client->source.buffer->header, client->source.state, client->indication);
					client->source.buffer = enqueue(client, client->source.buffer);
					client->source.state = CODEX_STATE_RESTART;
					continue;

				} else if ((client->source.buffer->header == CODEX_INDICATION_FAREND) && (client->indication == CODEX_INDICATION_NONE)) {

					DIMINUTO_LOG_INFORMATION("%s: READ FAREND client=%p header=%d state='%c' indication=%d\n", program, client, client->source.buffer->header, client->source.state, client->indication);
					client->source.state = CODEX_STATE_IDLE;
					client->indication = CODEX_INDICATION_FAREND;

					/*
					 * Stop consuming the input stream and force the writer to
					 * do something so it notices the indication.
					 */

					client->source.buffer->header = CODEX_INDICATION_NONE;
					client->source.buffer = enqueue(client, client->source.buffer);

				} else if ((client->source.buffer->header == CODEX_INDICATION_READY) && (client->indication == CODEX_INDICATION_PENDING)) {

					DIMINUTO_LOG_INFORMATION("%s: READ READY client=%p header=%d state='%c' indication=%d\n", program, client, client->source.buffer->header, client->source.state, client->indication);
					client->source.state = CODEX_STATE_IDLE;
					client->indication = CODEX_INDICATION_READY;

					/*
					 * Stop consuming the input stream and force the writer to
					 * do something so it notices the indication.
					 */

					client->source.buffer->header = CODEX_INDICATION_NONE;
					client->source.buffer = enqueue(client, client->source.buffer);

				} else {

					DIMINUTO_LOG_WARNING("%s: READ INDICATION client=%p header=%d state='%c' indication=%d\n", program, client, client->source.buffer->header, client->source.state, client->indication);
					client->source.state = CODEX_STATE_RESTART;
					continue;

				}

				if (client->sink.state != CODEX_STATE_IDLE) {
					/* Do nothing. */
				} else if (renegotiate(client)) {
					/* Do nothing. */
				} else {

					DIMINUTO_LOG_INFORMATION("%s: FINAL client=%p\n", program, client);
					client = destroy(client);

				}

			}

			while ((fd = diminuto_mux_ready_write(&mux)) >= 0) {
				void ** here = (void **)0;
				client_t * client = (client_t *)0;

				here = diminuto_fd_map_ref(map, fd);
				ASSERT(here != (void **)0);
				client = (client_t *)*here;
				ASSERT(client != (client_t *)0);

				if (client->sink.state == CODEX_STATE_IDLE) {
					continue;
				}

				if (client->sink.buffer == (buffer_t *)0) {

					client->sink.buffer = dequeue(client);
					if (client->sink.buffer == (buffer_t *)0) {
						continue;
					}
					if (client->sink.state != CODEX_STATE_START) {
						client->sink.state = CODEX_STATE_RESTART;
					}

				}

				client->sink.state = codex_machine_writer(client->sink.state, expected, client->ssl, &(client->sink.buffer->header), &(client->sink.buffer->payload), client->sink.buffer->header, &(client->sink.here), &(client->sink.length));

				if (client->sink.state == CODEX_STATE_FINAL) {

					DIMINUTO_LOG_INFORMATION("%s: FINAL client=%p\n", program, client);
					client = destroy(client);
					continue;

				}

				if (client->sink.state != CODEX_STATE_COMPLETE) {
					continue;
				}

				if (client->indication == CODEX_INDICATION_NONE) {

					DIMINUTO_LOG_DEBUG("%s: WRITE DATA client=%p header=%d state='%c' indication=%d\n", program, client, client->sink.buffer->header, client->sink.state, client->indication);
					client->sink.buffer = release(client->sink.buffer);
					continue;

				} else if (client->indication == CODEX_INDICATION_FAREND) {

					DIMINUTO_LOG_DEBUG("%s: WRITE DATA client=%p header=%d state='%c' indication=%d\n", program, client, client->sink.buffer->header, client->sink.state, client->indication);
					client->sink.buffer = release(client->sink.buffer);
					client->sink.state = CODEX_STATE_IDLE;

					/*
					 * Stop producing the output stream.
					 */

				} else if (client->indication == CODEX_INDICATION_NEAREND) {

					DIMINUTO_LOG_DEBUG("%s: WRITE DATA client=%p header=%d state='%c' indication=%d\n", program, client, client->sink.buffer->header, client->sink.state, client->indication);
					client->sink.buffer->header = CODEX_INDICATION_FAREND;
					client->sink.state = CODEX_STATE_RESTART;
					client->indication = CODEX_INDICATION_PENDING;
					continue;

				} else if (client->indication == CODEX_INDICATION_PENDING) {

					DIMINUTO_LOG_INFORMATION("%s: WRITE FAREND client=%p header=%d state='%c' indication=%d\n", program, client, client->sink.buffer->header, client->sink.state, client->indication);
					client->sink.buffer = release(client->sink.buffer);
					client->sink.state = CODEX_STATE_IDLE;

					/*
					 * Stop producing the output stream.
					 */

				} else {

					DIMINUTO_LOG_WARNING("%s: WRITE DATA client=%p header=%d state='%c' indication=%d\n", program, client, client->sink.buffer->header, client->sink.state, client->indication);
					client->sink.buffer = release(client->sink.buffer);
					continue;

				}

				if (client->source.state != CODEX_STATE_IDLE) {
					/* Do nothing. */
				} else if (renegotiate(client)) {
					/* Do nothing. */
				} else {

					DIMINUTO_LOG_INFORMATION("%s: FINAL client=%p\n", program, client);
					client = destroy(client);

				}

			}

			diminuto_yield();

		} while (fd >= 0);

	}

	diminuto_mux_fini(&mux);

	{
		int fd = -1;
		void ** here = (void **)0;
		client_t * client = (client_t *)0;
		diminuto_list_t * node = (diminuto_list_t *)0;
		int freed = 0;

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
			client = destroy(client);

		}

		diminuto_mux_fini(&mux);

		free(map);

		while ((node = diminuto_list_dequeue(&pool)) != (diminuto_list_t *)0) {
			free(node);
			freed += 1;
		}

		ctx = codex_context_free(ctx);
		EXPECT(ctx == (codex_context_t *)0);

		DIMINUTO_LOG_INFORMATION("%s: END allocated=%d freed=%d\n", program, malloced, freed);
		EXPECT(malloced == freed);

	}

	EXIT();
}

