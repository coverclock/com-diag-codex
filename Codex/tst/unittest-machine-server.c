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
#include "../src/codex_unittest.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>

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
	stream_t source;
	stream_t sink;
} client_t;

int main(int argc, char ** argv)
{
	const char * program = "unittest-machine-server";
	const char * nearend = "49152";
	const char * expected = "client.prairiethorn.org";
	bool enforce = true;
	long seconds = -1; /* Unimplemented. */
	long octets = -1; /* Unimplemented. */
	size_t bufsize = 256;
	int rc = -1;
	codex_context_t * ctx = (codex_context_t *)0;
	codex_rendezvous_t * bio = (codex_rendezvous_t *)0;
	ssize_t count = 0;
	diminuto_fd_map_t * map = (diminuto_fd_map_t *)0;
	void ** here = (void **)0;
	diminuto_mux_t mux = { 0 };
	int fd = -1;
	int rendezvous = -1;
	int bytes = -1;
	void * temp = (void *)0;
	char * endptr = (char *)0;
	client_t * client = 0;
	codex_state_t state = CODEX_STATE_FINAL;
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

	here = diminuto_fd_map_ref(map, rendezvous);
	ASSERT(here != (void **)0);
	ASSERT(*here == (void *)0);
	*here = (void *)bio;

	rc = diminuto_mux_register_accept(&mux, rendezvous);
	ASSERT(rc >= 0);

	while (!diminuto_terminator_check()) {

		if (diminuto_hangup_check()) {
			DIMINUTO_LOG_INFORMATION("%s: SIGHUP\n", program);
			/* Unimplemented. */
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

			here = diminuto_fd_map_ref(map, fd);
			ASSERT(here != (void **)0);
			ASSERT(*here != (void *)0);
			bio = (codex_rendezvous_t *)*here;

			client = (client_t *)malloc(sizeof(client_t));
			ASSERT(client != (client_t *)0);
			memset(client, 0, sizeof(client_t));

			client->ssl = codex_server_connection_new(ctx, bio);
			ASSERT(client->ssl != (codex_connection_t *)0);
			ASSERT(codex_connection_is_server(client->ssl));
			client->size = bufsize;

			client->source.state = CODEX_STATE_START;
			client->source.buffer = malloc(bufsize);
			ASSERT(client->source.buffer != (void *)0);

			client->sink.state = CODEX_STATE_START;
			client->sink.buffer = malloc(bufsize);
			ASSERT(client->sink.buffer != (void *)0);

			fd = codex_connection_descriptor(client->ssl);
			ASSERT(fd >= 0);

			DIMINUTO_LOG_INFORMATION("%s: START client=%p fd=%d\n", program, client, fd);

			here = diminuto_fd_map_ref(map, fd);
			ASSERT(here != (void **)0);
			ASSERT(*here == (void *)0);
			*here = (void *)client;

			rc = diminuto_mux_register_read(&mux, fd);
			ASSERT(rc >= 0);

			rc = diminuto_mux_register_write(&mux, fd);
			ASSERT(rc >= 0);

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

			state = codex_machine_reader(client->source.state, client->ssl, &(client->source.header), client->source.buffer, client->size, &(client->source.here), &(client->source.length));

			if (client->source.state != CODEX_STATE_START) {
				/* Do nothing. */
			} else if (state == CODEX_STATE_START) {
				/* Do nothing. */
			} else {

				rc = codex_connection_verify(client->ssl, expected);
				if (!enforce) {
					/* Do nothing. */
				} else if (rc == CODEX_CONNECTION_VERIFY_CN) {
					/* Do nothing. */
				} else if (rc == CODEX_CONNECTION_VERIFY_FQDN) {
					/* Do nothing. */
				} else {
					state = CODEX_STATE_FINAL;
				}

			}

			if (client->source.state == CODEX_STATE_FINAL) {
				/* Do nothing. */
			} else if (state != CODEX_STATE_FINAL) {
				/* Do nothing. */
			} else {

				DIMINUTO_LOG_INFORMATION("%s: FINAL client=%p\n", program, client);

				rc = diminuto_mux_unregister_read(&mux, fd);
				ASSERT(rc >= 0);

				rc = diminuto_mux_unregister_write(&mux, fd);
				ASSERT(rc >= 0);

				here = diminuto_fd_map_ref(map, fd);
				ASSERT(here != (void **)0);
				ASSERT(*here != (void *)0);
				client = (client_t *)*here;

				rc = codex_connection_close(client->ssl);
				ASSERT(rc >= 0);
				client->ssl = codex_connection_free(client->ssl);
				ASSERT(client->ssl == (codex_connection_t *)0);
				free(client->source.buffer);
				free(client->sink.buffer);
				free(client);

				*here = (void *)0;

				continue;

			}

			if (client->source.state == CODEX_STATE_COMPLETE) {
				/* Do nothing. */
			} else if (state != CODEX_STATE_COMPLETE) {
				/* Do nothing. */
			} else {

				DIMINUTO_LOG_DEBUG("%s: READ client=%p bytes=%d\n", program, client, client->source.header);

			}

			client->source.state = state;

			if (client->sink.state != CODEX_STATE_COMPLETE) {
				/* Do nothing. */
			} else if (state != CODEX_STATE_COMPLETE) {
				/* Do nothing. */
			} else {

				temp = client->source.buffer;
				client->source.buffer = client->sink.buffer;
				client->sink.buffer = temp;
				client->source.state = CODEX_STATE_START;
				client->sink.state = CODEX_STATE_START;

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

			state = codex_machine_writer(client->sink.state, client->ssl, &(client->sink.header), client->sink.buffer, client->sink.header, &(client->sink.here), &(client->sink.length));

			if (client->sink.state == CODEX_STATE_FINAL) {
				/* Do nothing. */
			} else if (state != CODEX_STATE_FINAL) {
				/* Do nothing. */
			} else {

				DIMINUTO_LOG_INFORMATION("%s: FINAL client=%p\n", program, client);

				rc = diminuto_mux_unregister_read(&mux, fd);
				ASSERT(rc >= 0);

				rc = diminuto_mux_unregister_write(&mux, fd);
				ASSERT(rc >= 0);

				here = diminuto_fd_map_ref(map, fd);
				ASSERT(here != (void **)0);
				ASSERT(*here != (void *)0);
				client = (client_t *)*here;

				rc = codex_connection_close(client->ssl);
				ASSERT(rc >= 0);
				client->ssl = codex_connection_free(client->ssl);
				ASSERT(client->ssl == (codex_connection_t *)0);

				free(client->source.buffer);
				free(client->sink.buffer);
				free(client);

				*here = (void *)0;

				continue;

			}

			if (client->sink.state == CODEX_STATE_COMPLETE) {
				/* Do nothing. */
			} else if (state != CODEX_STATE_COMPLETE) {
				/* Do nothing. */
			} else {

				DIMINUTO_LOG_DEBUG("%s: WRITE client=%p bytes=%d\n", program, client, client->source.header);

			}

			client->source.state = state;

			if (client->source.state != CODEX_STATE_COMPLETE) {
				/* Do nothing. */
			} else if (state != CODEX_STATE_COMPLETE) {
				/* Do nothing. */
			} else {

				temp = client->sink.buffer;
				client->sink.buffer = client->source.buffer;
				client->source.buffer = temp;
				client->sink.state = CODEX_STATE_START;
				client->source.state = CODEX_STATE_START;

			}

		}

	}

	DIMINUTO_LOG_INFORMATION("%s: END\n", program);

	diminuto_mux_fini(&mux);

	fd = codex_rendezvous_descriptor(bio);
	ASSERT(fd >= 0);
	ASSERT(fd == rendezvous);

	rc = diminuto_mux_unregister_accept(&mux, fd);
	ASSERT(rc >= 0);

	here = diminuto_fd_map_ref(map, fd);
	ASSERT(here != (void **)0);
	ASSERT(*here == bio);
	*here = (void *)0;

	bio = codex_server_rendezvous_free(bio);
	ASSERT(bio == (codex_rendezvous_t *)0);

	for (fd = 0; fd < count; ++fd) {

		here = diminuto_fd_map_ref(map, fd);
		ASSERT(here != (void **)0);
		if (*here == (void *)0) { continue; }
		client = (client_t *)*here;

		rc = codex_connection_close(client->ssl);
		ASSERT(rc >= 0);
		client->ssl = codex_connection_free(client->ssl);
		ASSERT(client->ssl == (codex_connection_t *)0);

		free(client->source.buffer);
		free(client->sink.buffer);
		free(client);

		*here = (void *)0;

	}

	free(map);

	ctx = codex_context_free(ctx);
	EXPECT(ctx == (codex_context_t *)0);

	EXIT();
}

