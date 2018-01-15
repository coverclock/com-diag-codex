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
#include "com/diag/diminuto/diminuto_fd.h"
#include "com/diag/diminuto/diminuto_mux.h"
#include "com/diag/codex/codex.h"
#include "../src/codex_unittest.h"
#include <stdint.h>

int main(int argc, char ** argv)
{
	const char * name = "unittest-server";
	const char * nearend = "49152";
	const char * expected = "client.prairiethorn.org";
	int rc;
	SSL_CTX * context;
	BIO * rendezvous;
	ssize_t count;
	diminuto_fd_map_t * map;
	void ** here;
	diminuto_mux_t mux;
	int fd;
	SSL * connection;
	uint8_t buffer[4096];
	int reads;
	int writes;

	(void)diminuto_core_enable();

	diminuto_log_setmask();

	if (argc >= 1) {
		name = argv[0];
	}

	if (argc >= 2) {
		nearend = argv[1];
	}

	if (argc >= 3) {
		expected = argv[2];
	}

	DIMINUTO_LOG_DEBUG("%s: nearend=\"%s\" expected=\"%s\"\n", name, nearend, expected);

	rc = diminuto_terminator_install(!0);
	ASSERT(rc >= 0);

	count = diminuto_fd_maximum();
	ASSERT(count > 0);

	map = diminuto_fd_map_alloc(count);
	ASSERT(map != (diminuto_fd_map_t *)0);

	diminuto_mux_init(&mux);

	rc = codex_initialize();
	ASSERT(rc == 0);

	rc = codex_parameters(COM_DIAG_CODEX_OUT_ETC_PATH "/dh256.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/dh512.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/dh1024.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/dh2048.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/dh4096.pem");
	ASSERT(rc == 0);

	context = codex_server_context_new(COM_DIAG_CODEX_OUT_ETC_PATH "/root.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/server.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/server.pem");
	ASSERT(context != (SSL_CTX *)0);

	rendezvous = codex_server_rendezvous_new(nearend);
	ASSERT(rendezvous != (BIO *)0);

	fd = codex_rendezvous_descriptor(rendezvous);
	ASSERT(fd >= 0);

	DIMINUTO_LOG_DEBUG("%s: rendezvous=%p fd=%d\n", name, rendezvous, fd);

	here = diminuto_fd_map_ref(map, fd);
	ASSERT(here != (void **)0);
	ASSERT(*here == (void *)0);
	*here = (void *)rendezvous;

	rc = diminuto_mux_register_accept(&mux, fd);
	ASSERT(rc >= 0);

	while (!diminuto_terminator_check()) {

		rc = diminuto_mux_wait(&mux, -1);
		ASSERT(rc >= 0);

		fd = diminuto_mux_ready_accept(&mux);
		if (fd >= 0) {

			here = diminuto_fd_map_ref(map, fd);
			ASSERT(here != (void **)0);
			ASSERT((BIO *)*here == rendezvous);

			connection = codex_server_connection_new(context, rendezvous);
			ASSERT(connection != (SSL *)0);

			rc = codex_connection_verify(connection, expected);
			if (rc <= 0) {

				(void)codex_connection_free(connection);

			} else {

				fd = codex_connection_descriptor(connection);
				ASSERT(fd >= 0);

				DIMINUTO_LOG_DEBUG("%s: connection=%p fd=%d\n", connection, fd);

				here = diminuto_fd_map_ref(map, fd);
				ASSERT(here != (void **)0);
				ASSERT(*here == (void *)0);
				*here = (void *)connection;

				rc = diminuto_mux_register_read(&mux, fd);
				ASSERT(rc >= 0);

			}

		}

		fd = diminuto_mux_ready_read(&mux);
		if (fd >= 0) {

			here = diminuto_fd_map_ref(map, fd);
			ASSERT(here != (void **)0);
			ASSERT(*here != (void *)0);
			connection = (SSL *)*here;

			rc = codex_connection_read(connection, buffer, sizeof(buffer));
			DIMINUTO_LOG_DEBUG("%s: connection=%p read=%d\n", connection, rc);
			if (rc > 0) {
				for (reads = rc, writes = 0; writes < reads; writes += rc)
					rc = codex_connection_write(connection, buffer + writes, reads - writes);
					DIMINUTO_LOG_DEBUG("%s: connection=%p write=%d\n", connection, rc);
					if (rc <= 0) {
						break;
					}
			}

			if (rc <= 0) {

				rc = codex_connection_close(connection);
				ASSERT(rc >= 0);

				connection = codex_connection_free(connection);
				ASSERT(connection == (SSL *)0);

				*here = (void *)0;

			}

		}

	}

	diminuto_mux_fini(&mux);

	fd = codex_rendezvous_descriptor(rendezvous);
	ASSERT(fd >= 0);

	here = diminuto_fd_map_ref(map, fd);
	ASSERT(here != (void **)0);
	ASSERT(*here == rendezvous);
	*here = (void *)0;

	rendezvous = codex_server_rendezvous_free(rendezvous);
	ASSERT(rendezvous == (BIO *)0);

	for (fd = 0; fd < count; ++fd) {

		here = diminuto_fd_map_ref(map, fd);
		ASSERT(here != (void **)0);
		if (*here == (void *)0) { continue; }
		connection = (SSL *)*here;

		rc = codex_connection_close(connection);
		ASSERT(rc >= 0);

		connection = codex_connection_free(connection);
		ASSERT(connection == (SSL *)0);

		*here = (void *)0;

	}

	context = codex_context_free(context);
	EXPECT(context == (SSL_CTX *)0);

	EXIT();
}

