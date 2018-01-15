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
#include "com/diag/diminuto/diminuto_mux.h"
#include "com/diag/codex/codex.h"
#include "../src/codex_unittest.h"
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char ** argv)
{
	const char * name = "unittest-client";
	const char * farend = "localhost:49152";
	const char * expected = "server.prairiethorn.org";
	int rc;
	SSL_CTX * context;
	diminuto_mux_t mux;
	int fd;
	SSL * connection;
	uint8_t buffer[256];
	int reads;
	int writes;

	(void)diminuto_core_enable();

	diminuto_log_setmask();

	if (argc >= 1) {
		name = argv[0];
	}

	if (argc >= 2) {
		farend = argv[1];
	}

	if (argc >= 3) {
		expected = argv[2];
	}

	rc = diminuto_terminator_install(!0);
	ASSERT(rc >= 0);

	DIMINUTO_LOG_DEBUG("%s: farend=\"%s\" expected=\"%s\" length=%zu\n", name, farend, expected, sizeof(buffer));

	diminuto_mux_init(&mux);

	rc = codex_initialize();
	ASSERT(rc == 0);

	rc = codex_parameters(COM_DIAG_CODEX_OUT_ETC_PATH "/dh256.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/dh512.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/dh1024.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/dh2048.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/dh4096.pem");
	ASSERT(rc == 0);

	context = codex_client_context_new(COM_DIAG_CODEX_OUT_ETC_PATH "/root.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/client.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/client.pem");
	ASSERT(context != (SSL_CTX *)0);

	connection = codex_client_connection_new(context, farend);
	ASSERT(connection != (SSL *)0);

	rc = codex_connection_verify(connection, expected);
	if (rc <= 0) {

		rc = codex_connection_close(connection);
		ASSERT(rc >= 0);

		connection = codex_connection_free(connection);
		ASSERT(connection == (SSL *)0);

		exit(1);
	}

	fd = codex_connection_descriptor(connection);
	ASSERT(fd >= 0);
	ASSERT(fd != STDIN_FILENO);
	ASSERT(fd != STDOUT_FILENO);

	rc = diminuto_mux_register_read(&mux, STDIN_FILENO);
	ASSERT(rc >= 0);

	rc = diminuto_mux_register_read(&mux, fd);
	ASSERT(rc >= 0);

	while (!diminuto_terminator_check()) {

		rc = diminuto_mux_wait(&mux, -1);
		ASSERT(rc >= 0);

		fd = diminuto_mux_ready_read(&mux);
		if (fd == codex_connection_descriptor(connection)) {

			rc = codex_connection_read(connection, buffer, sizeof(buffer));
			DIMINUTO_LOG_DEBUG("%s: connection=%p read=%d\n", connection, rc);
			if (rc <= 0) {
				break;
			}

			for (reads = rc, writes = 0; writes < reads; writes += rc) {
				rc = write(STDOUT_FILENO, buffer + writes, reads - writes);
				DIMINUTO_LOG_DEBUG("%s: fd=%d written=%d\n", STDOUT_FILENO, rc);
				if (rc <= 0) {
					break;
				}

			}

		} else if (fd == STDIN_FILENO) {

			rc = read(STDIN_FILENO, buffer, sizeof(buffer));
			DIMINUTO_LOG_DEBUG("%s: fd=%d read=%d\n", STDIN_FILENO, rc);
			if (rc <= 0) {
				break;
			}

			for (reads = rc, writes = 0; writes < reads; writes += rc) {
				rc = codex_connection_write(connection, buffer + writes, reads - writes);
				DIMINUTO_LOG_DEBUG("%s: connection=%p written=%d\n", connection, rc);
				if (rc <= 0) {
					break;
				}
			}

		} else {

			DIMINUTO_LOG_DEBUG("%s: fd=%d\n", fd);

		}
	}

	diminuto_mux_fini(&mux);

	rc = codex_connection_close(connection);
	ASSERT(rc >= 0);

	connection = codex_connection_free(connection);
	ASSERT(connection == (SSL *)0);

	context = codex_context_free(context);
	EXPECT(context == (SSL_CTX *)0);

	EXIT();
}

