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
#include "com/diag/diminuto/diminuto_mux.h"
#include "com/diag/diminuto/diminuto_delay.h"
#include "com/diag/codex/codex.h"
#include "../src/codex_unittest.h"
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdbool.h>

int main(int argc, char ** argv)
{
	const char * name = "unittest-client";
	const char * farend = "localhost:49152";
	const char * expected = "server.prairiethorn.org";
	int rc;
	codex_context_t * ctx;
	diminuto_mux_t mux;
	int fd;
	codex_connection_t * ssl;
	uint8_t buffer[256];
	int reads;
	int writes;
	bool eof;
	size_t input;
	size_t output;

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

	DIMINUTO_LOG_DEBUG("%s: farend=\"%s\" expected=\"%s\" length=%zu\n", name, farend, expected, sizeof(buffer));

	diminuto_mux_init(&mux);

	rc = codex_initialize();
	ASSERT(rc == 0);

	rc = codex_parameters(COM_DIAG_CODEX_OUT_ETC_PATH "/dh256.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/dh512.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/dh1024.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/dh2048.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/dh4096.pem");
	ASSERT(rc == 0);

	ctx = codex_client_context_new(COM_DIAG_CODEX_OUT_ETC_PATH "/root.pem", COM_DIAG_CODEX_OUT_ETC_PATH, COM_DIAG_CODEX_OUT_ETC_PATH "/client.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/client.pem");
	ASSERT(ctx != (SSL_CTX *)0);

	ssl = codex_client_connection_new(ctx, farend);
	ASSERT(ssl != (SSL *)0);

	rc = codex_connection_verify(ssl, expected);
#if !0
	rc = 0;
#endif
	if (rc < 0) {

		rc = codex_connection_close(ssl);
		ASSERT(rc >= 0);

		ssl = codex_connection_free(ssl);
		ASSERT(ssl == (SSL *)0);

		exit(1);
	}

	fd = codex_connection_descriptor(ssl);
	ASSERT(fd >= 0);
	ASSERT(fd != STDIN_FILENO);
	ASSERT(fd != STDOUT_FILENO);

	rc = diminuto_mux_register_read(&mux, STDIN_FILENO);
	ASSERT(rc >= 0);

	rc = diminuto_mux_register_read(&mux, fd);
	ASSERT(rc >= 0);

	eof = false;
	input = 0;
	output = 0;
	while ((!eof) || (output < input)) {

		rc = diminuto_mux_wait(&mux, -1);
		if ((rc == 0) || ((rc < 0) && (errno == EINTR))) {
			diminuto_yield();
			continue;
		}
		ASSERT(rc > 0);

		fd = diminuto_mux_ready_read(&mux);
		if (fd == codex_connection_descriptor(ssl)) {

			rc = codex_connection_read(ssl, buffer, sizeof(buffer));
			DIMINUTO_LOG_DEBUG("%s: connection=%p read=%d\n", name, ssl, rc);
			if (rc <= 0) {
				rc = diminuto_mux_unregister_read(&mux, fd);
				ASSERT(rc >= 0);
				break;
			}

			for (reads = rc, writes = 0; writes < reads; writes += rc) {
				rc = write(STDOUT_FILENO, buffer + writes, reads - writes);
				DIMINUTO_LOG_DEBUG("%s: fd=%d written=%d\n", name, STDOUT_FILENO, rc);
				if (rc <= 0) {
					if (rc < 0) { diminuto_perror("write"); }
					break;
				}
			}

			output += writes;

		} else if (fd == STDIN_FILENO) {

			rc = read(fd, buffer, sizeof(buffer));
			DIMINUTO_LOG_DEBUG("%s: fd=%d read=%d\n", name, fd, rc);
			if (rc <= 0) {
				if (rc < 0) { diminuto_perror("read"); }
				rc = diminuto_mux_unregister_read(&mux, fd);
				ASSERT(rc >= 0);
				eof = true;
				continue;
			}

			for (reads = rc, writes = 0; writes < reads; writes += rc) {
				rc = codex_connection_write(ssl, buffer + writes, reads - writes);
				DIMINUTO_LOG_DEBUG("%s: connection=%p written=%d\n", name, ssl, rc);
				if (rc <= 0) {
					break;
				}
			}

			input += reads;

		} else {

			DIMINUTO_LOG_DEBUG("%s: fd=%d\n", name, fd);

		}
	}

	diminuto_mux_fini(&mux);

	rc = codex_connection_close(ssl);
	ASSERT(rc >= 0);

	ssl = codex_connection_free(ssl);
	ASSERT(ssl == (codex_connection_t *)0);

	ctx = codex_context_free(ctx);
	EXPECT(ctx == (codex_context_t *)0);

	EXIT();
}

