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
	const char * program = "unittest-client";
	const char * farend = "localhost:49152";
	const char * expected = "server.prairiethorn.org";
	bool enforce = true;
	int rc;
	codex_context_t * ctx;
	diminuto_mux_t mux;
	int fd;
	codex_connection_t * ssl;
	uint8_t buffer[256];
	int bytes;
	int reads;
	int writes;
	bool eof;
	size_t input;
	size_t output;
    int opt;
    extern char * optarg;

	(void)diminuto_core_enable();

	diminuto_log_setmask();

    program = ((program = strrchr(argv[0], '/')) == (char *)0) ? argv[0] : program + 1;

    while ((opt = getopt(argc, argv, "Ve:f:v?")) >= 0) {

        switch (opt) {

        case 'V':
        	enforce = false;
        	break;

        case 'e':
            expected = optarg;
            break;

        case 'f':
        	farend = optarg;
        	break;

        case 'v':
        	enforce = true;
        	break;

        case '?':
        	fprintf(stderr, "usage: %s [ -f %s ] [ -e %s ] [ -V | -v ]\n", program, farend, expected);
            return 1;
            break;

        }

    }

	DIMINUTO_LOG_DEBUG("%s: farend=\"%s\" expected=\"%s\" enforce=%d length=%zu\n", program, farend, expected, enforce, sizeof(buffer));

	diminuto_mux_init(&mux);

	rc = codex_initialize();
	ASSERT(rc == 0);

	rc = codex_parameters(COM_DIAG_CODEX_OUT_CRT_PATH "/" "dh.pem");
	ASSERT(rc == 0);

	ctx = codex_client_context_new(COM_DIAG_CODEX_OUT_CRT_PATH "/" "root.pem", (const char *)0, COM_DIAG_CODEX_OUT_CRT_PATH "/" "client.pem", COM_DIAG_CODEX_OUT_CRT_PATH "/" "client.pem");
	ASSERT(ctx != (SSL_CTX *)0);

	ssl = codex_client_connection_new(ctx, farend);
	ASSERT(ssl != (SSL *)0);

	fd = codex_connection_descriptor(ssl);
	ASSERT(fd >= 0);
	ASSERT(fd != STDIN_FILENO);
	ASSERT(fd != STDOUT_FILENO);

	DIMINUTO_LOG_DEBUG("%s: connection=%p fd=%d\n", program, ssl, fd);

	rc = codex_connection_verify(ssl, expected);
	if (enforce && (rc != CODEX_CONNECTION_VERIFY_FQDN)) {

		rc = codex_connection_close(ssl);
		ASSERT(rc >= 0);

		ssl = codex_connection_free(ssl);
		ASSERT(ssl == (SSL *)0);

		exit(1);
	}

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

			bytes = codex_connection_read(ssl, buffer, sizeof(buffer));
			DIMINUTO_LOG_DEBUG("%s: connection=%p read=%d\n", program, ssl, bytes);
			if (bytes <= 0) {
				rc = diminuto_mux_unregister_read(&mux, fd);
				ASSERT(rc >= 0);
				break;
			}

			for (reads = bytes, writes = 0; writes < reads; writes += bytes) {
				bytes = write(STDOUT_FILENO, buffer + writes, reads - writes);
				DIMINUTO_LOG_DEBUG("%s: fd=%d written=%d\n", program, STDOUT_FILENO, bytes);
				if (bytes <= 0) {
					if (bytes < 0) { diminuto_perror("write"); }
					break;
				}
			}

			output += writes;

		} else if (fd == STDIN_FILENO) {

			bytes = read(fd, buffer, sizeof(buffer));
			DIMINUTO_LOG_DEBUG("%s: fd=%d read=%d\n", program, fd, bytes);
			if (bytes <= 0) {
				if (bytes < 0) { diminuto_perror("read"); }
				rc = diminuto_mux_unregister_read(&mux, fd);
				ASSERT(rc >= 0);
				eof = true;
				continue;
			}

			for (reads = bytes, writes = 0; writes < reads; writes += bytes) {
				bytes = codex_connection_write(ssl, buffer + writes, reads - writes);
				DIMINUTO_LOG_DEBUG("%s: connection=%p written=%d\n", program, ssl, bytes);
				if (bytes <= 0) {
					break;
				}
			}

			input += reads;

		} else {

			FAILURE();

		}
	}

	EXPECT(eof && (output == input));

	diminuto_mux_fini(&mux);

	rc = codex_connection_close(ssl);
	EXPECT(rc >= 0);

	ssl = codex_connection_free(ssl);
	EXPECT(ssl == (codex_connection_t *)0);

	ctx = codex_context_free(ctx);
	EXPECT(ctx == (codex_context_t *)0);

	EXIT();
}

