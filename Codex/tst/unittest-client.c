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
#include "com/diag/diminuto/diminuto_hangup.h"
#include "com/diag/diminuto/diminuto_fletcher.h"
#include "com/diag/diminuto/diminuto_timer.h"
#include "com/diag/diminuto/diminuto_frequency.h"
#include "com/diag/diminuto/diminuto_alarm.h"
#include "com/diag/codex/codex.h"
#include "../src/codex_unittest.h"
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>

int main(int argc, char ** argv)
{
	const char * program = "unittest-client";
	const char * farend = "localhost:49152";
	const char * expected = "server.prairiethorn.org";
	bool enforce = true;
	diminuto_ticks_t period = 0;
	size_t bufsize = 256;
	uint8_t * buffer = (uint8_t *)0;
	long seconds = -1;
	long octets = -1;
	int rc = -1;
	codex_context_t * ctx = (codex_context_t *)0;
	diminuto_mux_t mux = { 0 };
	int fd = -1;
	codex_connection_t * ssl = (codex_connection_t *)0;
	int bytes = -1;
	int reads = -1;
	int writes = -1;
	bool eof = false;
	size_t input = 0;
	size_t output = 0;
	char * endptr = (char *)0;
	uint16_t f16source = 0;
	uint8_t f16sourceA = 0;
	uint8_t f16sourceB = 0;
	uint16_t f16sink = 0;
	uint8_t f16sinkA = 0;
	uint8_t f16sinkB = 0;
	size_t sourced = 0;
	size_t sunk = 0;
	long count = 0;
	diminuto_sticks_t ticks = -1;
	long prior = -1;
    int opt = '\0';
    extern char * optarg;

	(void)diminuto_core_enable();

	diminuto_log_setmask();

    program = ((program = strrchr(argv[0], '/')) == (char *)0) ? argv[0] : program + 1;

    while ((opt = getopt(argc, argv, "B:Vf:b:e:p:s:v?")) >= 0) {

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

        case 'f':
        	farend = optarg;
        	break;

        case 'p':
        	period = strtol(optarg, &endptr, 0);
        	break;

        case 's':
        	seconds = strtol(optarg, &endptr, 0);
        	break;

        case 'v':
        	enforce = true;
        	break;

        case '?':
        	fprintf(stderr, "usage: %s [ -B BUFSIZE ] [ -b BYTES ] [ -e EXPECTED ] [ -f FAREND ] [ -p SECONDS ] [ -s SECONDS ] [ -V | -v ]\n", program);
            return 1;
            break;

        }

    }

	DIMINUTO_LOG_INFORMATION("%s: BEGIN B=%zu b=%ld f=\"%s\" e=\"%s\" p=%llu s=%ld v=%d\n", program, bufsize, bytes, farend, expected, period, seconds, enforce);

	buffer = (uint8_t *)malloc(bufsize);
	ASSERT(buffer != (uint8_t *)0);

	rc = diminuto_hangup_install(!0);
	ASSERT(rc == 0);

	if (period > 0) {

		rc = diminuto_alarm_install(!0);
		ASSERT(rc == 0);

 		ticks = diminuto_timer_periodic(period * diminuto_frequency());
		ASSERT(ticks >= 0);

	}

	diminuto_mux_init(&mux);

	rc = codex_initialize();
	ASSERT(rc == 0);

	rc = codex_parameters(COM_DIAG_CODEX_OUT_CRT_PATH "/" "dh.pem");
	ASSERT(rc == 0);

	ctx = codex_client_context_new(COM_DIAG_CODEX_OUT_CRT_PATH "/" "root.pem", (const char *)0, COM_DIAG_CODEX_OUT_CRT_PATH "/" "client.pem", COM_DIAG_CODEX_OUT_CRT_PATH "/" "client.pem");
	ASSERT(ctx != (SSL_CTX *)0);

	ssl = codex_client_connection_new(ctx, farend);
	ASSERT(ssl != (SSL *)0);
	ASSERT(!codex_connection_is_server(ssl));

	fd = codex_connection_descriptor(ssl);
	ASSERT(fd >= 0);
	ASSERT(fd != STDIN_FILENO);
	ASSERT(fd != STDOUT_FILENO);

	DIMINUTO_LOG_DEBUG("%s: RUN connection=%p fd=%d\n", program, ssl, fd);

	rc = codex_connection_verify(ssl, expected);
	if (enforce && (rc != CODEX_CONNECTION_VERIFY_FQDN)) {

		rc = codex_connection_close(ssl);
		ASSERT(rc >= 0);

		ssl = codex_connection_free(ssl);
		ASSERT(ssl == (SSL *)0);

		exit(1);
	}

	if (seconds > 0) {
		prior = codex_connection_renegotiate_seconds(ssl, seconds);
		DIMINUTO_LOG_INFORMATION("%s: RUN connection=%p seconds=%ld was=%ld\n", program, ssl, seconds, prior);
	}

	if (octets > 0) {
		prior = codex_connection_renegotiate_bytes(ssl, octets);
		DIMINUTO_LOG_INFORMATION("%s: RUN connection=%p bytes=%ld was=%ld\n", program, ssl, bytes, prior);
	}

	rc = diminuto_mux_register_read(&mux, STDIN_FILENO);
	ASSERT(rc >= 0);

	rc = diminuto_mux_register_read(&mux, fd);
	ASSERT(rc >= 0);

	eof = false;
	input = 0;
	output = 0;
	while ((!eof) || (output < input)) {

		if (diminuto_alarm_check()) {
			DIMINUTO_LOG_INFORMATION("%s: RUN eof=%d input=%zu output=%zu f16source=0x%4.4x f16sink=0x%4.4x renegotiations=%ld\n", program, eof, input, output, f16sink, f16source, count);
		}

		if (diminuto_hangup_check()) {
			DIMINUTO_LOG_INFORMATION("%s: SIGHUP\n", program);
			rc = codex_connection_renegotiate(ssl);
			ASSERT(rc == 0);
		}

		rc = diminuto_mux_wait(&mux, -1);
		if ((rc == 0) || ((rc < 0) && (errno == EINTR))) {
			diminuto_yield();
			continue;
		}
		ASSERT(rc > 0);

		fd = diminuto_mux_ready_read(&mux);
		if (fd == codex_connection_descriptor(ssl)) {

			bytes = codex_connection_read(ssl, buffer, bufsize);
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

			f16source = diminuto_fletcher_16(buffer, writes, &f16sourceA, &f16sourceB);

			output += writes;

		} else if (fd == STDIN_FILENO) {

			bytes = read(fd, buffer, bufsize);
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

			f16sink = diminuto_fletcher_16(buffer, reads, &f16sinkA, &f16sinkB);

			input += reads;

		} else {

			FAILURE();

		}

	}

	ticks = diminuto_timer_periodic(0);
	ASSERT(ticks >= 0);

	count = codex_connection_renegotiations(ssl);
	EXPECT(count >= 0);

	DIMINUTO_LOG_INFORMATION("%s: END eof=%d input=%zu output=%zu f16source=0x%4.4x f16sink=0x%4.4x renegotiations=%ld\n", program, eof, input, output, f16sink, f16source, count);
	EXPECT(eof);
	EXPECT(input == output);
	EXPECT(f16source == f16sink);

	diminuto_mux_fini(&mux);

	rc = codex_connection_close(ssl);
	EXPECT(rc >= 0);

	ssl = codex_connection_free(ssl);
	EXPECT(ssl == (codex_connection_t *)0);

	ctx = codex_context_free(ctx);
	EXPECT(ctx == (codex_context_t *)0);

	free(buffer);

	EXIT();
}

