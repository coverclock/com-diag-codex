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
#include "com/diag/diminuto/diminuto_mux.h"
#include "com/diag/diminuto/diminuto_delay.h"
#include "com/diag/diminuto/diminuto_hangup.h"
#include "com/diag/diminuto/diminuto_fletcher.h"
#include "com/diag/diminuto/diminuto_timer.h"
#include "com/diag/diminuto/diminuto_frequency.h"
#include "com/diag/diminuto/diminuto_alarm.h"
#include "com/diag/diminuto/diminuto_fd.h"
#include "com/diag/codex/codex.h"
#include "unittest-codex.h"
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>

static const char * program = "unittest-core-client";
static const char * farend = "localhost:49162";
static const char * expected = "server.prairiethorn.org";
static diminuto_ticks_t period = 0;
static size_t bufsize = 256;
static const char * pathcaf = COM_DIAG_CODEX_OUT_CRT_PATH "/" "root.pem";
static const char * pathcap = (const char *)0;
static const char * pathcrt = COM_DIAG_CODEX_OUT_CRT_PATH "/" "client.pem";
static const char * pathkey = COM_DIAG_CODEX_OUT_CRT_PATH "/" "client.pem";
static const char * pathdhf = COM_DIAG_CODEX_OUT_CRT_PATH "/" "dh.pem";
static int selfsigned = -1;

int main(int argc, char ** argv)
{
	uint8_t * buffer = (uint8_t *)0;
	int rc = -1;
	codex_context_t * ctx = (codex_context_t *)0;
	diminuto_mux_t mux = { 0 };
	int fd = -1;
	codex_connection_t * ssl = (codex_connection_t *)0;
	ssize_t bytes = -1;
	ssize_t reads = -1;
	ssize_t writes = -1;
	bool eof = false;
	uint64_t input = 0;
	uint64_t output = 0;
	char * endptr = (char *)0;
	uint16_t f16source = 0;
	uint8_t f16sourceA = 0;
	uint8_t f16sourceB = 0;
	uint16_t f16sink = 0;
	uint8_t f16sinkA = 0;
	uint8_t f16sinkB = 0;
	long count = 0;
	diminuto_sticks_t ticks = -1;
	long prior = -1;
    int opt = '\0';
    extern char * optarg;

	(void)diminuto_core_enable();

	diminuto_log_setmask();

    program = ((program = strrchr(argv[0], '/')) == (char *)0) ? argv[0] : program + 1;

    while ((opt = getopt(argc, argv, "B:C:D:K:P:R:SVf:e:p:sv?")) >= 0) {

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
        	pathcap = (*optarg != '\0') ? optarg : (const char *)0;
        	break;

        case 'R':
        	pathcaf = (*optarg != '\0') ? optarg : (const char *)0;
        	break;

        case 'S':
        	selfsigned = 0;
        	break;

        case 'e':
            expected = (*optarg != '\0') ? optarg : (const char *)0;
            break;

        case 'f':
        	farend = optarg;
        	break;

        case 'p':
        	period = strtol(optarg, &endptr, 0);
        	break;

        case 's':
        	selfsigned = 1;
        	break;

        case '?':
        	fprintf(stderr, "usage: %s [ -B BUFSIZE ] [ -C CERTIFICATEFILE ] [ -D DHPARMSFILE ] [ -K PRIVATEKEYFILE ] [ -P CERTIFICATESPATH ] [ -R ROOTFILE ] [ -e EXPECTED ] [ -e EXPECTED ] [ -f FAREND ] [ -p SECONDS ] [ -S | -s ]\n", program);
            return 1;
            break;

        }

    }

	DIMINUTO_LOG_INFORMATION("%s: BEGIN B=%zu C=\"%s\" D=\"%s\" K=\"%s\" P=\"%s\" R=\"%s\" f=\"%s\" e=\"%s\" p=%llu s=%d\n", program, bufsize, pathcrt, pathdhf, pathkey, (pathcap == (const char *)0) ? "" : pathcap, (pathcaf == (const char *)0) ? "" : pathcaf, farend, (expected == (const char *)0) ? "" : expected, period, selfsigned);

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

	if (selfsigned >= 0) {
	    extern int codex_set_self_signed_certificates(int);
		codex_set_self_signed_certificates(!!selfsigned);
	}

	rc = codex_initialize();
	ASSERT(rc == 0);

	rc = codex_parameters(pathdhf);
	ASSERT(rc == 0);

	ctx = codex_client_context_new(pathcaf, pathcap, pathcrt, pathkey);
	ASSERT(ctx != (SSL_CTX *)0);

	ssl = codex_client_connection_new(ctx, farend);
	ASSERT(ssl != (SSL *)0);
	EXPECT(!codex_connection_is_server(ssl));

	fd = codex_connection_descriptor(ssl);
	ASSERT(fd >= 0);
	ASSERT(fd != STDIN_FILENO);
	ASSERT(fd != STDOUT_FILENO);

	DIMINUTO_LOG_DEBUG("%s: RUN connection=%p fd=%d\n", program, ssl, fd);

	rc = codex_connection_verify(ssl, expected);
	if (rc == CODEX_VERIFY_FAILED) {

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

		if (diminuto_alarm_check()) {
			DIMINUTO_LOG_INFORMATION("%s: SIGALRM eof=%d input=%llu output=%llu f16source=0x%4.4x f16sink=0x%4.4x\n", program, eof, ULL(input), ULL(output), f16sink, f16source);
		}

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

			fd = diminuto_mux_ready_read(&mux);
			if (fd < 0) {

				break;

			} else if (fd == codex_connection_descriptor(ssl)) {

				do {

					bytes = codex_connection_read(ssl, buffer, bufsize);
					DIMINUTO_LOG_DEBUG("%s: READ connection=%p bytes=%d\n", program, ssl, bytes);
					if (bytes <= 0) {
						rc = diminuto_mux_unregister_read(&mux, fd);
						ASSERT(rc >= 0);
						break;
					}

					bytes = diminuto_fd_write_generic(STDOUT_FILENO, buffer, bytes, bytes);
					if (bytes <= 0) {
						break;
					}

					f16sink = diminuto_fletcher_16(buffer, bytes, &f16sinkA, &f16sinkB);
					output += bytes;

				} while (codex_connection_is_ready(ssl));

			} else if (fd == STDIN_FILENO) {

				bytes = diminuto_fd_read(STDIN_FILENO, buffer, bufsize);
				if (bytes <= 0) {
					DIMINUTO_LOG_INFORMATION("%s: EOF fd=%d\n", program, fd);
					rc = diminuto_mux_unregister_read(&mux, fd);
					ASSERT(rc >= 0);
					eof = true;
					continue;
				}

				f16source = diminuto_fletcher_16(buffer, bytes, &f16sourceA, &f16sourceB);
				input += bytes;

				for (reads = bytes, writes = 0; writes < reads; writes += bytes) {
					bytes = codex_connection_write(ssl, buffer + writes, reads - writes);
					DIMINUTO_LOG_DEBUG("%s: WRITE connection=%p bytes=%d\n", program, ssl, bytes);
					if (bytes <= 0) {
						break;
					}
				}
				if (bytes <= 0) {
					break;
				}

			} else {

				FATAL();

			}

		}

		diminuto_yield();

	}

	ticks = diminuto_timer_periodic(0);
	ASSERT(ticks >= 0);

	DIMINUTO_LOG_INFORMATION("%s: END eof=%d input=%llu output=%llu f16source=0x%4.4x f16sink=0x%4.4x\n", program, eof, ULL(input), ULL(output), f16sink, f16source);
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

