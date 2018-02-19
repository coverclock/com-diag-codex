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
#include "com/diag/diminuto/diminuto_pipe.h"
#include "com/diag/codex/codex.h"
#include "unittest-codex.h"
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>

static const char * program = "unittest-machine-client";
static const char * farend = "localhost:49182";
static const char * expected = "server.prairiethorn.org";
static bool enforce = true;
static diminuto_ticks_t period = 0;
static long seconds = -1; /* Unimplemented. */
static long octets = -1; /* Unimplemented. */
static size_t bufsize = 256;
static const char * pathcaf = COM_DIAG_CODEX_OUT_CRT_PATH "/" "root.pem";
static const char * pathcap = (const char *)0;
static const char * pathcrt = COM_DIAG_CODEX_OUT_CRT_PATH "/" "client.pem";
static const char * pathkey = COM_DIAG_CODEX_OUT_CRT_PATH "/" "client.pem";
static const char * pathdhf = COM_DIAG_CODEX_OUT_CRT_PATH "/" "dh.pem";

int main(int argc, char ** argv)
{
	static const int READER = 0;
	static const int WRITER = 1;
	codex_state_t states[2] = { CODEX_STATE_START, CODEX_STATE_COMPLETE };
	void * buffers[2] = { (void *)0, (void *)0 };
	codex_header_t headers[2] = { 0, 0 };
	uint8_t * heres[2] = { (uint8_t *)0, (uint8_t *)0 };
	size_t lengths[2] = { 0, 0 };
	codex_connection_t * ssl = (codex_connection_t *)0;
	codex_state_t state = CODEX_STATE_FINAL;
	void * temp = (void *)0;
	int rc = -1;
	codex_context_t * ctx = (codex_context_t *)0;
	diminuto_mux_t mux = { 0 };
	int fd = -1;
	ssize_t bytes = -1;
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
	diminuto_sticks_t ticks = -1;
	codex_indication_t indication = CODEX_INDICATION_NONE;
	bool pending = false;
    int opt = '\0';
    extern char * optarg;

	(void)diminuto_core_enable();

	diminuto_log_setmask();

    program = ((program = strrchr(argv[0], '/')) == (char *)0) ? argv[0] : program + 1;

    while ((opt = getopt(argc, argv, "B:C:D:K:P:R:Vf:b:e:p:s:v?")) >= 0) {

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
        	fprintf(stderr, "usage: %s [ -B BUFSIZE ] [ -C CERTIFICATEFILE ] [ -D DHPARMSFILE ] [ -K PRIVATEKEYFILE ] [ -P CERTIFICATESPATH ] [ -R ROOTFILE ] [ -b BYTES ] [ -e EXPECTED ] [ -b BYTES ] [ -e EXPECTED ] [ -f FAREND ] [ -p SECONDS ] [ -s SECONDS ] [ -V | -v ]\n", program);
            return 1;
            break;

        }

    }

	DIMINUTO_LOG_INFORMATION("%s: BEGIN B=%zu C=\"%s\" D=\"%s\" K=\"%s\" P=\"%s\" R=\"%s\" b=%ld f=\"%s\" e=\"%s\" p=%llu s=%ld v=%d\n", program, bufsize, pathcrt, pathdhf, pathkey, (pathcap == (const char *)0) ? "" : pathcap, pathcaf, octets, farend, expected, period, seconds, enforce);

	rc = diminuto_hangup_install(!0);
	ASSERT(rc == 0);

	if (period > 0) {

		rc = diminuto_alarm_install(!0);
		ASSERT(rc == 0);

 		ticks = diminuto_timer_periodic(period * diminuto_frequency());
		ASSERT(ticks >= 0);

	}

	rc = diminuto_pipe_install(!0);
	ASSERT(rc == 0);

	diminuto_mux_init(&mux);

	buffers[READER] = malloc(bufsize);
	ASSERT(buffers[READER] != (uint8_t *)0);
	buffers[WRITER] = malloc(bufsize);
	ASSERT(buffers[WRITER] != (uint8_t *)0);

	rc = codex_initialize();
	ASSERT(rc == 0);

	rc = codex_parameters(pathdhf);
	ASSERT(rc == 0);

	ctx = codex_client_context_new(pathcaf, pathcap, pathcrt, pathkey);
	ASSERT(ctx != (SSL_CTX *)0);

	ssl = codex_client_connection_new(ctx, farend);
	ASSERT(ssl != (SSL *)0);
	ADVISE(!codex_connection_is_server(ssl));

	fd = codex_connection_descriptor(ssl);
	ASSERT(fd >= 0);
	ASSERT(fd != STDIN_FILENO);
	ASSERT(fd != STDOUT_FILENO);

	rc = diminuto_mux_register_read(&mux, fd);
	ASSERT(rc >= 0);

	rc = diminuto_mux_register_write(&mux, fd);
	ASSERT(rc >= 0);

	rc = diminuto_mux_register_read(&mux, STDIN_FILENO);
	ASSERT(rc >= 0);

	eof = false;
	input = 0;
	output = 0;
	while ((!eof) || (output < input)) {

		if (diminuto_alarm_check()) {
			DIMINUTO_LOG_INFORMATION("%s: SIGALRM eof=%d input=%zu output=%zu f16source=0x%4.4x f16sink=0x%4.4x\n", program, eof, input, output, f16sink, f16source);
		}

		if (diminuto_hangup_check()) {
			DIMINUTO_LOG_INFORMATION("%s: SIGHUP\n", program);
			indication = CODEX_INDICATION_NEAREND;
		}

		if (diminuto_pipe_check()) {
			DIMINUTO_LOG_INFORMATION("%s: SIGPIPE\n", program);
			/* Unimplemented. */
		}

		rc = diminuto_mux_wait(&mux, -1);
		if ((rc == 0) || ((rc < 0) && (errno == EINTR))) {
			diminuto_yield();
			continue;
		}
		ASSERT(rc > 0);

		fd = diminuto_mux_ready_write(&mux);
		if (fd == codex_connection_descriptor(ssl)) {

			if (states[WRITER] == CODEX_STATE_COMPLETE) {
				/* Do nothing. */
			} else if (states[WRITER] == CODEX_STATE_IDLE) {
				/* Do nothing. */
			} else {

				state = codex_machine_writer(states[WRITER], expected, ssl, &(headers[WRITER]), buffers[WRITER], headers[WRITER], &(heres[WRITER]), &(lengths[WRITER]));

				if (state == CODEX_STATE_FINAL) {
					break;
				} else if (state == states[WRITER]) {
					/* Do nothing. */
				} else if (state != CODEX_STATE_COMPLETE) {
					/* Do nothing. */
				} else {

					DIMINUTO_LOG_DEBUG("%s: WRITE fd=%d bytes=%d\n", program, fd, headers[WRITER]);

				}

				states[WRITER] = state;

			}

		} else {
			/* Do nothing. */
		}

		fd = diminuto_mux_ready_read(&mux);
		if (fd == codex_connection_descriptor(ssl)) {

			if (states[READER] == CODEX_STATE_COMPLETE) {
				/* Cannot happen. */
			} else if (states[READER] == CODEX_STATE_IDLE) {
				/* Do nothing. */
			} else {

				state = codex_machine_reader(states[READER], expected, ssl, &(headers[READER]), buffers[READER], bufsize, &(heres[READER]), &(lengths[READER]));

				if (state == CODEX_STATE_FINAL) {
					break;
				} else if (state != CODEX_STATE_COMPLETE) {
					/* Do nothing. */
				} else if (headers[READER] == CODEX_INDICATION_FAREND) {

					DIMINUTO_LOG_INFORMATION("%s: INDICATION fd=%d indication=%d\n", program, fd, headers[READER]);

					indication = CODEX_INDICATION_FAREND;

					state = CODEX_STATE_IDLE;


				} else {

					DIMINUTO_LOG_DEBUG("%s: READ fd=%d bytes=%d\n", program, fd, headers[READER]);

					f16sink = diminuto_fletcher_16(buffers[READER], headers[READER], &f16sinkA, &f16sinkB);
					output += headers[READER];

					bytes = diminuto_fd_write_generic(STDOUT_FILENO, buffers[READER], headers[READER], headers[READER]);
					if (bytes <= 0) {
						break;
					}

					state = indication? CODEX_STATE_IDLE : CODEX_STATE_RESTART;

					if (pending)  {
						states[WRITER] = CODEX_STATE_START;
						pending = false;
					}

				}

				states[READER] = state;

			}

		} else if (fd == STDIN_FILENO) {

			if (states[WRITER] == CODEX_STATE_COMPLETE) {

				bytes = diminuto_fd_read(STDIN_FILENO, buffers[WRITER], bufsize);
				if (bytes <= 0) {
					DIMINUTO_LOG_INFORMATION("%s: EOF fd=%d\n", program, STDIN_FILENO);
					rc = diminuto_mux_unregister_read(&mux, STDIN_FILENO);
					ASSERT(rc >= 0);
					eof = true;
					continue;
				}

				headers[WRITER] = bytes;

				f16source = diminuto_fletcher_16(buffers[WRITER], headers[WRITER], &f16sourceA, &f16sourceB);
				input += headers[WRITER];

				states[WRITER] = indication ? CODEX_STATE_IDLE : (input == 0) ? CODEX_STATE_START : CODEX_STATE_RESTART;

			}

		} else {
			/* Do nothing. */
		}

		if (!indication) {
			/* Do nothing. */
		} else if (states[READER] != CODEX_STATE_IDLE) {
			/* Do nothing. */
		} else if (states[WRITER] != CODEX_STATE_IDLE) {
			/* Do nothing. */
		} else {

			DIMINUTO_LOG_INFORMATION("%s: INDICATING\n", program);

			if (indication == CODEX_INDICATION_NEAREND) {
				codex_state_t state = CODEX_STATE_RESTART;
				codex_header_t header = 0;
				uint8_t * here = (uint8_t *)0;
				size_t length = 0;

				do {
					state = codex_machine_writer(state, (char *)0, ssl, &header, (void *)0, CODEX_INDICATION_FAREND, &here, &length);
				} while ((state != CODEX_STATE_FINAL) && (state != CODEX_STATE_COMPLETE));

				if (state == CODEX_STATE_FINAL) {
					break;
				}

				/* TODO */

				states[READER] = CODEX_STATE_RESTART;
				states[WRITER] = CODEX_STATE_START;

			} else {

				states[READER] = CODEX_STATE_RESTART;
				states[WRITER] = CODEX_STATE_IDLE; /* (No change.) */
				pending = true;

			}

			indication = CODEX_INDICATION_NONE;

		}

		diminuto_yield();

	}

	ticks = diminuto_timer_periodic(0);
	ASSERT(ticks >= 0);

	DIMINUTO_LOG_INFORMATION("%s: END eof=%d input=%zu output=%zu f16source=0x%4.4x f16sink=0x%4.4x\n", program, eof, input, output, f16sink, f16source);
	EXPECT(eof);
	EXPECT(input == output);
	EXPECT(f16source == f16sink);

	diminuto_mux_fini(&mux);

	ssl = codex_connection_free(ssl);
	EXPECT(ssl == (codex_connection_t *)0);

	ctx = codex_context_free(ctx);
	EXPECT(ctx == (codex_context_t *)0);

	free(buffers[READER]);
	free(buffers[WRITER]);

	EXIT();
}

