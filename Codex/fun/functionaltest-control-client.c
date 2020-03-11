/* vi: set ts=4 expandtab shiftwidth=4: */
/**
 * @file
 *
 * Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
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
#include "com/diag/diminuto/diminuto_ipc4.h"
#include "com/diag/diminuto/diminuto_ipc6.h"
#include "unittest-codex.h"
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>

static const char * program = "unittest-control-client";
static const char * farend = "localhost:49162";
static const char * expected = "server.prairiethorn.org";
static diminuto_ticks_t period = 0;
static size_t bufsize = 256;
static const char * pathcaf = (const char *)0;
static const char * pathcap = (const char *)0;
static const char * pathcrl = (const char *)0;
static const char * pathcrt = (const char *)0;
static const char * pathkey = (const char *)0;
static const char * pathdhf = (const char *)0;
static int selfsigned = -1;

int main(int argc, char ** argv)
{
	uint8_t * buffer = (uint8_t *)0;
	int rc = -1;
	diminuto_mux_t mux = { 0 };
	int fd = -1;
	diminuto_ipc_endpoint_t endpoint = { 0 };
	int sock = -1;
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

    while ((opt = getopt(argc, argv, "B:C:D:K:L:P:R:SVf:e:p:sv?")) >= 0) {

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

        case 'L':
        	pathcrl = (*optarg != '\0') ? optarg : (const char *)0;
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
        	fprintf(stderr, "usage: %s [ -B BUFSIZE ] [ -C CERTIFICATEFILE ] [ -D DHPARMSFILE ] [ -K PRIVATEKEYFILE ] [ -L REVOCATIONFILE ] [ -P CERTIFICATESPATH ] [ -R ROOTFILE ] [ -e EXPECTED ] [ -e EXPECTED ] [ -f FAREND ] [ -p SECONDS ] [ -S | -s ]\n", program);
            return 1;
            break;

        }

    }

	DIMINUTO_LOG_INFORMATION("%s: BEGIN B=%zu C=\"%s\" D=\"%s\" K=\"%s\" L=\"%s\" P=\"%s\" R=\"%s\" f=\"%s\" e=\"%s\" p=%llu s=%d\n", program, bufsize, pathcrt, pathdhf, pathkey, (pathcrl == (const char *)0) ? "" : pathcrl, (pathcap == (const char *)0) ? "" : pathcap, (pathcaf == (const char *)0) ? "" : pathcaf, farend, (expected == (const char *)0) ? "" : expected, period, selfsigned);

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

	rc = diminuto_ipc_endpoint(farend, &endpoint);
	ASSERT(rc == 0);

	if (diminuto_ipc6_is_unspecified(&endpoint.ipv6)) {
		sock = diminuto_ipc4_stream_consumer(endpoint.ipv4, endpoint.tcp);
	} else {
		sock = diminuto_ipc6_stream_consumer(endpoint.ipv6, endpoint.tcp);
	}
	ASSERT(sock >= 0);

	fd = sock;
	ASSERT(fd >= 0);
	ASSERT(fd != STDIN_FILENO);
	ASSERT(fd != STDOUT_FILENO);

	DIMINUTO_LOG_DEBUG("%s: RUN connection=%d fd=%d\n", program, sock, fd);

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

			} else if (fd == sock) {

				do {

					bytes = diminuto_ipc4_stream_read(sock, buffer, bufsize);
					DIMINUTO_LOG_DEBUG("%s: READ connection=%d bytes=%d\n", program, sock, bytes);
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

				} while (false);

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
					bytes = diminuto_ipc4_stream_write(sock, buffer + writes, reads - writes);
					DIMINUTO_LOG_DEBUG("%s: WRITE connection=%d bytes=%d\n", program, sock, bytes);
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

	rc = diminuto_ipc4_close(sock);
	EXPECT(rc >= 0);

	free(buffer);

	EXIT();
}

