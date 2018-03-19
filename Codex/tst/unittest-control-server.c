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
#include "com/diag/diminuto/diminuto_ipc4.h"
#include "unittest-codex.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

static const char * program = "unittest-control-server";
static const char * nearend = "49162";
static const char * expected = "client.prairiethorn.org";
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
	int meetme = -1;
	diminuto_ipc_endpoint_t endpoint = { 0 };
	ssize_t count = 0;
	diminuto_fd_map_t * map = (diminuto_fd_map_t *)0;
	void ** here = (void **)0;
	diminuto_mux_t mux = { 0 };
	int fd = -1;
	int rendezvous = -1;
	int sock = -1;
	ssize_t bytes = -1;
	ssize_t reads = -1;
	ssize_t writes = -1;
	uintptr_t temp = 0;
	bool tripwire = false;
	char * endptr = (char *)0;
	long prior = -1;
    int opt = '\0';
    extern char * optarg;

	(void)diminuto_core_enable();

	diminuto_log_setmask();

    program = ((program = strrchr(argv[0], '/')) == (char *)0) ? argv[0] : program + 1;

    while ((opt = getopt(argc, argv, "B:C:D:K:L:P:R:SVe:n:sv?")) >= 0) {

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

        case 'n':
        	nearend = optarg;
        	break;

        case 's':
        	selfsigned = 1;
        	break;

        case '?':
        	fprintf(stderr, "usage: %s [ -B BUFSIZE ] [ -C CERTIFICATEFILE ] [ -D DHPARMSFILE ] [ -K PRIVATEKEYFILE ] [ -L REVOCATIONFILE ] [ -P CERTIFICATESPATH ] [ -R ROOTFILE ] [ -e EXPECTED ] [ -n NEAREND ] [ -S | -s ]\n", program);
            return 1;
            break;

        }

    }

	count = diminuto_fd_maximum();
	ASSERT(count > 0);

	DIMINUTO_LOG_INFORMATION("%s: BEGIN B=%zu C=\"%s\" D=\"%s\" K=\"%s\" L=\"%s\" P=\"%s\" R=\"%s\" e=\"%s\" n=\"%s\" s=%d fdcount=%d\n", program, bufsize, pathcrt, pathdhf, pathkey, (pathcrl == (const char *)0) ? "" : pathcrl, (pathcap == (const char *)0) ? "" : pathcap, (pathcaf == (const char *)0) ? "" : pathcaf, (expected == (const char *)0) ? "" : expected, nearend, selfsigned, count);

	buffer = (uint8_t *)malloc(bufsize);
	ASSERT(buffer != (uint8_t *)0);

	map = diminuto_fd_map_alloc(count);
	ASSERT(map != (diminuto_fd_map_t *)0);

	rc = diminuto_terminator_install(0);
	ASSERT(rc >= 0);

	rc = diminuto_hangup_install(0);
	ASSERT(rc >= 0);

	diminuto_mux_init(&mux);

	rc = diminuto_ipc_endpoint(nearend, &endpoint);
	ASSERT(rc == 0);

	meetme = diminuto_ipc4_stream_provider(endpoint.tcp);
	ASSERT(meetme >= 0);

	rendezvous = meetme;
	ASSERT(rendezvous >= 0);

	DIMINUTO_LOG_DEBUG("%s: RUN rendezvous=%d fd=%d\n", program, meetme, rendezvous);

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

			ASSERT(fd == rendezvous);

			fd = diminuto_ipc4_stream_accept(rendezvous);
			ASSERT(fd >= 0);

			DIMINUTO_LOG_INFORMATION("%s: START connection=%d fd=%d\n", program, rendezvous, fd);

			here = diminuto_fd_map_ref(map, fd);
			ASSERT(here != (void **)0);
			ASSERT(*here == (void *)0);
			/*
			 * This is horribly horribly dangerous: we're keeping a one-bit
			 * flag in the low order bit of the connection (SSL) address. This
			 * only works because the first field in the SSL structure is word
			 * aligned, not byte aligned. One minor change to the SSL structure
			 * and this breaks. But doing this keeps us from having to have a
			 * second file descriptor map.
			 */
			temp = (uintptr_t)0;
			temp |= 0x1;
			*here = (void *)temp;

			rc = diminuto_mux_register_read(&mux, fd);
			ASSERT(rc >= 0);

		}

		while (true) {

			fd = diminuto_mux_ready_read(&mux);
			if (fd < 0) {
				break;
			}

			here = diminuto_fd_map_ref(map, fd);
			ASSERT(here != (void **)0);
			temp = (uintptr_t)*here;
			tripwire = (temp & 0x1) != 0;
			if (tripwire) {
				temp &= ~(uintptr_t)0x1;
				*here = (void *)temp;
			}

			do {

				bytes = diminuto_ipc4_stream_read(fd, buffer, bufsize);
				DIMINUTO_LOG_DEBUG("%s: READ connection=%d bytes=%d\n", program, fd, bytes);

				if (bytes > 0) {

					for (reads = bytes, writes = 0; (writes < reads) && (bytes > 0); writes += bytes) {
						bytes = diminuto_ipc4_stream_write(fd, buffer + writes, reads - writes);
						DIMINUTO_LOG_DEBUG("%s: WRITE connection=%d bytes=%d\n", program, fd, bytes);
					}

				}

				if (bytes <= 0) {

					DIMINUTO_LOG_INFORMATION("%s: FINISH connection=%d\n", program, fd);

					rc = diminuto_mux_unregister_read(&mux, fd);
					EXPECT(rc >= 0);

					rc = diminuto_ipc4_close(fd);
					ADVISE(rc >= 0);

					*here = (void *)0;

				}

			} while (false);

		}

		diminuto_yield();

	}

	DIMINUTO_LOG_INFORMATION("%s: END\n", program);

	diminuto_mux_fini(&mux);

	fd = rendezvous;
	ASSERT(fd >= 0);
	ASSERT(fd == rendezvous);

	rc = diminuto_mux_unregister_accept(&mux, fd);
	EXPECT(rc >= 0);

	rc = diminuto_ipc4_close(fd);
	ASSERT(rc >= 0);

	for (fd = 0; fd < count; ++fd) {

		here = diminuto_fd_map_ref(map, fd);
		ASSERT(here != (void **)0);
		if (*here == (void *)0) { continue; }
		temp = (uintptr_t)*here;
		temp &= ~(uintptr_t)0x1;

		rc = diminuto_ipc4_close(fd);
		EXPECT(rc >= 0);

		*here = (void *)0;

	}

	free(map);

	free(buffer);

	EXIT();
}

