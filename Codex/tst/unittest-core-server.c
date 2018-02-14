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
#include "unittest-codex.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

static const char * program = "unittest-core-server";
static const char * nearend = "49162";
static const char * expected = "client.prairiethorn.org";
static bool enforce = true;
static long seconds = -1; /* Unimplemented. */
static long octets = -1; /* Unimplemented. */
static size_t bufsize = 256;
static const char * pathcaf = COM_DIAG_CODEX_OUT_CRT_PATH "/" "root.pem";
static const char * pathcap = (const char *)0;
static const char * pathcrt = COM_DIAG_CODEX_OUT_CRT_PATH "/" "server.pem";
static const char * pathkey = COM_DIAG_CODEX_OUT_CRT_PATH "/" "server.pem";
static const char * pathdhf = COM_DIAG_CODEX_OUT_CRT_PATH "/" "dh.pem";

int main(int argc, char ** argv)
{
	uint8_t * buffer = (uint8_t *)0;
	int rc = -1;
	codex_context_t * ctx = (codex_context_t *)0;
	codex_rendezvous_t * bio = (codex_rendezvous_t *)0;
	ssize_t count = 0;
	diminuto_fd_map_t * map = (diminuto_fd_map_t *)0;
	void ** here = (void **)0;
	diminuto_mux_t mux = { 0 };
	int fd = -1;
	int rendezvous = -1;
	codex_connection_t * ssl = (codex_connection_t *)0;
	int bytes = -1;
	int reads = -1;
	int writes = -1;
	uintptr_t temp = 0;
	bool tripwire = false;
	char * endptr = (char *)0;
	long prior = -1;
    int opt = '\0';
    extern char * optarg;

	(void)diminuto_core_enable();

	diminuto_log_setmask();

    program = ((program = strrchr(argv[0], '/')) == (char *)0) ? argv[0] : program + 1;

    while ((opt = getopt(argc, argv, "B:C:D:K:P:R:Vb:e:n:s:v?")) >= 0) {

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
        	fprintf(stderr, "usage: %s [ -B BUFSIZE ] [ -C CERTIFICATEFILE ] [ -D DHPARMSFILE ] [ -K PRIVATEKEYFILE ] [ -P CERTIFICATESPATH ] [ -R ROOTFILE ] [ -b BYTES ] [ -e EXPECTED ] [ -n NEAREND ] [ -s SECONDS ] [ -V | -v ]\n", program);
            return 1;
            break;

        }

    }

	count = diminuto_fd_maximum();
	ASSERT(count > 0);

	DIMINUTO_LOG_INFORMATION("%s: BEGIN B=%zu C=\"%s\" D=\"%s\" K=\"%s\" P=\"%s\" R=\"%s\" b=%ld e=\"%s\" n=\"%s\" s=%ld v=%d fdcount=%d\n", program, bufsize, pathcrt, pathdhf, pathkey, (pathcap == (const char *)0) ? "" : pathcap, pathcaf, octets, expected, nearend, seconds, enforce, count);

	buffer = (uint8_t *)malloc(bufsize);
	ASSERT(buffer != (uint8_t *)0);

	map = diminuto_fd_map_alloc(count);
	ASSERT(map != (diminuto_fd_map_t *)0);

	rc = diminuto_terminator_install(0);
	ASSERT(rc >= 0);

	rc = diminuto_hangup_install(0);
	ASSERT(rc >= 0);

	diminuto_mux_init(&mux);

	rc = codex_initialize();
	ASSERT(rc == 0);

	rc = codex_parameters(pathdhf);
	ASSERT(rc == 0);

	ctx = codex_server_context_new(pathcaf, pathcap, pathcrt, pathkey);
	ASSERT(ctx != (codex_context_t *)0);

	bio = codex_server_rendezvous_new(nearend);
	ASSERT(bio != (codex_rendezvous_t *)0);

	rendezvous = codex_rendezvous_descriptor(bio);
	ASSERT(rendezvous >= 0);

	DIMINUTO_LOG_DEBUG("%s: RUN rendezvous=%p fd=%d\n", program, bio, rendezvous);

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

			ssl = codex_server_connection_new(ctx, bio);
			ASSERT(ssl != (codex_connection_t *)0);
			ASSERT(codex_connection_is_server(ssl));

			fd = codex_connection_descriptor(ssl);
			ASSERT(fd >= 0);

			DIMINUTO_LOG_INFORMATION("%s: START connection=%p fd=%d\n", program, ssl, fd);

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
			temp = (uintptr_t)ssl;
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
			ASSERT(*here != (void *)0);
			temp = (uintptr_t)*here;
			tripwire = (temp & 0x1) != 0;
			if (tripwire) {
				temp &= ~(uintptr_t)0x1;
				*here = (void *)temp;
			}
			ssl = (codex_connection_t *)temp;

			bytes = codex_connection_read(ssl, buffer, bufsize);
			DIMINUTO_LOG_DEBUG("%s: READ connection=%p bytes=%d\n", program, ssl, bytes);

			if (tripwire) {

				rc = codex_connection_verify(ssl, expected);
				if (rc == CODEX_CONNECTION_VERIFY_CN) {
					/* Do nothing. */
				} else if (!enforce) {
					/* Do nothing. */
				} else {
					bytes = 0;
				}

			}

			if (bytes > 0) {

				for (reads = bytes, writes = 0; writes < reads; writes += bytes) {
					bytes = codex_connection_write(ssl, buffer + writes, reads - writes);
					DIMINUTO_LOG_DEBUG("%s: WRITE connection=%p bytes=%d\n", program, ssl, bytes);
					if (bytes <= 0) {
						break;
					}
				}

			} else {

				DIMINUTO_LOG_INFORMATION("%s: FINISH connection=%p\n", program, ssl);

				rc = diminuto_mux_unregister_read(&mux, fd);
				ASSERT(rc >= 0);

				rc = codex_connection_close(ssl);
				ASSERT(rc >= 0);

				ssl = codex_connection_free(ssl);
				ASSERT(ssl == (codex_connection_t *)0);

				*here = (void *)0;

			}

		}

		diminuto_yield();

	}

	DIMINUTO_LOG_INFORMATION("%s: END\n", program, ssl);

	diminuto_mux_fini(&mux);

	fd = codex_rendezvous_descriptor(bio);
	ASSERT(fd >= 0);
	ASSERT(fd == rendezvous);

	rc = diminuto_mux_unregister_accept(&mux, fd);
	ASSERT(rc >= 0);

	bio = codex_server_rendezvous_free(bio);
	ASSERT(bio == (codex_rendezvous_t *)0);

	for (fd = 0; fd < count; ++fd) {

		here = diminuto_fd_map_ref(map, fd);
		ASSERT(here != (void **)0);
		if (*here == (void *)0) { continue; }
		temp = (uintptr_t)*here;
		temp &= ~(uintptr_t)0x1;
		ssl = (codex_connection_t *)temp;

		rc = codex_connection_close(ssl);
		ASSERT(rc >= 0);

		ssl = codex_connection_free(ssl);
		ASSERT(ssl == (codex_connection_t *)0);

		*here = (void *)0;

	}

	free(map);

	ctx = codex_context_free(ctx);
	EXPECT(ctx == (codex_context_t *)0);

	free(buffer);

	EXIT();
}

