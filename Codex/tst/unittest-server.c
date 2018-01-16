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
#include "com/diag/diminuto/diminuto_delay.h"
#include "com/diag/codex/codex.h"
#include "../src/codex_unittest.h"
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>

int main(int argc, char ** argv)
{
	const char * program = "unittest-server";
	const char * nearend = "49152";
	const char * expected = "client.prairiethorn.org";
	bool enforce = false;
	int rc;
	codex_context_t * ctx;
	codex_rendezvous_t * bio;
	ssize_t count;
	diminuto_fd_map_t * map;
	void ** here;
	diminuto_mux_t mux;
	int fd;
	codex_connection_t * ssl;
	uint8_t buffer[256];
	int reads;
	int writes;
    int opt;
    extern char * optarg;

	(void)diminuto_core_enable();

	diminuto_log_setmask();

    program = ((program = strrchr(argv[0], '/')) == (char *)0) ? argv[0] : program + 1;

    while ((opt = getopt(argc, argv, "e:n:v?")) >= 0) {

        switch (opt) {

        case 'e':
            expected = optarg;
            break;

        case 'n':
        	nearend = optarg;
        	break;

        case 'v':
        	enforce = true;
        	break;

        case '?':
        	fprintf(stderr, "usage: %s [ -n %s ] [ -e %s ] [ -v ]\n", program, nearend, expected);
            return 1;
            break;

        }

    }

	count = diminuto_fd_maximum();
	ASSERT(count > 0);

	DIMINUTO_LOG_DEBUG("%s: nearend=\"%s\" expected=\"%s\" enforce=%d length=%zu count=%d\n", program, nearend, expected, enforce, sizeof(buffer), count);

	map = diminuto_fd_map_alloc(count);
	ASSERT(map != (diminuto_fd_map_t *)0);

	rc = diminuto_terminator_install(0);
	ASSERT(rc >= 0);

	diminuto_mux_init(&mux);

	rc = codex_initialize();
	ASSERT(rc == 0);

	rc = codex_parameters(COM_DIAG_CODEX_OUT_ETC_PATH "/dh256.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/dh512.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/dh1024.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/dh2048.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/dh4096.pem");
	ASSERT(rc == 0);

	ctx = codex_server_context_new(COM_DIAG_CODEX_OUT_ETC_PATH "/root.pem", (const char *)0, COM_DIAG_CODEX_OUT_ETC_PATH "/server.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/server.pem");
	ASSERT(ctx != (codex_context_t *)0);

	bio = codex_server_rendezvous_new(nearend);
	ASSERT(bio != (codex_rendezvous_t *)0);

	fd = codex_rendezvous_descriptor(bio);
	ASSERT(fd >= 0);

	DIMINUTO_LOG_DEBUG("%s: rendezvous=%p fd=%d\n", program, bio, fd);

	here = diminuto_fd_map_ref(map, fd);
	ASSERT(here != (void **)0);
	ASSERT(*here == (void *)0);
	*here = (void *)bio;

	rc = diminuto_mux_register_accept(&mux, fd);
	ASSERT(rc >= 0);

	while (!diminuto_terminator_check()) {

		rc = diminuto_mux_wait(&mux, -1);
		if ((rc == 0) || ((rc < 0) && (errno == EINTR))) {
			diminuto_yield();
			continue;
		}
		ASSERT(rc > 0);

		fd = diminuto_mux_ready_accept(&mux);
		if (fd >= 0) {

			here = diminuto_fd_map_ref(map, fd);
			ASSERT(here != (void **)0);
			ASSERT((codex_rendezvous_t *)*here == bio);

			ssl = codex_server_connection_new(ctx, bio);
			ASSERT(ssl != (codex_connection_t *)0);

			rc = codex_connection_verify(ssl, expected);
			if (enforce && (rc < 0)) {

				rc = codex_connection_close(ssl);
				EXPECT(rc >= 0);

				ssl = codex_connection_free(ssl);
				EXPECT(ssl == (codex_connection_t *)0);

			} else {

				fd = codex_connection_descriptor(ssl);
				ASSERT(fd >= 0);

				DIMINUTO_LOG_DEBUG("%s: connection=%p fd=%d\n", program, ssl, fd);

				here = diminuto_fd_map_ref(map, fd);
				ASSERT(here != (void **)0);
				ASSERT(*here == (void *)0);
				*here = (void *)ssl;

				rc = diminuto_mux_register_read(&mux, fd);
				ASSERT(rc >= 0);

			}

		}

		fd = diminuto_mux_ready_read(&mux);
		if (fd >= 0) {

			here = diminuto_fd_map_ref(map, fd);
			ASSERT(here != (void **)0);
			ASSERT(*here != (void *)0);
			ssl = (codex_connection_t *)*here;

			rc = codex_connection_read(ssl, buffer, sizeof(buffer));
			DIMINUTO_LOG_DEBUG("%s: connection=%p read=%d\n", program, ssl, rc);
			if (rc > 0) {

				for (reads = rc, writes = 0; writes < reads; writes += rc) {
					rc = codex_connection_write(ssl, buffer + writes, reads - writes);
					DIMINUTO_LOG_DEBUG("%s: connection=%p written=%d\n", program, ssl, rc);
					if (rc <= 0) {
						break;
					}
				}

			}

			if (rc <= 0) {

				rc = diminuto_mux_unregister_read(&mux, fd);
				ASSERT(rc >= 0);

				rc = codex_connection_close(ssl);
				ASSERT(rc >= 0);

				ssl = codex_connection_free(ssl);
				ASSERT(ssl == (codex_connection_t *)0);

				*here = (void *)0;

			}

		}

	}

	diminuto_mux_fini(&mux);

	fd = codex_rendezvous_descriptor(bio);
	ASSERT(fd >= 0);

	rc = diminuto_mux_unregister_accept(&mux, fd);
	ASSERT(rc >= 0);

	here = diminuto_fd_map_ref(map, fd);
	ASSERT(here != (void **)0);
	ASSERT(*here == bio);
	*here = (void *)0;

	bio = codex_server_rendezvous_free(bio);
	ASSERT(bio == (codex_rendezvous_t *)0);

	for (fd = 0; fd < count; ++fd) {

		here = diminuto_fd_map_ref(map, fd);
		ASSERT(here != (void **)0);
		if (*here == (void *)0) { continue; }
		ssl = (codex_connection_t *)*here;

		rc = codex_connection_close(ssl);
		ASSERT(rc >= 0);

		ssl = codex_connection_free(ssl);
		ASSERT(ssl == (codex_connection_t *)0);

		*here = (void *)0;

	}

	ctx = codex_context_free(ctx);
	EXPECT(ctx == (codex_context_t *)0);

	EXIT();
}

