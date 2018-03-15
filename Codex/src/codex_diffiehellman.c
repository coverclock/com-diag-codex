/* vi: set ts=4 expandtab shiftwidth=4: */
/**
 * @file
 *
 * Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 *
 * See the README.md for a list of references.
 */

/*******************************************************************************
 * HEADERS
 ******************************************************************************/

#include "com/diag/codex/codex.h"
#include "com/diag/diminuto/diminuto_criticalsection.h"
#include "com/diag/diminuto/diminuto_log.h"
#include "codex.h"

/*******************************************************************************
 * STATICS
 ******************************************************************************/

static pthread_mutex_t mutex_dh = PTHREAD_MUTEX_INITIALIZER;

static DH * dh = (DH *)0;

/*******************************************************************************
 * CALLBACKS
 ******************************************************************************/

DH * codex_diffiehellman_callback(SSL * ssl, int exp, int length)
{
	DH * dhp = (DH *)0;

	DIMINUTO_CRITICAL_SECTION_BEGIN(&mutex_dh);

		dhp = dh;

	DIMINUTO_CRITICAL_SECTION_END;

	if (dhp == (DH *)0) {
		DIMINUTO_LOG_ERROR("codex_diffiehellman_callback: ssl=%p export=%d length=%d dh=%p\n", ssl, exp, length, dhp);
	}

	return dhp;
}

/*******************************************************************************
 * DIFFIE-HELLMAN
 ******************************************************************************/

int codex_diffiehellman_import(const char * dhf)
{
	int rc = -1;
	BIO * bio = (BIO *)0;
	DH * dhp = (DH *)0;

	DIMINUTO_CRITICAL_SECTION_BEGIN(&mutex_dh);

		if (dhf == (const char *)0) {

			rc = 0;

		} else  if (dh != (DH *)0) {

			rc = 0;

		} else {

			DIMINUTO_LOG_DEBUG("codex_diffiehellman_import: dh dhf=\"%s\"\n", dhf);

			do {

				bio = BIO_new_file(dhf, "r");
				if (bio == (BIO *)0) {
					codex_perror(dhf);
					break;
				}

				/*
				 * This DH API call has an argument for providing a callback
				 * function to provide the password for the DH parameter file.
				 * But the openssl dhparam doesn't have a command line argument
				 * to provide as password, nor for the name of a configuration
				 * file that might provide a password. Since the DH parameter
				 * file seems to just contain a large prime seed, maybe that
				 * doesn't matter, as the DH symmetric key is (highly likely
				 * likely to be) different for every connection.
				 */

				dhp = PEM_read_bio_DHparams(bio, (DH **)0, (pem_password_cb *)0, (void *)0);
				if (dhp == (DH *)0) {
					codex_perror(dhf);
					break;
				}

				/*
				 * The OpenSSL man page on PEM_read_bio_DHparams() and its
				 * kin is strangely silent as to whether the pointer returned by
				 * the function must ultimately be free()'d. Since there is no
				 * function like SSL_library_shutdown() that I can find, and
				 * valgrind(1) shows memory allocated at exit(2), maybe I just
				 * need to resign myself to this.
				 */

				dh = dhp;

				rc = 0;

			} while (false);

			if (bio == (BIO *)0) {
				/* Do nothing. */
			} else if (BIO_free(bio) == 1) {
				/* Do nothing. */
			} else {
				codex_perror(dhf);
			}

		}

	DIMINUTO_CRITICAL_SECTION_END;

	return rc;
}
