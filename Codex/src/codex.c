/* vi: set ts=4 expandtab shiftwidth=4: */
/**
 * @file
 *
 * Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in README.h<BR>
 * Chip Overclock (coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 */

#include <stdbool.h>
#include <pthread.h>
#include "com/diag/codex/codex.h"
#include "com/diag/diminuto/diminuto_criticalsection.h"
#include "com/diag/diminuto/diminuto_log.h"


bool codex_initialize(void)
{
	static bool initialized = false;
	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

	if (!initialized) {
		DIMINUTO_CRITICAL_SECTION_BEGIN(&mutex);
			if (!initialized) {
				(void)SSL_library_init();
				SSL_load_error_strings();
				initialized = true;
			}
		DIMINUTO_CRITICAL_SECTION_END;
	}
}

void codex_perror(const char * s)
{
	char buffer[120];
	ERR_error_string_n(ERR_get_error(), buffer, sizeof(buffer));
    diminuto_log_log(DIMINUTO_LOG_PRIORITY_ERROR, "%s: %s\n", s, buffer);
}

SSL_CTX * codex_client_new(const char * certificate, const char * privatekey)
{
	SSL_CTX * result = (SSL_CTX *)0;
	SSL_METHOD * method = (SSL_METHOD *)0;
	SSL_CTX * context = (SSL_CTX *)0;
	int rc = -1;

	do {

		codex_initialize();

		method = SSLv23_method();
		if (method == (SSL_METHOD *)0) {
			codex_perror("SSLv23_method");
			break;
		}

		context = SSL_CTX_new(method);
		if (context == (SSL_CTX *)0) {
			codex_perror("SSL_CTX_new");
			break;
		}

		rc = SSL_CTX_use_certificate_file(context, certificate, SSL_FILETYPE_PEM);
		if (rc != 1) {
			codex_perror("SSL_CTX_use_certificate_file");
			break;
		}

		rc = SSL_CTX_use_PrivateKey_file(context, privatekey, SSL_FILETYPE_PEM);
		if (rc != 1) {
			codex_perror("SSL_CTX_use_PrivateKey_file");
			break;
		}

		result = context;

	} while (false);

	if (result != (SSL_CTX *)0) {
		/* Do nothing. */
	} else if (context == (SSL_CTX *)0) {
		/* Do nothing. */
	} else {
		SSL_CTX_free(context);
	}

	return result;
}

SSL_CTX * codex_client_free(SSL_CTX * context)
{
	if (context != (SSL_CTX *)0) {
		SSL_CTX_free(context);
		context = (SSL_CTX *)0;
	}

	return context;
}

