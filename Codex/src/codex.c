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
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include "com/diag/codex/codex.h"
#include "com/diag/diminuto/diminuto_criticalsection.h"
#include "com/diag/diminuto/diminuto_log.h"

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static bool initialized = false;

static const char CODEX_PASSWORD_ENV[] = COM_DIAG_CODEX_PASSWORD_ENV;

/*******************************************************************************
 * COMMON
 ******************************************************************************/

void codex_initialize(void)
{
	DIMINUTO_CRITICAL_SECTION_BEGIN(&mutex);

		if (!initialized) {
			(void)SSL_library_init();
			SSL_load_error_strings();
			initialized = true;
		}

	DIMINUTO_CRITICAL_SECTION_END;
}

void codex_perror(const char * str)
{
	char buffer[120];
	ERR_error_string_n(ERR_get_error(), buffer, sizeof(buffer));
    diminuto_log_log(DIMINUTO_LOG_PRIORITY_ERROR, "%s: %s\n", str, buffer);
}

SSL_CTX * codex_context_free(SSL_CTX * ctx)
{
	SSL_CTX * result = ctx;

	if (result != (SSL_CTX *)0) {
		SSL_CTX_free(result);
		result = (SSL_CTX *)0;
	}

	return result;
}

static int codex_password_callback(char * buffer, int size, int writing, void * that)
{
	const char * password = (const char *)0;
	int length = 0;

	if (size <= 0) {
		/* Do nothing. */
	} else if (buffer == (char *)0) {
		/* Do nothing. */
	} else if (that != (void *)0) {
		password = (const char *)that;
		strncpy(buffer, password, size);
		buffer[size - 1] = '\0';
		length = strnlen(buffer, size);
	} else {
		buffer[0] = '\0';
	}

	return length;
}

/*******************************************************************************
 * CLIENT
 ******************************************************************************/

SSL_CTX * codex_client_new(const char * crt, const char * pem)
{
	SSL_CTX * result = (SSL_CTX *)0;
	const SSL_METHOD * method = (SSL_METHOD *)0;
	SSL_CTX * ctx = (SSL_CTX *)0;
	char * password = (char *)0;
	int rc = -1;

	do {

		codex_initialize();

		method = SSLv23_method();
		if (method == (SSL_METHOD *)0) {
			codex_perror("SSLv23_method");
			break;
		}

		ctx = SSL_CTX_new(method);
		if (ctx == (SSL_CTX *)0) {
			codex_perror("SSL_CTX_new");
			break;
		}

		password = secure_getenv(CODEX_PASSWORD_ENV);
		if (password != (char *)0) {
			SSL_CTX_set_default_passwd_cb(ctx, codex_password_callback);
			SSL_CTX_set_default_passwd_cb_userdata(ctx, password);
		}

		rc = SSL_CTX_use_certificate_file(ctx, crt, SSL_FILETYPE_PEM);
		if (rc != 1) {
			codex_perror("SSL_CTX_use_certificate_file");
			break;
		}

		rc = SSL_CTX_use_PrivateKey_file(ctx, pem, SSL_FILETYPE_PEM);
		if (rc != 1) {
			codex_perror("SSL_CTX_use_PrivateKey_file");
			break;
		}

		result = ctx;

	} while (false);

	if (result != (SSL_CTX *)0) {
		/* Do nothing. */
	} else if (ctx == (SSL_CTX *)0) {
		/* Do nothing. */
	} else {
		SSL_CTX_free(ctx);
	}

	return result;
}

/*******************************************************************************
 * SERVER
 ******************************************************************************/

SSL_CTX * codex_server_new(const char * crt, const char * pem)
{
	SSL_CTX * result = (SSL_CTX *)0;
	const SSL_METHOD * method = (SSL_METHOD *)0;
	SSL_CTX * ctx = (SSL_CTX *)0;
	char * password = (char *)0;
	int rc = -1;

	do {

		codex_initialize();

		method = SSLv23_method();
		if (method == (SSL_METHOD *)0) {
			codex_perror("SSLv23_method");
			break;
		}

		ctx = SSL_CTX_new(method);
		if (ctx == (SSL_CTX *)0) {
			codex_perror("SSL_CTX_new");
			break;
		}

		password = secure_getenv(CODEX_PASSWORD_ENV);
		if (password != (char *)0) {
			SSL_CTX_set_default_passwd_cb(ctx, codex_password_callback);
			SSL_CTX_set_default_passwd_cb_userdata(ctx, password);
		}

		rc = SSL_CTX_use_certificate_file(ctx, crt, SSL_FILETYPE_PEM);
		if (rc != 1) {
			codex_perror("SSL_CTX_use_certificate_file");
			break;
		}

		rc = SSL_CTX_use_PrivateKey_file(ctx, pem, SSL_FILETYPE_PEM);
		if (rc != 1) {
			codex_perror("SSL_CTX_use_PrivateKey_file");
			break;
		}

		result = ctx;

	} while (false);

	if (result != (SSL_CTX *)0) {
		/* Do nothing. */
	} else if (ctx == (SSL_CTX *)0) {
		/* Do nothing. */
	} else {
		SSL_CTX_free(ctx);
	}

	return result;
}

