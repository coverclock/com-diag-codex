/* vi: set ts=4 expandtab shiftwidth=4: */
/**
 * @file
 *
 * Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in README.h<BR>
 * Chip Overclock (coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 *
 * REFERENCES
 *
 * J. Viega, M. Messier, P. Chandra, _Network Security with OpenSSL_, O'Reilly,
 * 2002, pp. 112-170
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
#include <openssl/x509.h>
#include "com/diag/codex/codex.h"
#include "com/diag/diminuto/diminuto_criticalsection.h"
#include "com/diag/diminuto/diminuto_log.h"
#include "codex.h"

/*******************************************************************************
 * CONSTANTS
 ******************************************************************************/

const char * const codex_client_password_env = COM_DIAG_CODEX_CLIENT_PASSWORD_ENV;

const char * const codex_server_password_env = COM_DIAG_CODEX_SERVER_PASSWORD_ENV;

/*******************************************************************************
 * GLOBALS
 ******************************************************************************/

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static bool initialized = false;

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

static int codex_verify_callback(int ok, X509_STORE_CTX * ctx)
{
	X509 * crt = (X509 *)0;
	int depth = -1;
	int error = 0;
	const char * text = (const char *)0;
	char name[256];

	if (!ok) {

		depth = X509_STORE_CTX_get_error_depth(ctx);

		diminuto_log_log(DIMINUTO_LOG_PRIORITY_NOTICE, "codex_verify_callback: depth=%d\n", depth);

		crt = X509_STORE_CTX_get_current_cert(ctx);

		name[0] = '\0';
		X509_NAME_oneline(X509_get_issuer_name(crt), name, sizeof(name));
		name[sizeof(name) - 1] = '\0';
		diminuto_log_log(DIMINUTO_LOG_PRIORITY_NOTICE, "codex_verify_callback: issuer=\"%s\"\n", name);

		name[0] = '\0';
		X509_NAME_oneline(X509_get_subject_name(crt), name, sizeof(name));
		name[sizeof(name) - 1] = '\0';
		diminuto_log_log(DIMINUTO_LOG_PRIORITY_NOTICE, "codex_verify_callback: subject=\"%s\"\n", name);

		error = X509_STORE_CTX_get_error(ctx);

		text = X509_verify_cert_error_string(error);
		if (text != (const char *)0) {
			diminuto_log_log(DIMINUTO_LOG_PRIORITY_NOTICE, "codex_verify_callback: error=%d=\"%s\"\n", error, text);
		}

	}

	return ok;
}

SSL_CTX * codex_context_new(const char * key, const char * caf, const char * crt, const char * pem, int flags, int depth)
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

		rc = SSL_CTX_load_verify_locations(ctx, caf, (const char *)0);
		if (rc != 1) {
			codex_perror("SSL_CTX_load_verify_locations");
			break;
		}

		rc = SSL_CTX_set_default_verify_paths(ctx);
		if (rc != 1) {
			codex_perror("SSL_CTX_load_verify_locations");
			break;
		}

		password = secure_getenv(key);
		if (password != (char *)0) {
			SSL_CTX_set_default_passwd_cb(ctx, codex_password_callback);
			SSL_CTX_set_default_passwd_cb_userdata(ctx, password);
		}

		rc = SSL_CTX_use_certificate_chain_file(ctx, crt);
		if (rc != 1) {
			codex_perror("SSL_CTX_use_certificate_chain_file");
			break;
		}

		rc = SSL_CTX_use_PrivateKey_file(ctx, pem, SSL_FILETYPE_PEM);
		if (rc != 1) {
			codex_perror("SSL_CTX_use_PrivateKey_file");
			break;
		}

		SSL_CTX_set_verify(ctx, flags, codex_verify_callback);

		SSL_CTX_set_verify_depth(ctx, depth);

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

SSL_CTX * codex_context_free(SSL_CTX * ctx)
{
	SSL_CTX * result = ctx;

	if (result != (SSL_CTX *)0) {
		SSL_CTX_free(result);
		result = (SSL_CTX *)0;
	}

	return result;
}

/*******************************************************************************
 * CLIENT
 ******************************************************************************/

/*******************************************************************************
 * SERVER
 ******************************************************************************/

