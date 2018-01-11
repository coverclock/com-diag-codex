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

const char * const codex_cipher_list = COM_DIAG_CODEX_CIPHER_LIST;

/*******************************************************************************
 * GLOBALS
 ******************************************************************************/

DH * codex_dh512 = (DH *)0;

DH * codex_dh1024 = (DH *)0;

DH * codex_dh2048 = (DH *)0;

DH * codex_dh4096 = (DH *)0;

/*******************************************************************************
 * STATICS
 ******************************************************************************/

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static bool initialized = false;

/*******************************************************************************
 * CALLBACKS
 ******************************************************************************/

static int codex_password_callback(char * buffer, int size, int writing, void * that)
{
	const char * password = (const char *)that;
	int length = 0;

	if (size <= 0) {
		/* Do nothing. */
	} else if (buffer == (char *)0) {
		/* Do nothing. */
	} else if (password == (const char *)0) {
		buffer[0] = '\0';
	} else if (size <= (length = strnlen(password, size + 1))) {
		buffer[0] = '\0';
		length = 0;
	} else {
		strncpy(buffer, password, size);
		buffer[size - 1] = '\0';
	}

	return length;
}

static int codex_verification_callback(int ok, X509_STORE_CTX * ctx)
{
	X509 * crt = (X509 *)0;
	int depth = -1;
	int error = 0;
	const char * text = (const char *)0;
	char name[256];

	if (!ok) {

		depth = X509_STORE_CTX_get_error_depth(ctx);
		diminuto_log_log(DIMINUTO_LOG_PRIORITY_WARNING, "codex_verification_callback: depth=%d\n", depth);

		crt = X509_STORE_CTX_get_current_cert(ctx);
		if (crt != (X509 *)0) {

			name[0] = '\0';
			X509_NAME_oneline(X509_get_issuer_name(crt), name, sizeof(name));
			name[sizeof(name) - 1] = '\0';
			diminuto_log_log(DIMINUTO_LOG_PRIORITY_WARNING, "codex_verification_callback: issuer=\"%s\"\n", name);

			name[0] = '\0';
			X509_NAME_oneline(X509_get_subject_name(crt), name, sizeof(name));
			name[sizeof(name) - 1] = '\0';
			diminuto_log_log(DIMINUTO_LOG_PRIORITY_WARNING, "codex_verification_callback: subject=\"%s\"\n", name);

		}

		error = X509_STORE_CTX_get_error(ctx);
		if (error != X509_V_OK) {
			text = X509_verify_cert_error_string(error);
			diminuto_log_log(DIMINUTO_LOG_PRIORITY_WARNING, "codex_verification_callback: error=%d=\"%s\"\n", error, (text != (const char *)0) ? text : "");
		}

	}

	return ok;
}

static DH * codex_parameters_callback(SSL * ssl, int export, int length)
{
	DH * dhp = (DH *)0;

	switch (length) {

	case 512:
		dhp = codex_dh512;
		break;

	case 1024:
		dhp = codex_dh1024;
		break;

	case 2048:
		dhp = codex_dh2048;
		break;

	case 4096:
		dhp = codex_dh4096;
		break;

	default:
		break;

	}

	if (dhp == (DH *)0) {
		diminuto_log_log(DIMINUTO_LOG_PRIORITY_ERROR, "codex_parameters_callback: length=%d result=NULL\n", length);
	}

	return dhp;
}

/*******************************************************************************
 * COMMON
 ******************************************************************************/

void codex_perror(const char * str)
{
	unsigned long error = -1;
	char buffer[120];

	while (!0) {
		error = ERR_get_error();
		if (error == 0) { break; }
		buffer[0] = '\0';
		ERR_error_string_n(error, buffer, sizeof(buffer));
		buffer[sizeof(buffer) - 1] = '\0';
		diminuto_log_log(DIMINUTO_LOG_PRIORITY_ERROR, "%s: [%d] \"%s\"\n", str, error, buffer);
	}
}

int codex_initialize(void)
{
	int rc = -1;

	DIMINUTO_CRITICAL_SECTION_BEGIN(&mutex);

		do {

			if (!initialized) {

				rc = SSL_library_init();
				if (rc != 1) {
					codex_perror("SSL_library_init");
					break;
				}

				SSL_load_error_strings();

				initialized = true;

			}

		} while (0);

	DIMINUTO_CRITICAL_SECTION_END;

	return initialized ? 0 : -1;
}

static DH * codex_import(const char * dhf)
{
	DH * dhp = (DH *)0;
	BIO * bio = (BIO *)0;
	int rc = -1;

	do {

		bio = BIO_new_file(dhf, "r");
		if (bio == (BIO *)0) {
			codex_perror(dhf);
			break;
		}

		dhp = PEM_read_bio_DHparams(bio, (DH **)0, (pem_password_cb *)0, (void *)0);
		if (dhp == (DH *)0) {
			codex_perror(dhf);
			break;
		}

		/*
		 * The OpenSSL man page on PEM_read_bio_DHparams() and its kin is
		 * strangely silent as to whether the pointer returned by the function
		 * must ultimately be free()'d. Since there is no function like
		 * SSL_library_shutdown() that I can find, and valgrind(1) shows memory
		 * allocated at exit(2), maybe I just need to resign myself to this.
		 */

	} while (0);

	if (bio != (BIO *)0) {
		rc = BIO_free(bio);
		if (rc != 1) {
			codex_perror(dhf);
		}
	}

	return dhp;
}

#define CODEX_PARAMETERS(_LENGTH_) \
		if (dh##_LENGTH_##f == (const char *)0) { \
			/* Do nothing. */ \
		} else if (codex_dh##_LENGTH_ != (DH *)0) { \
			/* Do nothing. */ \
		} else { \
			codex_dh##_LENGTH_ = codex_import(dh##_LENGTH_##f); \
			if (codex_dh##_LENGTH_ == (DH *)0) { \
				break; \
			} \
		} \
		if (codex_dh##_LENGTH_ != (DH *)0) { \
			any = codex_dh##_LENGTH_; \
		}

int codex_parameters(const char * dh512f, const char * dh1024f, const char * dh2048f, const char * dh4096f)
{
	int rc = -1;
	DH * any = (DH *)0;

	DIMINUTO_CRITICAL_SECTION_BEGIN(&mutex);

		do {

			CODEX_PARAMETERS(512);

			CODEX_PARAMETERS(1024);

			CODEX_PARAMETERS(2048);

			CODEX_PARAMETERS(4096);

			rc = 0;

		} while (0);

	DIMINUTO_CRITICAL_SECTION_END;

	if (any == (DH *)0) {
		diminuto_log_log(DIMINUTO_LOG_PRIORITY_WARNING, "codex_parameters: result=NULL");
	}

	return rc;

}

SSL_CTX * codex_context_new(const char * env, const char * caf, const char * crt, const char * pem, int flags, int depth, int options)
{
	SSL_CTX * result = (SSL_CTX *)0;
	const SSL_METHOD * method = (SSL_METHOD *)0;
	SSL_CTX * ctx = (SSL_CTX *)0;
	char * password = (char *)0;
	int rc = -1;

	do {

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

		password = secure_getenv(env);
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

		SSL_CTX_set_verify(ctx, flags, codex_verification_callback);

		SSL_CTX_set_verify_depth(ctx, depth);

		(void)SSL_CTX_set_options(ctx, options);

		SSL_CTX_set_tmp_dh_callback(ctx, codex_parameters_callback);

		rc = SSL_CTX_set_cipher_list(ctx, codex_cipher_list);
		if (rc != 1) {
			codex_perror("SSL_CTX_set_cipher_list");
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

SSL_CTX * codex_context_free(SSL_CTX * ctx)
{
	if (ctx != (SSL_CTX *)0) {
		SSL_CTX_free(ctx);
		ctx = (SSL_CTX *)0;
	}

	return ctx;
}

/*******************************************************************************
 * CLIENT
 ******************************************************************************/

/*******************************************************************************
 * SERVER
 ******************************************************************************/

