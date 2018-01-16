/* vi: set ts=4 expandtab shiftwidth=4: */
/**
 * @file
 *
 * Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in README.h<BR>
 * Chip Overclock (coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 *
 * See the README.md for a list of references.
 */

/*******************************************************************************
 * HEADERS
 ******************************************************************************/

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
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

DH * codex_dh256 = (DH *)0;

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
 * HELPERS
 ******************************************************************************/

void codex_perror(const char * str)
{
	int save = -1;
	unsigned long error = -1;
	int ii = 0;
	char buffer[120];

	save = errno;

	while (!0) {
		error = ERR_get_error();
		if (error == 0) { break; }
		buffer[0] = '\0';
		ERR_error_string_n(error, buffer, sizeof(buffer));
		buffer[sizeof(buffer) - 1] = '\0';
		DIMINUTO_LOG_ERROR("%s: [%d] <%8.8x> \"%s\"\n", str, ii++, error, buffer);
	}

	if (ii == 0) {
		errno = save;
		diminuto_perror(str);
	}
}

int codex_serror(const char * str, const SSL * ssl, int rc)
{
	int action = 0;
	int err = 0;
	int temp = 0;
	int save = -1;

	save = errno;

	err = SSL_get_error(ssl, rc);
	switch (err) {

	case SSL_ERROR_NONE:
		break;

	case SSL_ERROR_ZERO_RETURN:
		action = 1;
		break;

	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
	case SSL_ERROR_WANT_CONNECT:
	case SSL_ERROR_WANT_ACCEPT:
	case SSL_ERROR_WANT_X509_LOOKUP:
		break;

	case SSL_ERROR_SYSCALL:
	case SSL_ERROR_SSL:
		errno = save;
		if (errno > 0) {
			codex_perror(str);
			action = -1;
		}
		break;

	default:
		break;

	}

	if (action != 0) {
		DIMINUTO_LOG_DEBUG("codex_serror: str=\"%s\" ssl=%p rc=%d err=%d action=%d\n", str, ssl, rc, err, action);
	}

	return action;
}

static DH * codex_parameters_import(const char * dhf)
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

/*******************************************************************************
 * CALLBACKS
 ******************************************************************************/

int codex_password_callback(char * buffer, int size, int writing, void * that)
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

int codex_verification_callback(int ok, X509_STORE_CTX * ctx)
{
	X509 * crt = (X509 *)0;
	int depth = -1;
	int error = 0;
	const char * text = (const char *)0;
	char name[256];

	if (!ok) {

		depth = X509_STORE_CTX_get_error_depth(ctx);
		DIMINUTO_LOG_WARNING("codex_verification_callback: depth=%d\n", depth);

		crt = X509_STORE_CTX_get_current_cert(ctx);
		if (crt != (X509 *)0) {

			name[0] = '\0';
			X509_NAME_oneline(X509_get_issuer_name(crt), name, sizeof(name));
			name[sizeof(name) - 1] = '\0';
			DIMINUTO_LOG_WARNING("codex_verification_callback: issuer=\"%s\"\n", name);

			name[0] = '\0';
			X509_NAME_oneline(X509_get_subject_name(crt), name, sizeof(name));
			name[sizeof(name) - 1] = '\0';
			DIMINUTO_LOG_WARNING("codex_verification_callback: subject=\"%s\"\n", name);

		}

		error = X509_STORE_CTX_get_error(ctx);
		if (error != X509_V_OK) {
			text = X509_verify_cert_error_string(error);
			DIMINUTO_LOG_WARNING("codex_verification_callback: error=%d=\"%s\"\n", error, (text != (const char *)0) ? text : "");
		}

	}

	return ok;
}

DH * codex_parameters_callback(SSL * ssl, int exp, int length)
{
	DH * dhp = (DH *)0;

	DIMINUTO_LOG_DEBUG("codex_parameters_callback: ssl=%p export=%d length=%d\n", ssl, exp, length);

	switch (length) {

	case 256:
		dhp = codex_dh256;
		break;

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
		DIMINUTO_LOG_WARNING("codex_parameters_callback: ssl=%p export=%d length=%d result=NULL\n", ssl, exp, length);
	}

	return dhp;
}

/*******************************************************************************
 * INITIALIZATION
 ******************************************************************************/

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

				OPENSSL_config((const char *)0);

				initialized = true;

			}

		} while (0);

	DIMINUTO_CRITICAL_SECTION_END;

	return initialized ? 0 : -1;
}

#define CODEX_PARAMETERS(_LENGTH_) \
		do { \
			if (dh##_LENGTH_##f == (const char *)0) { \
				/* Do nothing. */ \
			} else if (codex_dh##_LENGTH_ != (DH *)0) { \
				/* Do nothing. */ \
			} else { \
				codex_dh##_LENGTH_ = codex_parameters_import(dh##_LENGTH_##f); \
				if (codex_dh##_LENGTH_ == (DH *)0) { \
					rc = -1; \
				} \
			} \
			if (codex_dh##_LENGTH_ != (DH *)0) { \
				any = codex_dh##_LENGTH_; \
			} \
		} while (0)

int codex_parameters(const char * dh256f, const char * dh512f, const char * dh1024f, const char * dh2048f, const char * dh4096f)
{
	int rc = 0;
	DH * any = (DH *)0;

	DIMINUTO_CRITICAL_SECTION_BEGIN(&mutex);

		do {

			CODEX_PARAMETERS(256);

			CODEX_PARAMETERS(512);

			CODEX_PARAMETERS(1024);

			CODEX_PARAMETERS(2048);

			CODEX_PARAMETERS(4096);

		} while (0);

	DIMINUTO_CRITICAL_SECTION_END;

	if (any == (DH *)0) {
		DIMINUTO_LOG_WARNING("codex_parameters: result=NULL");
	}

	return rc;

}

/*******************************************************************************
 * CONTEXT
 ******************************************************************************/

codex_context_t * codex_context_new(const char * env, const char * caf, const char * cap, const char * crt, const char * pem, int flags, int depth, int options)
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

		rc = SSL_CTX_load_verify_locations(ctx, caf, cap);
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

codex_context_t * codex_context_free(codex_context_t * ctx)
{
	if (ctx != (SSL_CTX *)0) {
		SSL_CTX_free(ctx);
		ctx = (SSL_CTX *)0;
	}

	return ctx;
}

/*******************************************************************************
 * CONNECTION
 ******************************************************************************/

int codex_connection_verify(codex_connection_t * ssl, const char * expected)
{
	int result = 0;
	long error = X509_V_ERR_APPLICATION_VERIFICATION;
	int found = 0;
	X509 * crt = (X509 *)0;
	X509_NAME * subject = (X509_NAME *)0;
	int count = 0;
	X509_EXTENSION * ext = (X509_EXTENSION *)0;
	int ii = 0;
	ASN1_OBJECT * obj = (ASN1_OBJECT *)0;
	int nid = -1;
	const char * str = (char *)0;
	const X509V3_EXT_METHOD * meth = (X509V3_EXT_METHOD *)0;
	const unsigned char * dat = (const unsigned char *)0;
	void * ptr = (void *)0;
	STACK_OF(CONF_VALUE) * vals = (STACK_OF(CONF_VALUE) *)0;
	int jj = 0;
	CONF_VALUE * val = (CONF_VALUE *)0;
	int lim = 0;
	X509_NAME * nam = (X509_NAME *)0;
	char buffer[256];
	int rc = -1;
	const char * text = (const char *)0;

	do {

		crt = SSL_get_peer_certificate(ssl);
		if (crt == (X509 *)0) {
			break;
		}

		count = X509_get_ext_count(crt);
		for (ii = 0; ii < count; ++ii) {

			ext = X509_get_ext(crt, ii);
			if (ext == (X509_EXTENSION *)0) {
				continue;
			}

			obj = X509_EXTENSION_get_object(ext);
			if (obj == (ASN1_OBJECT *)0) {
				continue;
			}

			nid = OBJ_obj2nid(obj);
			if (nid == NID_undef) {
				continue;
			}

			str = OBJ_nid2sn(nid);
			if (str == (const char *)0) {
				continue;
			}

			DIMINUTO_LOG_DEBUG("codex_connection_verify: \"%s\" ? \"%s\"\n", str, COM_DIAG_CODEX_SHORTNAME_SUBJECTALTNAME);

			if (strcmp(str, COM_DIAG_CODEX_SHORTNAME_SUBJECTALTNAME) != 0) {
				continue;
			}

			meth = X509V3_EXT_get(ext);
			if (meth == (X509V3_EXT_METHOD *)0) {
				continue;
			}

			if (ext->value == (ASN1_OCTET_STRING *)0) {
				continue;
			}

			dat = ext->value->data;

			if (meth->d2i == (X509V3_EXT_D2I)0) {
				continue;
			}

			ptr = meth->d2i((void *)0, &dat, ext->value->length);

			if (meth->i2v == (X509V3_EXT_I2V)0) {
				continue;
			}

			vals = meth->i2v(meth, ptr, (STACK_OF(CONF_VALUE) *)0);
			if (vals == (STACK_OF(CONF_VALUE) *)0) {
				continue;
			}

			lim = sk_CONF_VALUE_num(vals);

			for (jj = 0; jj < lim; ++jj) {

				val = sk_CONF_VALUE_value(vals, jj);
				if (val == (CONF_VALUE *)0) {
					continue;
				}

				if (val->name == (char *)0) {
					continue;
				}

				if (val->value == (char *)0) {
					continue;
				}

				DIMINUTO_LOG_DEBUG("codex_connection_verify: \"%s\"=\"%s\" ? \"%s\"=\"%s\"\n", val->name, val->value, COM_DIAG_CODEX_CONFNAME_DNS, expected);

				if (strcmp(val->name, COM_DIAG_CODEX_CONFNAME_DNS) != 0) {
					continue;
				}

				if (strcmp(val->value, expected) != 0) {
					continue;
				}

				/*
				 * Fully qualified domain name (FQDN) matches.
				 */
				DIMINUTO_LOG_DEBUG("codex_connection_verify: FQDN matches\n");
				found = !0;
				break;
			}

			if (found) {
				break;
			}
		}

		if (found) {
			break;
		}

		nam = X509_get_subject_name(crt);
		if (nam == (X509_NAME *)0) {
			break;
		}

		buffer[0] = '\0';
		rc = X509_NAME_get_text_by_NID(nam, NID_commonName, buffer, sizeof(buffer));
		if (rc <= 0) {
			break;
		}
		buffer[sizeof(buffer) - 1] = '\0';

		DIMINUTO_LOG_DEBUG("codex_connection_verify: \"%s\"=\"%s\" ? \"%s\"\n", SN_commonName, buffer, expected);

		if (strcasecmp(buffer, expected) != 0) {
			break;
		}

		/*
		 * CommonName (CN) in certificate matches.
		 */
		DIMINUTO_LOG_DEBUG("codex_connection_verify: CN matches\n");
		found = !0;
		break;

	} while (0);

	if (crt != (X509 *)0) {
		X509_free(crt);
	}

	if (found) {
		error = SSL_get_verify_result(ssl);
	}

	if (error != X509_V_OK) {
		text = X509_verify_cert_error_string(error);
		DIMINUTO_LOG_WARNING("codex_connection_verify: <%d> \"%s\"\n", error, (text != (const char *)0) ? text : "");
		result = -1;
	}

	return result;
}

bool codex_connection_closed(codex_connection_t * ssl)
{
	int rc = 0;

	rc = SSL_get_shutdown(ssl);

	return ((rc & SSL_RECEIVED_SHUTDOWN) != 0);
}

int codex_connection_close(codex_connection_t * ssl)
{
	int rc = 0;
	int flags = 0;
	int action = 0;

	flags = SSL_get_shutdown(ssl);
	if ((flags & SSL_SENT_SHUTDOWN) == 0) {
		while (!0) {
			rc = SSL_shutdown(ssl);
			if (rc < 0) {
				action = codex_serror("SSL_shutdown", ssl, rc);
				if (action == 0) {
					rc = 0;
				}
				break;
			} else if (rc > 0) {
				rc = 0;
				break;
			} else {
				continue;
			}
		}
	}

	return rc;
}

codex_connection_t * codex_connection_free(codex_connection_t * ssl)
{
	(void)codex_connection_close(ssl);

	SSL_free(ssl);

	ssl = (SSL *)0;

	return ssl;
}

/*******************************************************************************
 * INPUT/OUTPUT
 ******************************************************************************/

int codex_connection_read(codex_connection_t * ssl, void * buffer, int size)
{
	int len = 0;

	len = SSL_read(ssl, buffer, size);
	if (len < 0) {
		codex_serror("SSL_read", ssl, len);
	}

	return len;
}

int codex_connection_write(codex_connection_t * ssl, const void * buffer, int size)
{
	int len = 0;

	len = SSL_write(ssl, buffer, size);
	if (len < 0) {
		codex_serror("SSL_write", ssl, len);
	}

	return len;
}

/*******************************************************************************
 * CLIENT
 ******************************************************************************/

codex_connection_t * codex_client_connection_new(codex_context_t * ctx, const char * farend)
{
	SSL * ssl = (SSL *)0;
	BIO * bio = (BIO *)0;
	int rc = -1;

	do {

		bio = BIO_new_connect(farend);
		if (bio == (BIO *)0) {
			codex_perror("BIO_new_connect");
			break;
		}

		rc = BIO_do_connect(bio);
		if (rc <= 0) {
			codex_perror("BIO_do_connect");
			break;
		}

		ssl = SSL_new(ctx);
		if (ssl == (SSL *)0) {
			codex_perror("SSL_new");
			break;
		}

		SSL_set_bio(ssl, bio, bio);

		rc = SSL_connect(ssl);
		if (rc > 0) {
			break;
		}
		codex_serror("SSL_connect", ssl, rc);

		SSL_free(ssl);

		ssl = (SSL *)0;
		bio = (BIO *)0;

	} while (0);

	if (ssl != (SSL *)0) {
		/* Do nothing. */
	} else if (bio == (BIO *)0) {
		/* Do nothing. */
	} else {
		rc = BIO_free(bio);
		if (rc != 1) {
			codex_perror("BIO_free");
		}
	}

	return ssl;
}

/*******************************************************************************
 * SERVER
 ******************************************************************************/

codex_rendezvous_t * codex_server_rendezvous_new(const char * nearend)
{
	BIO * acc = (BIO *)0;
	int rc = -1;

	do {

		acc = BIO_new_accept(nearend);
		if (acc == (BIO *)0) {
			codex_perror("BIO_new_accept");
			break;
		}

		rc = BIO_do_accept(acc);
		if (rc > 0) {
			break;
		}
		codex_perror("BIO_do_accept");

		rc = BIO_free(acc);
		if (rc != 1) {
			codex_perror("BIO_free");
		}

		/*
		 * Potential memory leak here in the unlikely event BIO_free() fails.
		 */

		acc = (BIO *)0;

	} while (0);

	return acc;
}

codex_rendezvous_t * codex_server_rendezvous_free(codex_rendezvous_t * acc)
{
	int rc = -1;

	do {

		rc = BIO_free(acc);
		if (rc != 1) {
			codex_perror("BIO_free_all");
			break;
		}

		acc = (BIO *)0;

	} while (0);

	return acc;
}

codex_connection_t * codex_server_connection_new(codex_context_t * ctx, codex_rendezvous_t * acc)
{
	SSL * ssl = (SSL *)0;
	BIO * bio = (BIO *)0;
	int rc = -1;

	do {

		bio = BIO_pop(acc);
		if (bio == (BIO *)0) {

			rc = BIO_do_accept(acc);
			if (rc <= 0) {
				codex_perror("BIO_do_accept");
				break;
			}

			bio = BIO_pop(acc);
			if (bio == (BIO *)0) {
				break;
			}

		}

		ssl = SSL_new(ctx);
		if (ssl == (SSL *)0) {
			codex_perror("SSL_new");
			break;
		}

		/*
		 * Indicate to SSL that this connection is the server side.
		 */

		SSL_set_accept_state(ssl);

		/*
		 * And the BIO we just received is both the source and the sink.
		 */

		SSL_set_bio(ssl, bio, bio);

	} while (0);

	if (ssl != (SSL *)0) {
		/* Do nothing. */
	} else if (bio == (BIO *)0) {
		/* Do nothing. */
	} else {
		rc = BIO_free(acc);
		if (rc != 1) {
			codex_perror("BIO_free");
		}
	}

	return ssl;
}
