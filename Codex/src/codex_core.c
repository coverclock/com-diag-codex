/* vi: set ts=4 expandtab shiftwidth=4: */
/**
 * @file
 *
 * Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 *
 * CORE
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
#include <stdio.h>
#include "com/diag/codex/codex.h"
#include "com/diag/diminuto/diminuto_criticalsection.h"
#include "com/diag/diminuto/diminuto_log.h"
#include "com/diag/diminuto/diminuto_delay.h"
#include "com/diag/diminuto/diminuto_token.h"
#include "codex.h"

/*******************************************************************************
 * CONSTANTS
 ******************************************************************************/

const char * const codex_client_password_env = COM_DIAG_CODEX_CLIENT_PASSWORD_ENV;

const char * const codex_server_password_env = COM_DIAG_CODEX_SERVER_PASSWORD_ENV;

const char * const codex_method = DIMINUTO_TOKEN_TOKEN(COM_DIAG_CODEX_METHOD);

const char * const codex_cipher_list = COM_DIAG_CODEX_CIPHER_LIST;

const int codex_certificate_depth = COM_DIAG_CODEX_CERTIFICATE_DEPTH;

const long codex_renegotiate_bytes = COM_DIAG_CODEX_RENEGOTIATE_BYTES;

const long codex_renegotiate_seconds = COM_DIAG_CODEX_RENEGOTIATE_SECONDS;

/*******************************************************************************
 * GLOBALS
 ******************************************************************************/

DH * codex_dh = (DH *)0;

/*******************************************************************************
 * STATICS
 ******************************************************************************/

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static bool initialized = false;

/*******************************************************************************
 * DEBUGGING
 ******************************************************************************/

#if 0
#	define CODEX_WTF ((void)fprintf(stderr, "CODEX_WTF: %s[%d]\n", __FILE__, __LINE__))
#else
#	define CODEX_WTF ((void)0)
#endif

void codex_wtf(const char * file, int line, const codex_connection_t * ssl, int rc, int errnumber)
{
	unsigned long error = -1;
	int serror = -1;

	error = ERR_peek_error();
	if (ssl != (SSL *)0) { serror = SSL_get_error(ssl, rc); }

	DIMINUTO_LOG_NOTICE("codex_wtf: file=\"%s\" line=%d ssl=%p rc=%d ERR_get_error=%ld SSL_get_error=%d errno=%d\n", file, line, ssl, rc, error, serror, errnumber);
}

/*******************************************************************************
 * ERRORS
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

codex_serror_t codex_serror(const char * str, const SSL * ssl, int rc)
{
	codex_serror_t result = CODEX_SERROR_OTHER;
	int error = -1;
	int save = -1;
	long queued = -1;
	const char * debug = (const char *)0;
	const char * information = (const char *)0;
	const char * notice = (const char *)0;
	const char * warning = (const char *)0;

	save = errno;

	error = SSL_get_error(ssl, rc);
	result = (codex_serror_t)error;
	switch (error) {

	case CODEX_SERROR_NONE:
		/* Only happens if (rc > 0). */
		debug = "NONE";
		break;

	case CODEX_SERROR_ZERO:
		/* Only happens if received shutdown (presumably rc==0). */
		debug = "ZERO";
		break;

	case CODEX_SERROR_READ:
		information = "READ";
		break;

	case CODEX_SERROR_WRITE:
		information = "WRITE";
		break;

	case CODEX_SERROR_CONNECT:
		information = "CONNECT";
		break;

	case CODEX_SERROR_ACCEPT:
		information = "ACCEPT";
		break;

	case CODEX_SERROR_LOOKUP:
		notice = "LOOKUP";
		break;

	case CODEX_SERROR_SYSCALL:
		queued = ERR_peek_error();
		if (queued != 0) {
			codex_perror(str);
		} else if (save == 0) {
			/* Do nothing. */
		} else if (save == EINTR) {
			/* Do nothing. */
		} else {
			errno = save;
			diminuto_perror(str);
		}
		debug = "SYSCALL";
		break;

	case CODEX_SERROR_SSL:
		errno = save;
		codex_perror(str);
		debug = "SSL";
		break;

	default:
		/* Might happen if libssl or libcrypto are updated. */
		result = CODEX_SERROR_OTHER;
		warning = "OTHER";
		break;

	}

	/*
	 * Here:
	 * DEBUG items are those that aren't important or are redundant to log.
	 * INFORMATION items are those that that might be of interest sometimes.
	 * NOTICE items are those which I'm actively debugging or curious about.
	 * WARNING items are where the OpenSSL API has done something unexpected.
	 */

	if (warning != (const char *)0) {
		DIMINUTO_LOG_WARNING("codex_serror: str=\"%s\" ssl=%p rc=%d error=%d errno=%d warning=\"%s\" result=%d\n", str, ssl, rc, error, save, warning, result);
	} else if (notice != (const char *)0) {
		DIMINUTO_LOG_NOTICE("codex_serror: str=\"%s\" ssl=%p rc=%d error=%d errno=%d notice=\"%s\" result=%d\n", str, ssl, rc, error, save, notice, result);
	} else if (information != (const char *)0) {
		DIMINUTO_LOG_INFORMATION("codex_serror: str=\"%s\" ssl=%p rc=%d error=%d errno=%d information=\"%s\" result=%d\n", str, ssl, rc, error, save, information, result);
	} else if (debug != (const char *)0) {
		DIMINUTO_LOG_DEBUG("codex_serror: str=\"%s\" ssl=%p rc=%d error=%d errno=%d debug=\"%s\" result=%d\n", str, ssl, rc, error, save, debug, result);
	} else {
		/* Do nothing. */
	}

	errno = save;

	return result;
}

/*******************************************************************************
 * HELPERS
 ******************************************************************************/

DH * codex_parameters_import(const char * dhf)
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

	} while (false);

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
	X509_NAME * nam = (X509_NAME *)0;
	int depth = -1;
	int error = 0;
	const char * text = (const char *)0;
	char name[256];

	depth = X509_STORE_CTX_get_error_depth(ctx);

	crt = X509_STORE_CTX_get_current_cert(ctx);
	if (crt != (X509 *)0) {

		/*
		 * These fields are deliberately displayed in the same order as when
		 * using the "openssl x509 -subject -issuer -noout" command.
		 */

		name[0] = '\0';
		nam = X509_get_issuer_name(crt);
		if (nam != (X509_NAME *)0) {
			X509_NAME_oneline(nam, name, sizeof(name));
			name[sizeof(name) - 1] = '\0';
		}
		DIMINUTO_LOG_INFORMATION("codex_verification_callback: subject[%d]=\"%s\"\n", depth, name);

		name[0] = '\0';
		nam = X509_get_issuer_name(crt);
		if (nam != (X509_NAME *)0) {
			X509_NAME_oneline(nam, name, sizeof(name));
			name[sizeof(name) - 1] = '\0';
		}
		DIMINUTO_LOG_INFORMATION("codex_verification_callback: issuer[%d]=\"%s\"\n", depth, name);

	}

	if (!ok) {

		error = X509_STORE_CTX_get_error(ctx);
		text = X509_verify_cert_error_string(error);
		DIMINUTO_LOG_WARNING("codex_verification_callback: error=%d=\"%s\"\n", error, (text != (const char *)0) ? text : "");

	}

	return ok;
}

DH * codex_parameters_callback(SSL * ssl, int exp, int length)
{
	DH * dhp = (DH *)0;

	DIMINUTO_CRITICAL_SECTION_BEGIN(&mutex);

		dhp = codex_dh;

	DIMINUTO_CRITICAL_SECTION_END;

	if (dhp == (DH *)0) {
		DIMINUTO_LOG_ERROR("codex_parameters_callback: ssl=%p export=%d length=%d result=NULL\n", ssl, exp, length);
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

		if (!initialized) {

			rc = SSL_library_init();
			if (rc != 1) {
				codex_perror("SSL_library_init");
			} else {
				SSL_load_error_strings();
				OPENSSL_config((const char *)0);
				initialized = true;
			}

		}

	DIMINUTO_CRITICAL_SECTION_END;

	return initialized ? 0 : -1;
}

int codex_parameters(const char * dhf)
{
	int rc = 0;

	DIMINUTO_CRITICAL_SECTION_BEGIN(&mutex);

		if (dhf == (const char *)0) {
			/* Do nothing. */
		} else  if (codex_dh != (DH *)0) {
			/* Do nothing. */
		} else {
			codex_dh = codex_parameters_import(dhf);
			if (codex_dh == (DH *)0) {
				rc = -1;
			}
		}

	DIMINUTO_CRITICAL_SECTION_END;


	return rc;

}

/*******************************************************************************
 * CONTEXT
 ******************************************************************************/

codex_context_t * codex_context_new(const char * env, const char * caf, const char * cap, const char * crt, const char * key, int flags, int depth, int options)
{
	SSL_CTX * result = (SSL_CTX *)0;
	const SSL_METHOD * method = (SSL_METHOD *)0;
	SSL_CTX * ctx = (SSL_CTX *)0;
	char * password = (char *)0;
	int rc = -1;

	do {

		method = COM_DIAG_CODEX_METHOD;
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

		rc = SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM);
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

/*
 * This was mostly written by reverse engineering X509V3_EXT_print() in
 * crypto/x509v3/v3_prn.c from https://github.com/openssl/openssl.git. I
 * have tried to exercise all the nominal paths, but no guarantees.
 */
codex_connection_verify_t codex_connection_verify(codex_connection_t * ssl, const char * expected)
{
	codex_connection_verify_t result = CODEX_CONNECTION_VERIFY_PASSED;
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
	void * ptr = (void *)0;
	STACK_OF(CONF_VALUE) * vals = (STACK_OF(CONF_VALUE) *)0;
	int jj = 0;
	CONF_VALUE * val = (CONF_VALUE *)0;
	int lim = 0;
	X509_NAME * nam = (X509_NAME *)0;
	char buffer[256];
	int rc = -1;
	const char * text = (const char *)0;
	char * value = (char *)0;
	const unsigned char * p = (const unsigned char *)0;
	ASN1_OCTET_STRING * extoct = (ASN1_OCTET_STRING *)0;
	int extlen = 0;
	const ASN1_ITEM * it = (const ASN1_ITEM *)0;

	do {

		if (expected == (const char *)0) {
			DIMINUTO_LOG_WARNING("codex_connection_verify: ssl=%p expected=%p\n", ssl, expected);
			break;
		}

		crt = SSL_get_peer_certificate(ssl);
		if (crt == (X509 *)0) {
			DIMINUTO_LOG_WARNING("codex_connection_verify: ssl=%p crt=%p\n", ssl, crt);
			break;
		}

		DIMINUTO_LOG_DEBUG("codex_connection_verify: ssl=%p crt=%p expected=\"%s\"\n", ssl, crt, expected);

		count = X509_get_ext_count(crt);
		DIMINUTO_LOG_DEBUG("codex_connection_verify: ssl=%p crt=%p extensions=%d\n", ssl, crt, count);
		for (ii = 0; ii < count; ++ii) {

			ext = X509_get_ext(crt, ii);
			if (ext == (X509_EXTENSION *)0) {
				CODEX_WTF;
				continue;
			}

			obj = X509_EXTENSION_get_object(ext);
			if (obj == (ASN1_OBJECT *)0) {
				CODEX_WTF;
				continue;
			}

			nid = OBJ_obj2nid(obj);
			if (nid == NID_undef) {
				CODEX_WTF;
				continue;
			}

			str = OBJ_nid2sn(nid);
			if (str == (const char *)0) {
				CODEX_WTF;
				continue;
			}

			DIMINUTO_LOG_DEBUG("codex_connection_verify: EXT \"%s\"\n", str);

			if (strcmp(str, COM_DIAG_CODEX_SHORTNAME_SUBJECTALTNAME) != 0) {
				CODEX_WTF;
				continue;
			}

			extoct = X509_EXTENSION_get_data(ext);
			if (extoct == (ASN1_OCTET_STRING *)0) {
				CODEX_WTF;
				continue;
			}

			extlen = ASN1_STRING_length(extoct);

			/*
			 * The function X509V3_EXT_print() uses ASN1_STRING_get0_data()
			 * to extract this value. But even though that function uses it, and
			 * I find the function in the ASN.1 library in libcrypto, and
			 * there's a function prototype for it in the openssl/asn1.h header
			 * file, and a man page for it on the OpenSSL.org web site, the
			 * linker can't find it. Weird.
			 */

			p = extoct->data; /* ?ASN1_STRING_get0_data(extoct)? */
			if (p == (const unsigned char *)0) {
				CODEX_WTF;
				continue;
			}

			meth = X509V3_EXT_get(ext);
			if (meth == (X509V3_EXT_METHOD *)0) {
				DIMINUTO_LOG_DEBUG("codex_connection_verify: none \"%s\"\n", p);
				continue;
			}

			it = ASN1_ITEM_ptr(meth->it);

			if (it != (ASN1_ITEM_EXP *)0) {

				ptr = ASN1_item_d2i((ASN1_VALUE **)0, &p, extlen, it);
				if (ptr == (void *)0) {
					CODEX_WTF;
					continue;
				}

			} else if (meth->d2i != (X509V3_EXT_D2I)0) {

				ptr = meth->d2i((void *)0, &p, extlen);
				if (ptr == (void *)0) {
					CODEX_WTF;
					continue;
				}

			} else {

				CODEX_WTF;
				continue;

			}

			if (meth->i2v != (X509V3_EXT_I2V)0) {

				vals = meth->i2v(meth, ptr, (STACK_OF(CONF_VALUE) *)0);
				if (vals == (STACK_OF(CONF_VALUE) *)0) {
					continue;
				}

				lim = sk_CONF_VALUE_num(vals);
				DIMINUTO_LOG_DEBUG("codex_connection_verify: ssl=%p crt=%p stack=%d\n", ssl, crt, lim);
				for (jj = 0; jj < lim; ++jj) {

					val = sk_CONF_VALUE_value(vals, jj);
					if (val == (CONF_VALUE *)0) {
						CODEX_WTF;
						continue;
					}

					if (val->name == (char *)0) {
						CODEX_WTF;
						continue;
					}

					if (val->value == (char *)0) {
						CODEX_WTF;
						continue;
					}

					DIMINUTO_LOG_DEBUG("codex_connection_verify: FQDN \"%s\"=\"%s\"\n", val->name, val->value);

					if (strcmp(val->name, COM_DIAG_CODEX_CONFNAME_DNS) != 0) {
						CODEX_WTF;
						continue;
					}

					if (strcmp(val->value, expected) != 0) {
						CODEX_WTF;
						continue;
					}

					found = !0;
					break;
				}

				if (found) {
					break;
				}

			} else if (meth->i2s != (X509V3_EXT_I2S)0) {

				value = meth->i2s(meth, ptr);
				if (value == (char *)0) {
					CODEX_WTF;
					continue;
				}

				/*
				 * I don't actually know how this one can occur, so I skip it.
				 * But I'm interested in what it's value might be.
				 */

				DIMINUTO_LOG_DEBUG("codex_connection_verify: FQDN \"%s\"\n", value);
				continue;

			} else {

				DIMINUTO_LOG_DEBUG("codex_connection_verify: other \"%s\"\n", p);
				continue;

			}
		}

		if (found) {
			/*
			 * Fully Qualified Domain Name (FQDN) matches.
			 */
			DIMINUTO_LOG_INFORMATION("codex_connection_verify: FQDN=\"%s\"\n", expected);
			result = CODEX_CONNECTION_VERIFY_FQDN;
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

		DIMINUTO_LOG_DEBUG("codex_connection_verify: CN \"%s\"=\"%s\"\n", SN_commonName, buffer);

		if (strcasecmp(buffer, expected) != 0) {
			break;
		}

		/*
		 * Common Name (CN) matches.
		 */
		DIMINUTO_LOG_INFORMATION("codex_connection_verify: CN=\"%s\"\n", expected);
		result = CODEX_CONNECTION_VERIFY_CN;

		found = !0;
		break;

	} while (false);

	/*
	 * If either we weren't asked to check the peer FQDN or CN, or if we were
	 * and the result was a match against our expected FQDN or CN, then we
	 * change the error number to what the API's own verification returned.
	 * Otherwise we leave the error set to the Application Verification error
	 * number to indicate we reject it regardless of what the API said.
	 */

	if ((expected == (const char *)0) || found) {
		error = SSL_get_verify_result(ssl);
	}

	if (crt != (X509 *)0) {
		X509_free(crt);
	}

	if (error != X509_V_OK) {
		text = X509_verify_cert_error_string(error);
		DIMINUTO_LOG_WARNING("codex_connection_verify: FAILED <%d> \"%s\"\n", error, (text != (const char *)0) ? text : "");
		result = CODEX_CONNECTION_VERIFY_FAILED;
	}

	return result;
}

bool codex_connection_closed(codex_connection_t * ssl)
{
	int flags = 0;

	flags = SSL_get_shutdown(ssl);

	return ((flags & SSL_RECEIVED_SHUTDOWN) != 0);
}

int codex_connection_close(codex_connection_t * ssl)
{
	int rc = 0;
	int flags = 0;
	int error = 0;
	uint8_t empty[0];

	flags = SSL_get_shutdown(ssl);
	if ((flags & SSL_SENT_SHUTDOWN) == 0) {
		while (true) {
			rc = SSL_shutdown(ssl);
			if (rc > 0) {
				rc = 0;
				break;
			} else if (rc == 0) {
				diminuto_yield();
			} else {
				(void)codex_serror("SSL_shutdown", ssl, rc);
				break;
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

bool codex_connection_is_server(const codex_connection_t * ssl)
{
	/*
	 * Parameter to SSL_is_server() can and should be const.
	 */
	return !!SSL_is_server((codex_connection_t *)ssl);
}

/*******************************************************************************
 * INPUT/OUTPUT
 ******************************************************************************/

int codex_connection_read(codex_connection_t * ssl, void * buffer, int size)
{
	int rc = -1;
	int error = 0;
	long queued = -1;
	bool retry = false;
	uint8_t empty[0];

	do {

		if (size > 0) {
			rc = SSL_read(ssl, buffer, size);
			if (rc <= 0) {

				retry = false;
				error = codex_serror("SSL_read", ssl, rc);
				switch (error) {
				case CODEX_SERROR_NONE:
					if (!retry) { retry = true; }
					break;
				case CODEX_SERROR_SSL:
					rc = -1;
					break;
				case CODEX_SERROR_READ:
					if (!retry) { retry = true; }
					break;
				case CODEX_SERROR_WRITE:
					rc = -1; /* TODO */
					break;
				case CODEX_SERROR_LOOKUP:
					rc = -1; /* TODO */
					break;
				case CODEX_SERROR_SYSCALL:
					rc = -1;
					break;
				case CODEX_SERROR_ZERO:
					rc = 0;
					break;
				case CODEX_SERROR_CONNECT:
					rc = -1; /* Should never happen. */
					break;
				case CODEX_SERROR_ACCEPT:
					rc = -1; /* Should never happen. */
					break;
				case CODEX_SERROR_OTHER:
				default:
					rc = -1; /* Might happen if OpenSSL is updated. */
					break;
				}

			}
		}

		DIMINUTO_LOG_DEBUG("codex_connection_read: ssl=%p buffer=%p size=%d rc=%d retry=%d\n", ssl, buffer, size, rc, retry);

		if (retry) {
			diminuto_yield();
		}

	} while (retry);

	return rc;
}

int codex_connection_write(codex_connection_t * ssl, const void * buffer, int size)
{
	int rc = -1;
	int error = 0;
	bool retry = false;
	uint8_t empty[0];

	do {

		if (size > 0) {
			rc = SSL_write(ssl, buffer, size);
			if (rc <= 0) {

				retry = false;
				error = codex_serror("SSL_write", ssl, rc);
				switch (error) {
				case CODEX_SERROR_NONE:
					retry = true;
					break;
				case CODEX_SERROR_SSL:
					rc = -1;
					break;
				case CODEX_SERROR_READ:
					rc = -1; /* TODO */
					break;
				case CODEX_SERROR_WRITE:
					if (!retry) { retry = true; }
					break;
				case CODEX_SERROR_LOOKUP:
					rc = -1; /* TODO */
					break;
				case CODEX_SERROR_SYSCALL:
					rc = -1;
					break;
				case CODEX_SERROR_ZERO:
					rc = 0;
					break;
				case CODEX_SERROR_CONNECT:
					rc = -1; /* Should never happen. */
					break;
				case CODEX_SERROR_ACCEPT:
					rc = -1; /* Should never happen. */
					break;
				case CODEX_SERROR_OTHER:
				default:
					rc = -1; /* Might happen if OpenSSL is updated. */
					break;
				}

			}
		}

		DIMINUTO_LOG_DEBUG("codex_connection_write: ssl=%p buffer=%p size=%d rc=%d retry=%d\n", ssl, buffer, size, rc, retry);

		if (retry) {
			diminuto_yield();
		}

	} while (retry);

	return rc;
}

/*******************************************************************************
 * MULTIPLEXING
 ******************************************************************************/

/*
 * I've successfully multiplexed multiple SSL connections using select(2) via
 * the Diminuto mux feature. But in SSL there is a *lot* going on under the
 * hood. The byte stream the application reads and writes is an artifact of
 * all the authentication and crypto going on in libssl and libcrypto. The
 * Linux socket and multiplexing implementation in the kernel lies below all
 * of this and knows *nothing* about it. So the fact that there's data to be
 * read on the socket doesn't mean there's _application_ data to be read. A lot
 * of application reads and writes may merely be driving the underlying protocol
 * and associated state machines in the SSL implementation. Hence multiplexing
 * isn't as useful as it might seem. A multi-threaded server approach, which
 * uses blocking reads and writes, albeit less scalable, might ultimately be
 * more useful.
 */

int codex_rendezvous_descriptor(codex_rendezvous_t * bio)
{
	return BIO_get_fd(bio, (int *)0);
}

int codex_connection_descriptor(codex_connection_t * ssl)
{
	return SSL_get_fd(ssl);
}

/*******************************************************************************
 * CLIENT
 ******************************************************************************/

codex_context_t * codex_client_context_new(const char * caf, const char * cap, const char * crt, const char * key)
{
	return codex_context_new(codex_client_password_env, caf, cap, crt, key, SSL_VERIFY_PEER, codex_certificate_depth, SSL_OP_ALL | SSL_OP_NO_SSLv2);
}

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

		(void)codex_serror("SSL_connect", ssl, rc);

		SSL_free(ssl);

		ssl = (SSL *)0;
		bio = (BIO *)0;

	} while (false);

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

codex_context_t * codex_server_context_new(const char * caf, const char * cap, const char * crt, const char * key)
{
	return codex_context_new(codex_server_password_env, caf, cap, crt, key, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, codex_certificate_depth, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_SINGLE_DH_USE);
}

codex_rendezvous_t * codex_server_rendezvous_new(const char * nearend)
{
	BIO * bio = (BIO *)0;
	int rc = -1;
	int fd = -1;

	do {

		bio = BIO_new_accept(nearend);
		if (bio == (BIO *)0) {
			codex_perror("BIO_new_accept");
			break;
		}

		/*
		 * This doesn't appear to work, but at least it's benign.
		 */
		(void)BIO_set_bind_mode(bio, BIO_BIND_REUSEADDR_IF_UNUSED);

		rc = BIO_do_accept(bio);
		if (rc > 0) {
			break;
		}
		codex_perror("BIO_do_accept");

		rc = BIO_free(bio);
		if (rc != 1) {
			codex_perror("BIO_free");
		}

		bio = (BIO *)0;

	} while (false);

	return bio;
}

codex_rendezvous_t * codex_server_rendezvous_free(codex_rendezvous_t * bio)
{
	int rc = -1;

	do {

		rc = BIO_free(bio);
		if (rc != 1) {
			codex_perror("BIO_free");
			break;
		}

		bio = (BIO *)0;

	} while (false);

	return bio;
}

codex_connection_t * codex_server_connection_new(codex_context_t * ctx, codex_rendezvous_t * bio)
{
	SSL * ssl = (SSL *)0;
	BIO * tmp = (BIO *)0;
	int rc = -1;

	do {

		tmp = BIO_pop(bio);
		if (tmp == (BIO *)0) {

			rc = BIO_do_accept(bio);
			if (rc <= 0) {
				codex_perror("BIO_do_accept");
				break;
			}

			tmp = BIO_pop(bio);
			if (tmp == (BIO *)0) {
				break;
			}

		}

		ssl = SSL_new(ctx);
		if (ssl == (SSL *)0) {
			codex_perror("SSL_new");
			break;
		}

		/*
		 * Indicate to SSL that this connection is the server side...
		 */

		SSL_set_accept_state(ssl);

		/*
		 * and the BIO we just received is both the source and the sink.
		 */

		SSL_set_bio(ssl, tmp, tmp);

	} while (false);

	if (ssl != (SSL *)0) {
		/* Do nothing. */
	} else if (tmp == (BIO *)0) {
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
 * RENEGOTIATION
 ******************************************************************************/

int codex_connection_renegotiate(codex_connection_t * ssl)
{
	int rc = -1;

	do {

		rc = SSL_renegotiate(ssl);
		if (rc != 1) {
			(void)codex_serror("SSL_renegotiate", ssl, rc);
			rc = -1;
			break;
		}

		rc = SSL_do_handshake(ssl);
		if (rc != 1) {
			(void)codex_serror("SSL_do_handshake", ssl, rc);
			rc = -1;
			break;
		}

		if (!SSL_is_server(ssl)) {
			rc = 0;
			break;
		}

		ssl->state = SSL_ST_ACCEPT;

		rc = SSL_do_handshake(ssl);
		if (rc != 1) {
			(void)codex_serror("SSL_do_handshake(2)", ssl, rc);
			rc = -1;
			break;
		}

		rc = 0;

	} while (false);

	return rc;
}

bool codex_connection_renegotiating(const codex_connection_t * ssl)
{
	/*
	 * Parameter of SSL_renegotiatate_pending() can and should be const.
	 */
	return SSL_renegotiate_pending((codex_connection_t *)ssl);
}

