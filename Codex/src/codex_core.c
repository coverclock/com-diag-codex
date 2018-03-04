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

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <stdio.h>
#include "com/diag/codex/codex.h"
#include "com/diag/diminuto/diminuto_criticalsection.h"
#include "com/diag/diminuto/diminuto_log.h"
#include "com/diag/diminuto/diminuto_delay.h"
#include "com/diag/diminuto/diminuto_types.h"
#include "com/diag/diminuto/diminuto_ipc4.h"
#include "com/diag/diminuto/diminuto_ipc6.h"
#include "codex.h"

/*******************************************************************************
 * GLOBALS
 ******************************************************************************/

DH * codex_dh = (DH *)0;

/*******************************************************************************
 * PARAMETERS
 ******************************************************************************/

#undef COM_DIAG_CODEX_SETTOR
#define COM_DIAG_CODEX_SETTOR(_NAME_, _TYPE_, _UNDEFINED_, _DEFAULT_) \
	static _TYPE_ codex_##_NAME_ = _DEFAULT_;

#include "codex_settors.h"

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

	DIMINUTO_LOG_NOTICE("codex_wtf: WTF file=\"%s\" line=%d ssl=%p rc=%d ERR_get_error=%ld SSL_get_error=%d errno=%d\n", file, line, ssl, rc, error, serror, errnumber);
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
		DIMINUTO_LOG_ERROR("codex_perror: \"%s\" errno=%d index=%d error=0x%08x=\"%s\"\n", str, save, ii++, error, buffer);
	}

	if (ii > 0) {
		/* Do nothing. */
	} else if (save == 0) {
		/* Do nothing. */
	} else {
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

	save = errno;

	error = SSL_get_error(ssl, rc);
	switch (error) {

	case SSL_ERROR_NONE:
		/* Only happens if (rc > 0). */
		result = CODEX_SERROR_NONE;
		break;

	case SSL_ERROR_ZERO_RETURN:
		/* Only happens if received shutdown (presumably rc==0). */
		result = CODEX_SERROR_ZERO;
		break;

	case SSL_ERROR_WANT_READ:
		result = CODEX_SERROR_READ;
		break;

	case SSL_ERROR_WANT_WRITE:
		result = CODEX_SERROR_WRITE;
		break;

	case SSL_ERROR_WANT_CONNECT:
		result = CODEX_SERROR_CONNECT;
		break;

	case SSL_ERROR_WANT_ACCEPT:
		result = CODEX_SERROR_ACCEPT;
		break;

	case SSL_ERROR_WANT_X509_LOOKUP:
		result = CODEX_SERROR_LOOKUP;
		break;

	case SSL_ERROR_SYSCALL:
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
		result = CODEX_SERROR_SYSCALL;
		break;

	case SSL_ERROR_SSL:
		errno = save;
		codex_perror(str);
		result = CODEX_SERROR_SSL;
		break;

	default:
		/* Might happen if libssl or libcrypto are updated. */
		result = CODEX_SERROR_OTHER;
		break;

	}

	if (rc < 0) {
		DIMINUTO_LOG_INFORMATION("codex_serror: \"%s\" ssl=%p rc=%d serror=%d errno=%d error='%c'\n", str, ssl, rc, error, save, result);
	} else {
		DIMINUTO_LOG_DEBUG("codex_serror: \"%s\" ssl=%p rc=%d serror=%d errno=%d error='%c'\n", str, ssl, rc, error, save, result);
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
		DIMINUTO_LOG_INFORMATION("codex_verification_callback: ctx=%p subject[%d]=\"%s\"\n", ctx, depth, name);

		name[0] = '\0';
		nam = X509_get_issuer_name(crt);
		if (nam != (X509_NAME *)0) {
			X509_NAME_oneline(nam, name, sizeof(name));
			name[sizeof(name) - 1] = '\0';
		}
		DIMINUTO_LOG_INFORMATION("codex_verification_callback: ctx=%p issuer[%d]=\"%s\"\n", ctx, depth, name);

	}

	if (!ok) {

		error = X509_STORE_CTX_get_error(ctx);
		text = X509_verify_cert_error_string(error);
		DIMINUTO_LOG_NOTICE("codex_verification_callback: ctx=%p error=%d=\"%s\"\n", ctx, error, (text != (const char *)0) ? text : "");

		switch (error) {

		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
		case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
			if (codex_self_signed_certificates) {
				DIMINUTO_LOG_NOTICE("codex_verification_callback: ctx=%p codex_self_signed_certificates=%d\n", ctx, codex_self_signed_certificates);
				ok = 1;
			}
			break;

		default:
			/* Do nothing. */
			break;

		}

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
 * GETTORS/SETTORS
 ******************************************************************************/

#undef COM_DIAG_CODEX_SETTOR
#define COM_DIAG_CODEX_SETTOR(_NAME_, _TYPE_, _UNDEFINED_, _DEFAULT_) \
	_TYPE_ codex_set_##_NAME_(_TYPE_ now) \
	{ \
		_TYPE_ was = (_TYPE_)_UNDEFINED_; \
		DIMINUTO_CRITICAL_SECTION_BEGIN(&mutex); \
			was = codex_##_NAME_; \
			if (now != (_TYPE_)_UNDEFINED_) { codex_##_NAME_ = now; } \
		DIMINUTO_CRITICAL_SECTION_END; \
		return was; \
	}

#include "codex_settors.h"

/*******************************************************************************
 * CONTEXT
 ******************************************************************************/

codex_context_t * codex_context_new(const char * env, const char * caf, const char * cap, const char * crt, const char * key, int flags, int depth, int options, codex_method_t method, const char * list, const char * context)
{
	SSL_CTX * result = (SSL_CTX *)0;
	const SSL_METHOD * table = (SSL_METHOD *)0;
	SSL_CTX * ctx = (SSL_CTX *)0;
	char * password = (char *)0;
	int rc = -1;

	do {

		table = (*method)();
		if (table == (SSL_METHOD *)0) {
			codex_perror("(*method)");
			break;
		}

		ctx = SSL_CTX_new(table);
		if (ctx == (SSL_CTX *)0) {
			codex_perror("SSL_CTX_new");
			break;
		}

		rc = SSL_CTX_load_verify_locations(ctx, caf, cap);
		if (rc != 1) {
			codex_perror("SSL_CTX_load_verify_locations");
			break;
		}

		/*
		 * Not completely convinced this is a good idea.
		 */
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

		(void)SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

		SSL_CTX_set_verify(ctx, flags, codex_verification_callback);

		SSL_CTX_set_verify_depth(ctx, depth);

		(void)SSL_CTX_set_options(ctx, options);

		SSL_CTX_set_tmp_dh_callback(ctx, codex_parameters_callback);

		rc = SSL_CTX_set_cipher_list(ctx, list);
		if (rc != 1) {
			codex_perror("SSL_CTX_set_cipher_list");
			break;
		}

		if (context != (const char *)0) {
			rc = SSL_CTX_set_session_id_context(ctx, context, strlen(context));
			if (rc != 1) {
				/*
				 * Not fatal but will probably break renegotiation handshake
				 * from the server side.
				 */
				DIMINUTO_LOG_ERROR("codex_context_new: SSL_CTX_set_session_id_context\n");
			}
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
 * crypto/x509v3/v3_prn.c from https://github.com/openssl/openssl. I
 * have tried to exercise all the nominal paths, but no guarantees.
 */
int codex_connection_verify(codex_connection_t * ssl, const char * expected)
{
	int result = CODEX_VERIFY_FAILED;
	long error = X509_V_ERR_APPLICATION_VERIFICATION;
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
	int rc = -1;
	const char * text = (const char *)0;
	char * value = (char *)0;
	const unsigned char * p = (const unsigned char *)0;
	ASN1_OCTET_STRING * extoct = (ASN1_OCTET_STRING *)0;
	int extlen = 0;
	const ASN1_ITEM * it = (const ASN1_ITEM *)0;
	char buffer[256] = { '\0' };
	int fd = -1;
	diminuto_ipv4_t farend4 = 0;
	diminuto_ipv6_t farend6 = { 0 };
	diminuto_ipv4_t * address4 = (diminuto_ipv4_t *)0;
	diminuto_ipv6_t * address6 = (diminuto_ipv6_t *)0;
	diminuto_ipv4_t * addresses4 = (diminuto_ipv4_t *)0;
	diminuto_ipv6_t * addresses6 = (diminuto_ipv6_t *)0;
	diminuto_ipv4_buffer_t buffer4 = { '\0' };
	diminuto_ipv6_buffer_t buffer6 = { '\0' };
	diminuto_ipv4_buffer_t debug4 = { '\0' };
	diminuto_ipv6_buffer_t debug6 = { '\0' };
	const char * anycn = "";
	const char * anyfqdn = "";
	const char * cn = (const char *)0;
	const char * fqdn = (const char *)0;

	do {

		/*
		 * Before we descend into the certificate, we get our IPv4 and/or
		 * IPv6 addresses from the far end of the SSL connection. If we don't
		 * have one or the other (which should be impossible), we reject
		 * this connection.
		 */

		fd = SSL_get_fd(ssl);
		if (fd < 0) {
			DIMINUTO_LOG_ERROR("codex_connection_verify: fd ssl=%p crt=%p fd=%d\n", ssl, crt, fd);
			break;
		}

		farend4 = DIMINUTO_IPC4_UNSPECIFIED;
		rc = diminuto_ipc4_farend(fd, &farend4, (diminuto_port_t *)0);
		if (rc < 0) {
			DIMINUTO_LOG_ERROR("codex_connection_verify: ipc4 ssl=%p crt=%p rc=%d\n", ssl, crt, rc);
			break;
		}

		diminuto_ipc4_address2string(farend4, buffer4, sizeof(buffer4));

		farend6 = DIMINUTO_IPC6_UNSPECIFIED;
		rc = diminuto_ipc6_farend(fd, &farend6, (diminuto_port_t *)0);
		if (rc < 0) {
			DIMINUTO_LOG_ERROR("codex_connection_verify: ipc6 ssl=%p crt=%p rc=%d\n", ssl, crt, rc);
			break;
		}

		diminuto_ipc6_address2string(farend6, buffer6, sizeof(buffer6));

		if (!diminuto_ipc4_is_unspecified(&farend4)) {
			/* Do nothing. */
		} else if (!diminuto_ipc6_is_unspecified(&farend6)) {
			/* Do nothing. */
		} else {
			DIMINUTO_LOG_ERROR("codex_connection_verify: farend ssl=%p IPv4=%s IPv6=%s\n", ssl, buffer4, buffer6); /* Should be impossible. */
			break;
		}

		DIMINUTO_LOG_INFORMATION("codex_connection_verify: farend ssl=%p IPv4=%s IPv6=%s mask=0x%x\n", ssl, buffer4, buffer6, result);

		/*
		 * Next we check for a match against the Common Name (CN). We extract
		 * the CN even if we expect nothing, as a way of validity checking the
		 * certificate. If the certificate has no CN, we reject it, even if
		 * we don't care what the CN is.
		 */

		crt = SSL_get_peer_certificate(ssl);
		if (crt == (X509 *)0) {
			DIMINUTO_LOG_WARNING("codex_connection_verify: crt ssl=%p crt=%p\n", ssl, crt);
			break;
		}

		nam = X509_get_subject_name(crt);
		if (nam == (X509_NAME *)0) {
			DIMINUTO_LOG_WARNING("codex_connection_verify: nam ssl=%p crt=%p cn=%p\n", ssl, crt, nam);
			break;
		}

		buffer[0] = '\0';
		rc = X509_NAME_get_text_by_NID(nam, NID_commonName, buffer, sizeof(buffer));
		if (rc <= 0) {
			DIMINUTO_LOG_WARNING("codex_connection_verify: text ssl=%p crt=%p [cn]=%d\n", ssl, crt, rc);
			break;
		}
		buffer[sizeof(buffer) - 1] = '\0';

		anycn = buffer;
		DIMINUTO_LOG_DEBUG("codex_connection_verify: nid ssl=%p crt=%p \"%s\"=\"%s\"\n", ssl, crt, SN_commonName, anycn);

		if (expected == (const char *)0) {

			/*
			 * The certificate has a CN and seems otherwise valid, but the
			 * application chooses not to expect any CN or FQDN.
			 */

			result |= CODEX_VERIFY_PASSED;
			DIMINUTO_LOG_INFORMATION("codex_connection_verify: nil ssl=%p crt=%p CN=\"%s\" expected=%p mask=0x%x\n", ssl, crt, anycn, expected, result);

		} else if (strcasecmp(anycn, expected) == 0) {

			/*
			 * The CN matches. If that's the only verification that occurs, the
			 * application must decide if that's sufficient.
			 */

			cn = anycn;
			result |= CODEX_VERIFY_CN;
			DIMINUTO_LOG_INFORMATION("codex_connection_verify: cn ssl=%p crt=%p CN=\"%s\" mask=0x%x\n", ssl, crt, cn, result);

		} else {
			/* Do nothing. */
		}

		/*
		 * Even if the CN matches, we still walk the certificate looking at the
		 * Fully Qualified Domain Names (FQDNs).
		 */

		count = X509_get_ext_count(crt);
		DIMINUTO_LOG_DEBUG("codex_connection_verify: count ssl=%p crt=%p extensions=%d\n", ssl, crt, count);
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

			DIMINUTO_LOG_DEBUG("codex_connection_verify: nid2sn ssl=%p crt=%p str=\"%s\"\n", ssl, crt, str);

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
				CODEX_WTF;
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

			if (meth->i2v == (X509V3_EXT_I2V)0) {
				CODEX_WTF;
				continue;
			}

			vals = meth->i2v(meth, ptr, (STACK_OF(CONF_VALUE) *)0);
			if (vals == (STACK_OF(CONF_VALUE) *)0) {
				CODEX_WTF;
				continue;
			}

			lim = sk_CONF_VALUE_num(vals);
			DIMINUTO_LOG_DEBUG("codex_connection_verify: num ssl=%p crt=%p stack=%d\n", ssl, crt, lim);
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

				DIMINUTO_LOG_DEBUG("codex_connection_verify: vector ssl=%p crt=%p \"%s\"=\"%s\"\n", ssl, crt, val->name, val->value);

				if (strcmp(val->name, COM_DIAG_CODEX_CONFNAME_DNS) != 0) {
					CODEX_WTF;
					continue;
				}

				/*
				 * If the certificate contains FQDNs coded as DNS values, then
				 * the SSL connection *must* be coming from an IPv4 or IPv6
				 * address that matches an address resolved from a FQDN via
				 * DNS. If an FQDN has both an IPv4 and an IPv6 address, only
				 * ONE of them must match. Here's an example of why this is the
				 * case. Depending on how a host is configured, its IPv4 DNS
				 * address for "localhost" could be 127.0.0.1 and its IPv6 DNS
				 * address can legitimately be either ::ffff:127.0.0.1 or ::1.
				 * The former is an IPv4 address cast in IPv6-compatible form,
				 * and the latter is the standard IPv6 address for "localhost".
				 * Either is valid. If the host on "localhost" connects via
				 * IPv4, its far end IPv4 address will be 127.0.0.1 and its
				 * IPv6 address will be ::ffff:127.0.0.1. If it connects via
				 * IPv6, they may be 0.0.0.0 (because there is no IPv4-
				 * compatible form of its IPv6 address) and ::1.
				 */

				anyfqdn = val->value;

				if (!diminuto_ipc4_is_unspecified(&farend4)) {
					addresses4 = diminuto_ipc4_addresses(anyfqdn);
					if (addresses4 != (diminuto_ipv4_t *)0) {
						for (address4 = addresses4; !diminuto_ipc4_is_unspecified(address4); ++address4) {
							DIMINUTO_LOG_DEBUG("codex_connection_verify: dns4 ssl=%p crt=%p FQDN=\"%s\" IPv4=%s\n", ssl, crt, anyfqdn, diminuto_ipc4_address2string(*address4, debug4, sizeof(debug4)), result);
							if (diminuto_ipc4_compare(address4, &farend4) == 0) {

								/*
								 * The DNS resolution of this FQDN matches the
								 * IPv4 address associated with the far end.
								 */

								result |= (CODEX_VERIFY_IPV4 | CODEX_VERIFY_DNS);
								DIMINUTO_LOG_INFORMATION("codex_connection_verify: dns ssl=%p crt=%p CN=\"%s\" FQDN=\"%s\" IPv4=%s mask=0x%x\n", ssl, crt, anycn, anyfqdn, buffer4, result);
								break;

							}
						}
						free(addresses4);
					}
				}

				if (!diminuto_ipc6_is_unspecified(&farend6)) {
					addresses6 = diminuto_ipc6_addresses(anyfqdn);
					if (addresses6 != (diminuto_ipv6_t *)0) {
						for (address6 = addresses6; !diminuto_ipc6_is_unspecified(address6); ++address6) {
							DIMINUTO_LOG_DEBUG("codex_connection_verify: dns6 ssl=%p crt=%p FQDN=\"%s\" IPv6=%s\n", ssl, crt, anyfqdn, diminuto_ipc6_address2string(*address6, debug6, sizeof(debug6)), result);
							if (diminuto_ipc6_compare(address6, &farend6) == 0) {

								/*
								 * The DNS resolution of this FQDN matches the
								 * IPv6 address associated with the far end.
								 */

								result |= (CODEX_VERIFY_IPV6 | CODEX_VERIFY_DNS);
								DIMINUTO_LOG_INFORMATION("codex_connection_verify: dns ssl=%p crt=%p CN=\"%s\" FQDN=\"%s\" IPv6=%s mask=0x%x\n", ssl, crt, anycn, anyfqdn, buffer6, result);
								break;

							}
						}
						free(addresses6);
					}
				}

				/*
				 * Finally, we check to see if the FQDN matches our expected
				 * value. Note that the matching FQDN doesn't have to resolve
				 * via DNS to the IP address of the far end; merely *some* FQDN
				 * in the certificate has to do so.
				 */

				if (expected == (const char *)0) {
					/* Do nothing. */
				} else  if (strcmp(anyfqdn, expected) != 0) {
					/* Do nothing. */
				} else {

					/*
					 * The FQDN matches our expected value.
					 */

					fqdn = anyfqdn;
					result |= CODEX_VERIFY_FQDN;
					DIMINUTO_LOG_INFORMATION("codex_connection_verify: fqdn ssl=%p crt=%p CN=\"%s\" FQDN=\"%s\" mask=0x%x\n", ssl, crt, anycn, fqdn, result);

				}

			}

		}

	} while (false);

	/*
	 * Now we see what SSL thought of the certificate. If the error is that the
	 * certificate is self-signed, we check the (sadly) global option to accept
	 * self-signed certificates. If it is set, we complain, but go ahead and
	 * change the error code back to OK. But if SSL was happy with the
	 * certificate, but we were not, we change the error code to indicate an
	 * application failure.
	 */

	error = SSL_get_verify_result(ssl);
	switch (error) {

		case X509_V_OK:
			if (result == CODEX_VERIFY_FAILED) {
				error = X509_V_ERR_APPLICATION_VERIFICATION;
			}
			break;

		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
		case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
			if (codex_self_signed_certificates) {
				text = X509_verify_cert_error_string(error);
				if (text == (const char *)0) { text = ""; }
				DIMINUTO_LOG_NOTICE("codex_connection_verify: self ssl=%p CN=\"%s\" error=%d=\"%s\"\n", ssl, anycn, error, text);
				error = X509_V_OK;
			}
			break;

		default:
			break;

	}

	if (error != X509_V_OK) {
		text = X509_verify_cert_error_string(error);
		if (text == (const char *)0) { text = ""; }
		result = CODEX_VERIFY_FAILED;
		DIMINUTO_LOG_WARNING("codex_connection_verify: x509 ssl=%p crt=%p CN=\"%s\" IPv4=%s IPv6=%s error=%d=\"%s\" mask=0x%x\n", ssl, crt, anycn, diminuto_ipc4_address2string(farend4, buffer4, sizeof(buffer4)), diminuto_ipc6_address2string(farend6, buffer6, sizeof(buffer6)), text, result);
	}

	if (crt != (X509 *)0) {
		X509_free(crt);
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

	flags = SSL_get_shutdown(ssl);
	if ((flags & SSL_SENT_SHUTDOWN) == 0) {
		while (true) {
			codex_cerror();
			rc = SSL_shutdown(ssl);
			if (rc > 0) {
				rc = 0;
				break;
			} else if (rc == 0) {
				diminuto_yield();
			} else {
				codex_serror_t serror = CODEX_SERROR_SUCCESS;

				serror = codex_serror("SSL_shutdown", ssl, rc);
				switch (serror) {
				case CODEX_SERROR_NONE:
				case CODEX_SERROR_ZERO:
					rc = 0;
					break;
				default:
					flags = SSL_get_shutdown(ssl);
					if ((flags & SSL_RECEIVED_SHUTDOWN) != 0) {
						rc = 0;
					}
					break;
				}

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
#if defined(COM_DIAG_CODEX_PLATFORM_OPENSSL_1_0_1)

	/*
	 * OpenSSL 1.0.1 doesn't appear to have an API call to determine whether
	 * this is the server or the client side. We cheat.
	 */
	return !!ssl->server;

#else

	/*
	 * Parameter to SSL_is_server() can and should be const.
	 */
	return !!SSL_is_server((codex_connection_t *)ssl);

#endif
}


/*******************************************************************************
 * INPUT/OUTPUT
 ******************************************************************************/

ssize_t codex_connection_read_generic(codex_connection_t * ssl, void * buffer, size_t size, codex_serror_t * serror)
{
	int rc = -1;
	codex_serror_t error = CODEX_SERROR_SUCCESS;
	bool retry = false;

	do {

		retry = false;
		codex_cerror();
		rc = SSL_read(ssl, buffer, size);
		if (rc <= 0) {

			error = codex_serror("SSL_read", ssl, rc);
			switch (error) {
			case CODEX_SERROR_NONE:
				retry = true;
				break;
			case CODEX_SERROR_READ:
				retry = true;
				break;
			case CODEX_SERROR_WRITE:
				rc = -1;
				break;
			case CODEX_SERROR_SYSCALL: /* Likely to be a close(2) without a shutdown(2). */
			case CODEX_SERROR_ZERO:
				rc = 0;
				break;
			default:
				rc = -1;
				break;
			}

			DIMINUTO_LOG_INFORMATION("codex_connection_read_generic: ssl=%p buffer=%p size=%u rc=%d error='%c' retry=%d\n", ssl, buffer, size, rc, error, retry);

		}

		if (retry) {
			diminuto_yield();
		}

	} while (retry);

	if (serror != (codex_serror_t *)0) {
		*serror = error;
	}

	return rc;
}

ssize_t codex_connection_write_generic(codex_connection_t * ssl, const void * buffer, size_t size, codex_serror_t * serror)
{
	int rc = -1;
	codex_serror_t error = CODEX_SERROR_SUCCESS;
	bool retry = false;

	do {

		retry = false;
		codex_cerror();
		rc = SSL_write(ssl, buffer, size);
		if (rc <= 0) {

			error = codex_serror("SSL_write", ssl, rc);
			switch (error) {
			case CODEX_SERROR_NONE:
				retry = true;
				break;
			case CODEX_SERROR_READ:
				rc = -1;
				break;
			case CODEX_SERROR_WRITE:
				retry = true;
				break;
			case CODEX_SERROR_SYSCALL: /* Likely to be a close(2) without a shutdown(2). */
			case CODEX_SERROR_ZERO:
				rc = 0;
				break;
			default:
				rc = -1;
				break;
			}

			DIMINUTO_LOG_INFORMATION("codex_connection_write: ssl=%p buffer=%p size=%u rc=%d error='%c' retry=%d\n", ssl, buffer, size, rc, error, retry);

		}

		if (retry) {
			diminuto_yield();
		}

	} while (retry);

	if (serror != (codex_serror_t *)0) {
		*serror = error;
	}

	return rc;
}

/*******************************************************************************
 * CLIENT
 ******************************************************************************/

codex_context_t * codex_client_context_new(const char * caf, const char * cap, const char * crt, const char * key)
{
	return codex_context_new(codex_client_password_env, caf, cap, crt, key, SSL_VERIFY_PEER, codex_certificate_depth, SSL_OP_ALL | SSL_OP_NO_SSLv2, codex_method, codex_cipher_list, (const char *)0);
}

codex_connection_t * codex_client_connection_new(codex_context_t * ctx, const char * farend)
{
	SSL * ssl = (SSL *)0;
	BIO * bio = (BIO *)0;
	int rc = -1;

	do {
#if defined(COM_DIAG_CODEX_PLATFORM_OPENSSL_1_0_1)
		char * mutable = (char *)0;

		/*
		 * OpenSSL-1.0.1 doesn't declare the string passed into
		 * BIO_new_connect() as const. I haven't examined the implementation,
		 * but it's entirely possible it alters it, since I had to deal with a
		 * similar issue in the diminuto_ipc_endpoint() code.
		 */

		mutable = strdup(farend);
		if (mutable == (char *)0) {
			diminuto_perror("strdup");
			break;
		}

		bio = BIO_new_connect(mutable);
		if (bio == (BIO *)0) {
			codex_perror("BIO_new_connect");
			free(mutable);
			break;
		}

		free(mutable);

#else

		bio = BIO_new_connect(farend);
		if (bio == (BIO *)0) {
			codex_perror("BIO_new_connect");
			break;
		}

#endif

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

		codex_cerror();
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
	return codex_context_new(codex_server_password_env, caf, cap, crt, key, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, codex_certificate_depth, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_SINGLE_DH_USE, codex_method, codex_cipher_list, codex_session_id_context);
}

codex_rendezvous_t * codex_server_rendezvous_new(const char * nearend)
{
	BIO * bio = (BIO *)0;
	int rc = -1;
	int fd = -1;

	do {
#if defined(COM_DIAG_CODEX_PLATFORM_BORINGSSL)
		diminuto_ipc_endpoint_t endpoint;

		rc = diminuto_ipc_endpoint(nearend, &endpoint);
		if (rc < 0) {
			DIMINUTO_LOG_WARNING("diminuto_ipc_endpoint: \"%s\"\n", nearend);
			break;
		}

		if (diminuto_ipc6_is_unspecified(&endpoint.ipv6)) {
			fd = diminuto_ipc4_stream_provider_generic(endpoint.ipv4, endpoint.tcp, (const char *)0, -1);
		} else {
			fd = diminuto_ipc6_stream_provider_generic(endpoint.ipv6, endpoint.tcp, (const char *)0, -1);
		}
		if (fd < 0) {
			break;
		}

		bio = BIO_new_socket(fd, !0);
		if (bio != (BIO *)0) {
			break;
		}
		codex_perror("BIO_new_socket");

#elif defined(COM_DIAG_CODEX_PLATFORM_OPENSSL_1_0_1)
		char * mutable = (char *)0;

		/*
		 * OpenSSL-1.0.1 doesn't declare the string passed into
		 * BIO_new_accept() as const. I haven't examined the implementation,
		 * but it's entirely possible it alters it, since I had to deal with a
		 * similar issue in the diminuto_ipc_endpoint() code.
		 */

		mutable = strdup(nearend);
		if (mutable == (char *)0) {
			diminuto_perror("strdup");
			break;
		}

		bio = BIO_new_accept(mutable);
		if (bio == (BIO *)0) {
			codex_perror("BIO_new_accept");
			free(mutable);
			break;
		}

		rc = BIO_do_accept(bio);
		if (rc > 0) {
			free(mutable);
			break;
		}
		codex_perror("BIO_do_accept");

		free(mutable);

#else

		bio = BIO_new_accept(nearend);
		if (bio == (BIO *)0) {
			codex_perror("BIO_new_accept");
			break;
		}

		rc = BIO_do_accept(bio);
		if (rc > 0) {
			break;
		}
		codex_perror("BIO_do_accept");

#endif

		rc = BIO_free(bio);
		if (rc != 1) {
			codex_perror("BIO_free");
		}

		bio = (BIO *)0;

	} while (false);

	if (bio == (BIO *)0) {
		/* Do nothing: already failed. */
	} else if ((fd = BIO_get_fd(bio, (int *)0)) < 0) {
		/* Do nothing: should never happen; no recovery if it does. */
	} else if ((rc = diminuto_ipc_set_reuseaddress(fd, !0)) < 0) {
		/* Do nothing: function emits error message. */
	} else {
		/* Do nothing: experimental. */
	}

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

#if defined(COM_DIAG_CODEX_PLATFORM_BORINGSSL)

		rc = BIO_get_fd(bio, (int *)0);
		if (rc < 0) {
			errno = EINVAL;
			diminuto_perror("BIO_get_fd");
			break;
		}

		rc = diminuto_ipc4_stream_accept(rc);
		if (rc < 0) {
			break;
		}

		tmp = BIO_new_socket(rc, !0);
		if (tmp == (BIO *)0) {
			codex_perror("BIO_new_socket");
			break;
		}

#else

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

#endif

		ssl = SSL_new(ctx);
		if (ssl == (SSL *)0) {
			codex_perror("SSL_new");
			break;
		}

		SSL_set_bio(ssl, tmp, tmp);

		rc = SSL_accept(ssl);
		if (rc > 0) {
			break;
		}

		(void)codex_serror("SSL_accept", ssl, rc);

		SSL_free(ssl);

		ssl = (SSL *)0;
		tmp = (BIO *)0;

	} while (false);

	if (ssl != (SSL *)0) {
		/* Do nothing. */
	} else if (tmp == (BIO *)0) {
		/* Do nothing. */
	} else {
		rc = BIO_free(tmp);
		if (rc != 1) {
			codex_perror("BIO_free");
		}
	}

	return ssl;
}
