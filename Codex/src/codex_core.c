/* vi: set ts=4 expandtab shiftwidth=4: */
/**
 * @file
 *
 * Copyright 2018-2021 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 *
 * See the README.md for a list of references.
 */

/*******************************************************************************
 * HEADERS
 ******************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
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

#undef CODEX_PARAMETER
#define CODEX_PARAMETER(_NAME_, _TYPE_, _UNDEFINED_, _DEFAULT_) \
	_TYPE_ codex_##_NAME_ = _DEFAULT_;

#include "codex_parameters.h"

/*******************************************************************************
 * STATICS
 ******************************************************************************/

static bool initialized = false;

/*******************************************************************************
 * DEBUGGING
 ******************************************************************************/

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

void codex_perror_f(const char * file, int line, const char * str)
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
		DIMINUTO_LOG_ERROR("%s@%d: \"%s\" errno=%d=\"%s\" index=%d error=0x%08lx=\"%s\"\n", file, line, str, save, strerror(save), ii++, error, buffer);
	}

	if (ii > 0) {
		/* Do nothing. */
	} else if (save == 0) {
		/* Do nothing. */
	} else {
		errno = save;
		diminuto_perror_f(file, line, str);
	}
}

codex_serror_t codex_serror_f(const char * file, int line, const char * str, const SSL * ssl, int rc)
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
			codex_perror_f(file, line, str);
		} else if (save == 0) {
			/* Do nothing. */
		} else if (save == EINTR) {
			/* Do nothing. */
		} else {
			errno = save;
			diminuto_perror_f(file, line, str);
		}
		result = CODEX_SERROR_SYSCALL;
		break;

	case SSL_ERROR_SSL:
		errno = save;
		codex_perror_f(file, line, str);
		result = CODEX_SERROR_SSL;
		break;

	default:
		/* Might happen if libssl or libcrypto are updated. */
		result = CODEX_SERROR_OTHER;
		break;

	}

	if (rc < 0) {
		DIMINUTO_LOG_INFORMATION("%s@%d: \"%s\" ssl=%p rc=%d serror=%d errno=%d error='%c'\n", file, line, str, ssl, rc, error, save, result);
	} else {
		DIMINUTO_LOG_DEBUG("%s@%d: \"%s\" ssl=%p rc=%d serror=%d errno=%d error='%c'\n", file, line, str, ssl, rc, error, save, result);
	}

	errno = save;

	return result;
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

/*******************************************************************************
 * INITIALIZATION
 ******************************************************************************/

int codex_initialize(const char * cnf, const char * dhf, const char * crl)
{
	static pthread_mutex_t mutex_init = PTHREAD_MUTEX_INITIALIZER;
	int initrc = 0;
	int revokedrc = 0;
	int diffiehellmanrc = 0;

	DIMINUTO_CRITICAL_SECTION_BEGIN(&mutex_init);

		if (!initialized) {

			initrc = SSL_library_init();
			if (initrc != 1) {

				codex_perror("SSL_library_init");
				initrc = -1;

			} else {

				DIMINUTO_LOG_INFORMATION("codex_initialize: init cnf=\"%s\"\n", (cnf != (const char *)0) ? cnf : "");

				SSL_load_error_strings();
				OPENSSL_config(cnf);
				initialized = true;
				initrc = 0;

			}

		}

	DIMINUTO_CRITICAL_SECTION_END;

	if (dhf != (const char *)0) {

		DIMINUTO_LOG_INFORMATION("codex_initialize: init dhf=\"%s\"\n", dhf);
		diffiehellmanrc = codex_diffiehellman_import(dhf);

	}

	if (crl != (const char *)0) {

		DIMINUTO_LOG_INFORMATION("codex_initialize: init crl=\"%s\"\n", crl);
		revokedrc = codex_revoked_import(crl);

	}

	return ((initrc >= 0) && (diffiehellmanrc >= 0) && (revokedrc >= 0)) ? 0 : -1;
}

/*******************************************************************************
 * GETTORS/SETTORS
 ******************************************************************************/

#undef CODEX_PARAMETER
#define CODEX_PARAMETER(_NAME_, _TYPE_, _UNDEFINED_, _DEFAULT_) \
	_TYPE_ codex_set_##_NAME_(_TYPE_ now) \
	{ \
		_TYPE_ was = (_TYPE_)_UNDEFINED_; \
		static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER; \
		DIMINUTO_CRITICAL_SECTION_BEGIN(&mutex); \
			was = codex_##_NAME_; \
			if (now != (_TYPE_)_UNDEFINED_) { codex_##_NAME_ = now; } \
		DIMINUTO_CRITICAL_SECTION_END; \
		return was; \
	}

#include "codex_parameters.h"

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

		DIMINUTO_LOG_INFORMATION("codex_context_new: ctx caf=\"%s\"\n", (caf != (const char *)0) ? caf : "");
		DIMINUTO_LOG_INFORMATION("codex_context_new: ctx cap=\"%s\"\n", (cap != (const char *)0) ? cap : "");

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

		DIMINUTO_LOG_INFORMATION("codex_context_new: ctx env=\"%s\"\n", (env != (const char *)0) ? env : "");

		password = secure_getenv(env);
		if (password != (char *)0) {
			SSL_CTX_set_default_passwd_cb(ctx, codex_password_callback);
			SSL_CTX_set_default_passwd_cb_userdata(ctx, password);
		}

		DIMINUTO_LOG_INFORMATION("codex_context_new: ctx crt=\"%s\"\n", (crt != (const char *)0) ? crt : "");

		rc = SSL_CTX_use_certificate_chain_file(ctx, crt);
		if (rc != 1) {
			codex_perror("SSL_CTX_use_certificate_chain_file");
			break;
		}

		DIMINUTO_LOG_INFORMATION("codex_context_new: ctx key=\"%s\"\n", (key != (const char *)0) ? key : "");

		rc = SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM);
		if (rc != 1) {
			codex_perror("SSL_CTX_use_PrivateKey_file");
			break;
		}

		(void)SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

		/*
		 * N.B. *NOT* SSL_CTX_set_cert_verify_callback()!
		 */

		DIMINUTO_LOG_INFORMATION("codex_context_new: ctx flags=0x%x\n", flags);

		SSL_CTX_set_verify(ctx, flags, codex_verification_callback);

		DIMINUTO_LOG_INFORMATION("codex_context_new: ctx depth=%d\n", depth);

		SSL_CTX_set_verify_depth(ctx, depth);

		DIMINUTO_LOG_INFORMATION("codex_context_new: ctx options=0x%x\n", options);

		(void)SSL_CTX_set_options(ctx, options);

		SSL_CTX_set_tmp_dh_callback(ctx, codex_diffiehellman_callback);

		DIMINUTO_LOG_INFORMATION("codex_context_new: ctx list=\"%s\"\n", (list != (const char *)0) ? list : "");

		rc = SSL_CTX_set_cipher_list(ctx, list);
		if (rc != 1) {
			codex_perror("SSL_CTX_set_cipher_list");
			break;
		}

		DIMINUTO_LOG_INFORMATION("codex_context_new: ctx context=\"%s\"\n", (context != (const char *)0) ? context : "");

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

			DIMINUTO_LOG_INFORMATION("codex_connection_read_generic: ssl=%p buffer=%p size=%zu rc=%d error='%c' retry=%d\n", ssl, buffer, size, rc, error, retry);

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

			DIMINUTO_LOG_INFORMATION("codex_connection_write: ssl=%p buffer=%p size=%zu rc=%d error='%c' retry=%d\n", ssl, buffer, size, rc, error, retry);

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
#if defined(COM_DIAG_CODEX_PLATFORM_OPENSSL_1_0_1) || defined(COM_DIAG_CODEX_PLATFORM_OPENSSL_1_1_0)
		char * mutable = (char *)0;

		/*
		 * Some OpenSSL flavors don't declare the string passed into
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
		diminuto_ipc_endpoint_t endpoint = { 0 };

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

#elif defined(COM_DIAG_CODEX_PLATFORM_OPENSSL_1_0_1) || defined(COM_DIAG_CODEX_PLATFORM_OPENSSL_1_1_0)
		char * mutable = (char *)0;

		/*
		 * Some OpenSSL flavors don't declare the string passed into
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
