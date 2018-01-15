/* vi: set ts=4 expandtab shiftwidth=4: */
#ifndef _H_COM_DIAG_CODEX_CODEX_
#define _H_COM_DIAG_CODEX_CODEX_

/**
 * @file
 *
 * Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock <coverclock@diag.com><BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 */

#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

/*******************************************************************************
 * CONSTANTS
 ******************************************************************************/

extern const char * const codex_server_password_env;

extern const char * const codex_client_password_env;

extern const char * const codex_cipher_list;

/*******************************************************************************
 * HELPERS
 ******************************************************************************/

extern void codex_perror(const char * str);

extern int codex_serror(const char * str, const SSL * ssl, int rc);

/*******************************************************************************
 * INITIALIZATION
 ******************************************************************************/

extern int codex_initialize(void);

extern int codex_parameters(const char * dh256f, const char * dh512f, const char * dh1024f, const char * dh2048f, const char * dh4096f);

/*******************************************************************************
 * CONTEXTS
 ******************************************************************************/

extern SSL_CTX * codex_context_new(const char * env, const char * caf, const char * crt, const char * pem, int flags, int depth, int options);

extern SSL_CTX * codex_context_free(SSL_CTX * ctx);

/*******************************************************************************
 * CONNECTIONS
 ******************************************************************************/

extern int codex_connection_verify(SSL * ssl, const char * expected);

extern bool codex_connection_closed(SSL * ssl);

extern int codex_connection_close(SSL * ssl);

extern SSL * codex_connection_free(SSL * ssl);

/*******************************************************************************
 * MULTIPLEXING
 ******************************************************************************/

extern int codex_rendezvous_descriptor(BIO * acc)
{
	int fd;
	BIO_get_fd(acc, &fd);
	return fd;
}

extern int codex_connection_descriptor(SSL * ssl)
{
	return SSL_get_fd(ssl);
}

/*******************************************************************************
 * INPUT/OUTPUT
 ******************************************************************************/

extern int codex_connection_read(SSL * ssl, void * buffer, int size);

extern int codex_connection_write(SSL * ssl, const void * buffer, int size);

/*******************************************************************************
 * CLIENT
 ******************************************************************************/

static inline SSL_CTX * codex_client_context_new(const char * caf, const char * crt, const char * key)
{
	return codex_context_new(codex_client_password_env, caf, crt, key, SSL_VERIFY_PEER, 0, SSL_OP_ALL | SSL_OP_NO_SSLv2);
}

extern SSL * codex_client_connection_new(SSL_CTX * ctx, const char * farend);

/*******************************************************************************
 * SERVER
 ******************************************************************************/

static inline SSL_CTX * codex_server_context_new(const char * caf, const char * crt, const char * key)
{
	return codex_context_new(codex_server_password_env, caf, crt, key, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_SINGLE_DH_USE);
}

extern BIO * codex_server_rendezvous_new(const char * nearend);

extern BIO * codex_server_rendezvous_free(BIO * bio);

extern SSL * codex_server_connection_new(SSL_CTX * ctx, BIO * bio);

#endif
