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

#include <openssl/ssl.h>

/*******************************************************************************
 * CONSTANTS
 ******************************************************************************/

extern const char * const codex_server_password_env;

extern const char * const codex_client_password_env;

/*******************************************************************************
 * COMMON
 ******************************************************************************/

extern void codex_initialize(void);

extern void codex_perror(const char * str);

extern SSL_CTX * codex_context_new(const char * env, const char * caf, const char * crt, const char * pem, int flags, int depth);

extern SSL_CTX * codex_context_free(SSL_CTX * ctx);

/*******************************************************************************
 * CLIENT
 ******************************************************************************/

static inline SSL_CTX * codex_client_new(const char * caf, const char * crt, const char * key)
{
	return codex_context_new(codex_client_password_env, caf, crt, key, SSL_VERIFY_PEER, 0);
}

static inline SSL_CTX * codex_client_free(SSL_CTX * ctx)
{
	return codex_context_free(ctx);
}

/*******************************************************************************
 * SERVER
 ******************************************************************************/


static inline SSL_CTX * codex_server_new(const char * caf, const char * crt, const char * key)
{
	return codex_context_new(codex_server_password_env, caf, crt, key, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
}

static inline SSL_CTX * codex_server_free(SSL_CTX * ctx)
{
	return codex_context_free(ctx);
}

#endif
