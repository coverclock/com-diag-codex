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

#define COM_DIAG_CODEX_PASSWORD_SERVER_KEY "COM_DIAG_CODEX_PASSWORD_SERVER"

#define COM_DIAG_CODEX_PASSWORD_CLIENT_KEY "COM_DIAG_CODEX_PASSWORD_CLIENT"

extern const char * const codex_password_server_key;

extern const char * const codex_password_client_key;

/*******************************************************************************
 * COMMON
 ******************************************************************************/

extern void codex_initialize(void);

extern void codex_perror(const char * str);

extern SSL_CTX * codex_context_free(SSL_CTX * ctx);

/*******************************************************************************
 * CLIENT
 ******************************************************************************/

extern SSL_CTX * codex_client_new(const char * crt, const char * pem);

static inline SSL_CTX * codex_client_free(SSL_CTX * ctx) { return codex_context_free(ctx); }

/*******************************************************************************
 * SERVER
 ******************************************************************************/

extern SSL_CTX * codex_server_new(const char * crt, const char * pem);

static inline SSL_CTX * codex_server_free(SSL_CTX * ctx) { return codex_context_free(ctx); }

#endif
