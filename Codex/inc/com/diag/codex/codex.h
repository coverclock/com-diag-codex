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

/*******************************************************************************
 * HEADERS
 ******************************************************************************/

#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

/*******************************************************************************
 * TYPES
 ******************************************************************************/

typedef SSL_CTX codex_context_t;

typedef BIO codex_rendezvous_t;

typedef SSL codex_connection_t;

/*******************************************************************************
 * GENERATORS
 ******************************************************************************/

static const int CODEX_CONTEXT_DEPTH = 9;

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

extern int codex_serror(const char * str, const codex_connection_t * ssl, int rc);

/*******************************************************************************
 * INITIALIZATION
 ******************************************************************************/

extern int codex_initialize(void);

extern int codex_parameters(const char * dh256f, const char * dh512f, const char * dh1024f, const char * dh2048f, const char * dh4096f);

/*******************************************************************************
 * CONTEXT
 ******************************************************************************/

extern codex_context_t * codex_context_new(const char * env, const char * caf, const char * cap, const char * crt, const char * pem, int flags, int depth, int options);

extern codex_context_t * codex_context_free(codex_context_t * ctx);

/*******************************************************************************
 * CONNECTION
 ******************************************************************************/

extern int codex_connection_verify(codex_connection_t * ssl, const char * expected);

extern bool codex_connection_closed(codex_connection_t * ssl);

extern int codex_connection_close(codex_connection_t * ssl);

extern codex_connection_t * codex_connection_free(codex_connection_t * ssl);

/*******************************************************************************
 * INPUT/OUTPUT
 ******************************************************************************/

extern int codex_connection_read(codex_connection_t * ssl, void * buffer, int size);

extern int codex_connection_write(codex_connection_t * ssl, const void * buffer, int size);

/*******************************************************************************
 * MULTIPLEXING
 ******************************************************************************/

extern int codex_rendezvous_descriptor(codex_rendezvous_t * acc);

extern int codex_connection_descriptor(codex_connection_t * ssl);

/*******************************************************************************
 * CLIENT
 ******************************************************************************/

extern codex_context_t * codex_client_context_new(const char * caf, const char * cap, const char * crt, const char * key);

extern codex_connection_t * codex_client_connection_new(codex_context_t * ctx, const char * farend);

/*******************************************************************************
 * SERVER
 ******************************************************************************/

extern codex_context_t * codex_server_context_new(const char * caf, const char * cap, const char * crt, const char * key);

extern codex_rendezvous_t * codex_server_rendezvous_new(const char * nearend);

extern codex_rendezvous_t * codex_server_rendezvous_free(codex_rendezvous_t * bio);

extern codex_connection_t * codex_server_connection_new(codex_context_t * ctx, codex_rendezvous_t * bio);

#endif
