/* vi: set ts=4 expandtab shiftwidth=4: */
#ifndef _H_COM_DIAG_CODEX_CODEX_PRIVATE_
#define _H_COM_DIAG_CODEX_CODEX_PRIVATE_

/**
 * @file
 *
 * Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock <coverclock@diag.com><BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 *
 * These elements are not part of the public API. They are typically exposed
 * only for unit testing, for supporting separate translation modules in the
 * underlying implementation, or for supporting user-defined translations
 * modules that are built as part of this library for purposes of customization.
 */

/*******************************************************************************
 * HEADERS
 ******************************************************************************/

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/objects.h>
#include <openssl/conf.h>
#include <openssl/asn1.h>

/*******************************************************************************
 * PARAMETERS
 ******************************************************************************/

#if !defined(COM_DIAG_CODEX_METHOD)
#	warning COM_DIAG_CODEX_METHOD undefined!
#	define COM_DIAG_CODEX_METHOD ((SSL_METHOD *)0)
#endif

#if !defined(COM_DIAG_CODEX_CIPHER_LIST)
#	warning COM_DIAG_CODEX_CIPER_LIST undefined!
#	define COM_DIAG_CODEX_CIPHER_LIST ""
#endif

#if !defined(COM_DIAG_CODEX_SESSION_ID_CONTEXT)
#	warning COM_DIAG_CODEX_SESSION_ID_CONTEXT undefined!
#	define COM_DIAG_CODEX_SESSION_ID_CONTEXT ""
#endif

#if !defined(COM_DIAG_CODEX_CERTIFICATE_DEPTH)
#	warning COM_DIAG_CODEX_CERTIFICATE_DEPTH undefined!
#	define COM_DIAG_CODEX_CERTIFICATE_DEPTH 0
#endif

#if !defined(COM_DIAG_CODEX_SERVER_PASSWORD_ENV)
#	warning COM_DIAG_CODEX_SERVER_PASSWORD_ENV undefined!
#	define COM_DIAG_CODEX_SERVER_PASSWORD_ENV ""
#endif

#if !defined(COM_DIAG_CODEX_CLIENT_PASSWORD_ENV)
#	warning COM_DIAG_CODEX_CLIENT_PASSWORD_ENV undefined!
#	define COM_DIAG_CODEX_CLIENT_PASSWORD_ENV ""
#endif

/*******************************************************************************
 * GENERATORS
 ******************************************************************************/

#define COM_DIAG_CODEX_SHORTNAME_SUBJECTALTNAME "subjectAltName"

#define COM_DIAG_CODEX_CONFNAME_DNS "DNS"

/*******************************************************************************
 * TYPES
 ******************************************************************************/

typedef const SSL_METHOD * (*codex_method_t)(void);

/*******************************************************************************
 * GLOBALS
 ******************************************************************************/

extern DH * codex_dh;

/*******************************************************************************
 * DEBUGGING
 ******************************************************************************/

/**
 * Log at NOTICE a line containing the file name, line number, connection
 * pointer, first peeked error value, return code, SSL error value, and
 * errno (as errnumber).
 * @param file names the translation unit.
 * @param line is the line number.
 * @param ssl points to the connection.
 * @param rc is the return code.
 * @param errnumber is a copy of errno.
 */
extern void codex_wtf(const char * file, int line, const codex_connection_t * ssl, int rc, int errnumber);

/*******************************************************************************
 * GETTORS/SETTORS
 ******************************************************************************/

extern codex_method_t codex_set_method(codex_method_t now);

extern const char * codex_set_client_password_env(const char * now);

extern const char * codex_set_server_password_env(const char * now);

extern const char * codex_set_cipher_list(const char * now);

extern const char * codex_set_session_id_context(const char * now);

extern int codex_set_certificate_depth(int now);

/*******************************************************************************
 * CALLBACKS
 ******************************************************************************/

extern int codex_password_callback(char * buffer, int size, int writing, void * that);

extern int codex_verification_callback(int ok, X509_STORE_CTX * ctx);

extern DH * codex_parameters_callback(SSL * ssl, int exp, int length);

/*******************************************************************************
 * HELPERS
 ******************************************************************************/

extern DH * codex_parameters_import(const char * dhf);

#endif
