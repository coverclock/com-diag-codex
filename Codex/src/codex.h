/* vi: set ts=4 expandtab shiftwidth=4: */
#ifndef _H_COM_DIAG_CODEX_CODEX_PRIVATE_
#define _H_COM_DIAG_CODEX_CODEX_PRIVATE_

/**
 * @file
 *
 * Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
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

#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/objects.h>
#include <openssl/conf.h>
#include <openssl/asn1.h>
#include <openssl/err.h>

/*******************************************************************************
 * PARAMETERS
 ******************************************************************************/

/*
 * This is mostly done to keep the IDE (Eclipse in my case) happy because
 * nominally these preprocessor symbols are defined by the makefile at build-
 * time.
 */

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

#if !defined(COM_DIAG_CODEX_SELF_SIGNED_CERTIFICATES)
#	warning COM_DIAG_CODEX_SELF_SIGNED_CERTIFICATES undefined!
#	define COM_DIAG_CODEX_SELF_SIGNED_CERTIFICATES 0
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

/**
 * @COM_DIAG_CODEX_SHORTNAME_SUBJECTALTNAME defines a short name we expect
 * to find in the certificate.
 */
#define COM_DIAG_CODEX_SHORTNAME_SUBJECTALTNAME "subjectAltName"

/**
 * @COM_DIAG_CODEX_CONFNAME_DNS defines a configuration name we expect to
 * find in the certificate.
 */
#define COM_DIAG_CODEX_CONFNAME_DNS "DNS"

/*******************************************************************************
 * TYPES
 ******************************************************************************/

/*******************************************************************************
 * GLOBALS
 ******************************************************************************/

/**
 * Points to the one and only Diffie Hellman parameter structure.
 */
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
 * ERRORS
 ******************************************************************************/

/**
 * Clear the error queue as per SSL_get_error(3SSL).
 */
static inline void codex_cerror(void)
{
	while (ERR_get_error() != 0) { /* Do nothing. */ }
}

/*******************************************************************************
 * GETTORS/SETTORS
 ******************************************************************************/

/**
 * Get the existing method and optionally set a new one used for subsequent
 * calls to codex_context_new().
 * @param now if not NULL is the new value.
 * @return the prior or current value.
 */
extern codex_method_t codex_set_method(codex_method_t now);

/**
 * Get the existing client password environmental variable name and optionally
 * set a new one used for subsequent calls to codex_context_new().
 * @param now if not NULL is the new value.
 * @return the prior or current value.
 */
extern const char * codex_set_client_password_env(const char * now);

/**
 * Get the existing server password environmental variable name and optionally
 * set a new one used for subsequent calls to codex_context_new().
 * @param now if not NULL is the new value.
 * @return the prior or current value.
 */
extern const char * codex_set_server_password_env(const char * now);

/**
 * Get the existing cipher list and optionally set a new one used for subsequent
 * calls to codex_context_new().
 * @param now if not NULL is the new value.
 * @return the prior or current value.
 */
extern const char * codex_set_cipher_list(const char * now);

/**
 * Get the existing session identifier context and optionally set a new one used
 * for subsequent calls to codex_context_new().
 * @param now if not NULL is the new value.
 * @return the prior or current value.
 */
extern const char * codex_set_session_id_context(const char * now);

/**
 * Get the existing maximum certificate depth and optionally set a new one used
 * for subsequent calls to codex_context_new().
 * @param now if not -1 is the new value.
 * @return the prior or current value.
 */
extern int codex_set_certificate_depth(int now);

/**
 * Get the existing self-signed certificate setting and optionally set a new
 * one used for subsequent calls to codex_verification_callback().
 * @param now if not -1 is the new boolean value.
 * @return the prior or current value.
 */
extern int codex_set_self_signed_certificates(int now);

/*******************************************************************************
 * CALLBACKS
 ******************************************************************************/

/**
 * This call back allows the library to provide a password for its own
 * certificate files.
 * @param buffer is where to put the password.
 * @param size is the size of the buffer in bytes.
 * @param writing is true if the password is for writing, otherwise for reading.
 * @param that points to a context provided by the Codex library.
 * @return the size of the password string.
 */
extern int codex_password_callback(char * buffer, int size, int writing, void * that);

/**
 * This call back allows the application to further verify the certificate.
 * @param ok indicates whether OpenSSL verified the certificate.
 * @param ctx points to the X.509 certificate.
 * @return a value indicating whether the application verified the certificate.
 */
extern int codex_verification_callback(int ok, X509_STORE_CTX * ctx);

/**
 * This call back selects the DH parameter structure to use. It always returns
 * the imported structure (see below) regardless of the requested key length.
 * @param ssl points to the connection.
 * @param exp is not used.
 * @param length is the requested key length which is ignored.
 * @return a pointer to the DH parameter structure.
 */
extern DH * codex_parameters_callback(SSL * ssl, int exp, int length);

/*******************************************************************************
 * HELPERS
 ******************************************************************************/

/**
 * Import Diffie Hellman parameters from the specified file.
 * @param dhf is the name of the file. Note: the DH parameter structure
 * might be dynamically allocated in the OpenSSL implementation; I don't find
 * an API call to release it.
 * @return a pointer to a new DH parameter structure.
 */
extern DH * codex_parameters_import(const char * dhf);

#endif
