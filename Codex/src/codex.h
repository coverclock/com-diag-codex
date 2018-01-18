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
 * only for unit testing or for supporting separate translation modules in the
 * underlying implementation.
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
 * GENERATORS
 ******************************************************************************/

#define COM_DIAG_CODEX_SERVER_PASSWORD_ENV "COM_DIAG_CODEX_SERVER_PASSWORD"

#define COM_DIAG_CODEX_CLIENT_PASSWORD_ENV "COM_DIAG_CODEX_CLIENT_PASSWORD"

#define COM_DIAG_CODEX_SHORTNAME_SUBJECTALTNAME "subjectAltName"

#define COM_DIAG_CODEX_CONFNAME_DNS "DNS"

#if !defined(COM_DIAG_CODEX_CIPHER_LIST)
#	define COM_DIAG_CODEX_CIPHER_LIST ""
#	warning COM_DIAG_CODEX_CIPER_LIST undefined!
#endif

#if !defined(COM_DIAG_CODEX_CERTIFICATE_DEPTH)
#	define COM_DIAG_CODEX_CERTIFICATE_DEPTH 0
#	warning COM_DIAG_CODEX_CERTIFICATE_DEPTH undefined!
#endif

/*******************************************************************************
 * GLOBALS
 ******************************************************************************/

extern DH * codex_dh;

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
