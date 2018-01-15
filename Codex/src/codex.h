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
 * only for unit testing.
 */

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/objects.h>
#include <openssl/conf.h>

/*******************************************************************************
 * GENERATORS
 ******************************************************************************/

#define COM_DIAG_CODEX_SERVER_PASSWORD_ENV "COM_DIAG_CODEX_SERVER_PASSWORD"

#define COM_DIAG_CODEX_CLIENT_PASSWORD_ENV "COM_DIAG_CODEX_CLIENT_PASSWORD"

/**
 * Cipher suite selection control string.
 *
 * ALL:			All cipher suites;<BR>
 * !aNULL:		except those not offering authentication;<BR>
 * !ADH:		except Anonymous Diffie Hellman suites;<BR>
 * !LOW:		except Low Strength suites;<BR>
 * !EXP:		except Export Strength suites;<BR>
 * !MD5:		except Message Digest 5 suites;<BR>
 * @STRENGTH:	and select in order of highest strength to lowest.<BR>
 *
 * Try "openssl ciphers -v" followed by the control string below (probably in
 * single quotes) to see a list of possible cipher suites.
 *
 * See ciphers(1).
 */
#define COM_DIAG_CODEX_CIPHER_LIST "ALL:!aNULL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"

#define COM_DIAG_CODEX_SHORTNAME_SUBJECTALTNAME "subjectAltName"

#define COM_DIAG_CODEX_CONFNAME_DNS "DNS"

/*******************************************************************************
 * GLOBALS
 ******************************************************************************/

extern DH * codex_dh256;

extern DH * codex_dh512;

extern DH * codex_dh1024;

extern DH * codex_dh2048;

extern DH * codex_dh4096;

/*******************************************************************************
 * CALLBACKS
 ******************************************************************************/

extern int codex_password_callback(char * buffer, int size, int writing, void * that);

extern int codex_verification_callback(int ok, X509_STORE_CTX * ctx);

extern DH * codex_parameters_callback(SSL * ssl, int exp, int length);

#endif
