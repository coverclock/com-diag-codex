/* vi: set ts=4 expandtab shiftwidth=4: */
#ifndef _H_COM_DIAG_CODEX_CODEX_PRIVATE_
#define _H_COM_DIAG_CODEX_CODEX_PRIVATE_

/**
 * @file
 *
 * Copyright 2018-2022 Digital Aggregates Corporation, Colorado, USA<BR>
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

#include <pthread.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/objects.h>
#include <openssl/conf.h>
#include <openssl/err.h>

/*******************************************************************************
 * INITIALIZATON
 ******************************************************************************/

/**
 * Initializes the OpenSSL stack, loads the Diffie-Hellman (DH) parameter
 * file used for key exchange of the symmetric keys for data stream encryption,
 * and optionally loads the text file containing an ASCII list of serial
 * numbers identifying revoked certificates.
 * Only needs to be called once per application.
 * @param cfg names the OpenSSL configuration file or null if default.
 * @param app names the OpenSSL application or null if default.
 * @param flags contains the OpenSSL configuration flags or 0 if default.
 * @param dhf names the DH parameter file.
 * @param crl names the certificate revocation list file or null if none.
 * @return 0 if successful, <0 otherwise.
 */
int codex_initialize_f(const CONF * cfg, const char * app, int flags, const char * dhf, const char * crl);

/*******************************************************************************
 * PARAMETERS
 ******************************************************************************/

/*
 * This is mostly done to keep the IDE (Eclipse in my case) happy because
 * nominally these preprocessor symbols are defined by the Makefile at build-
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
 * @def COM_DIAG_CODEX_SHORTNAME_SUBJECTALTNAME
 * Defines a short name we expect to find in the certificate.
 */
#define COM_DIAG_CODEX_SHORTNAME_SUBJECTALTNAME "subjectAltName"

/**
 * @def COM_DIAG_CODEX_CONFNAME_DNS
 * Defines a configuration name we expect to find in the certificate.
 */
#define COM_DIAG_CODEX_CONFNAME_DNS "DNS"

/*******************************************************************************
 * GLOBALS
 ******************************************************************************/

#undef CODEX_PARAMETER
#define CODEX_PARAMETER(_NAME_, _TYPE_, _UNDEFINED_, _DEFAULT_) \
	extern _TYPE_ codex_##_NAME_;

#include "codex_parameters.h"

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

#undef CODEX_PARAMETER
#define CODEX_PARAMETER(_NAME_, _TYPE_, _UNDEFINED_, _DEFAULT_) \
	extern _TYPE_ codex_set_##_NAME_(_TYPE_ now);

#include "codex_parameters.h"

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
 * The OpenSSL validator calls this function against every certificate in the
 * chain. Codex uses this to permit self-signed certificates if they have been
 * enabled (they are disabled by default).
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
extern DH * codex_diffiehellman_callback(SSL * ssl, int exp, int length);

/*******************************************************************************
 * DIFFIE-HELLMAN
 ******************************************************************************/

/**
 * Import a pre-generated collection of Diffie-Hellman parameters to use in
 * symmetric encryption.
 * @param dhf points to the file name.
 * @return 0 for success or <0 if error.
 */
extern int codex_diffiehellman_import(const char * dhf);

/*******************************************************************************
 * CERTIFICATION REVOCATION LIST
 ******************************************************************************/

/**
 * Convert a certificate serial number in ASN1 integer form into a printable
 * string.
 * @param srl points to the serial number in ASN1 integer form.
 * @param srn points to the buffer in which the character string is placed.
 * @param size is the number of bytes in the buffer.
 * @return a pointer to the character string or NULL if an error occurred.
 */
extern char * codex_serialnumber_to_string(ASN1_INTEGER * srl, char * srn, size_t size);

/**
 * Return true if a serial number is revoked, false otherwise.
 * @param srn points to the serial number in character string form.
 * @return true if revoked, false otherwise.
 */
extern bool codex_serialnumber_is_revoked(const char * srn);

/**
 * Import an ASCII hexadecimal list of revoked serial numbers from a FILE
 * stream.
 * @param fp points to the FILE stream.
 * @return the number of non-unique serial numbers imported or <0 if error.
 */
extern int codex_revoked_import_stream(FILE * fp);

/**
 * Import an ASCII hexadecimal list of revoked serial numbers from a file.
 * @param crl points to the file name.
 * @return the number of non-unique serial numbers imported or <0 if error.
 */
extern int codex_revoked_import(const char * crl);

/**
 * Export an ASCII hexadecimal list of revoked serial numbers to a file stream.
 * @param fp points to the FILE stream.
 * @return the number of serial numbers exported or <0 if error.
 */
extern int codex_revoked_export_stream(FILE *fp);

/**
 * Export an ASCII hexadecimal list of revoked serial numbers to a file.
 * @param crl points to the file name.
 * @return the number of serial numbers exported or <0 if error.
 */
extern int codex_revoked_export(const char * crl);

/**
 * Free all memory associated with the global certificate revocation list cache
 * of ASCII hexadecimal serial numbers, which are stored in a red-black tree.
 * @return the number of freed serial number entries or <0 if error.
 */
extern int codex_revoked_free(void);

#endif
