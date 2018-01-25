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

/**
 * Type of object that contains the context for an OpenSSL server or client.
 */
typedef SSL_CTX codex_context_t;

/**
 * Type of object that defines the rendezvous to accept OpenSSL connections.
 */
typedef BIO codex_rendezvous_t;

/**
 * Type of object that describes an individualOpenSSL socket connection.
 */
typedef SSL codex_connection_t;

/**
 * These are the values the integer returned by codex_serror() may assume.
 * (One typical recoverable error is an EINTR from a system call that was
 * interrupted by a signal.)
 */
typedef enum CodexSerror {
	CODEX_SERROR_UNRECOVERABLE	= -1,		/* Connection had unrecoverable error. */
	CODEX_SERROR_CLOSED			= 0,		/* Connection closed. */
	CODEX_SERROR_RECOVERABLE	= 1,		/* Connection had recoverable error (retry). */
} codex_serror_t;

/**
 * These are the values the integer returned by codex_connection_verify() may
 * assume.
 */
typedef enum CodexConnectionVerify {
	CODEX_CONNECTION_VERIFY_FAILED	= -1,	/* Verification failed. */
	CODEX_CONNECTION_VERIFY_PASSED	= 0,	/* Verification passed with nothing expected. */
	CODEX_CONNECTION_VERIFY_CN		= 1,	/* Verification passed matching CN. */
	CODEX_CONNECTION_VERIFY_FQDN	= 2,	/* Verification passed matching FQDN. */
} codex_connection_verify_t;

/*******************************************************************************
 * CONSTANTS
 ******************************************************************************/

/**
 * Names the environmental variable whose value is the server password.
 */
extern const char * const codex_server_password_env;

/**
 * Names the environmental variable whose value is the client password.
 */
extern const char * const codex_client_password_env;

/**
 * Declares the name of the secure socket layer method.
 */
extern const char * const codex_method;

/**
 * Declares the available and usable cipher algorithms.
 */
extern const char * const codex_cipher_list;

/**
 * Declares the maximum depth to which certificates may be chained.
 */
extern const int codex_certificate_depth;

/**
 * Declares the minimum number of bytes which may trigger a renegotiation.
 */
extern const long codex_renegotiate_bytes;

/**
 * Declares the minimum number of seconds which may trigger a renegotiation.
 */
extern const long codex_renegotiate_seconds;

/*******************************************************************************
 * ERRORS
 ******************************************************************************/

/**
 * Logs the error messages found on the OpenSSL error queue.
 * @param str points to the prefix string printed before each message.
 */
extern void codex_perror(const char * str);

/**
 * Logs the error message associated with a particular connection and return
 * code.
 * @param str points to the prefix string printed before each message.
 * @param ssl points to the connection.
 * @param rc is the return code returned by the failing function.
 * @return 0 for closed, >0 for recoverable, <0 for unrecoverable.
 */
extern int codex_serror(const char * str, const codex_connection_t * ssl, int rc);

/*******************************************************************************
 * INITIALIZATION
 ******************************************************************************/

/**
 * Initializes the OpenSSL stack. Only needs to be called once per process.
 * @return 0 if successful, <0 otherwise.
 */
extern int codex_initialize(void);

/**
 * Loads a Diffie Hellman parameter file. I strongly suggest using no parameter
 * file for a key length less than 2048 (or whatever the Codex Makefile
 * currently generates for unit testing).
 * @param dhf names the DH parameter file.
 * @return 0 if successful, <0 otherwise.
 */
extern int codex_parameters(const char * dhf);

/*******************************************************************************
 * CONTEXT
 ******************************************************************************/

/**
 * Allocate a new OpenSSL context.
 * @param env names the environmental variable containing the password.
 * @param caf names the certificate file or NULL if none.
 * @param cap names the certificate path or NULL if none.
 * @param crt names the certificate to use.
 * @param key names the private key to use.
 * @param flags defines the peer verification options.
 * @param depth defines the maximum certificate depth (9 works well).
 * @param options defines the SSL protocol options.
 * @return a pointer to the new context if successful, NULL otherwise.
 */
extern codex_context_t * codex_context_new(const char * env, const char * caf, const char * cap, const char * crt, const char * key, int flags, int depth, int options);

/**
 * Free an existing OpenSSL context.
 * @param ctx points to the context.
 * @return NULL if successful, the original pointer otherwise.
 */
extern codex_context_t * codex_context_free(codex_context_t * ctx);

/*******************************************************************************
 * CONNECTION
 ******************************************************************************/

/**
 * Walk the peer X309 certificate and verify that it came from the expected host
 * by comparing the provided string against the FQDN or the CN, and furthermore
 * examine the OpenSSL verification status.
 * @param ssl points to the connection.
 * @param expected names the expected host FQDN or CN or NULL if none.
 * @return <0 if unverified, 2 if FQDN matched, 1 if CN matched, 0 otherwise.
 */
extern int codex_connection_verify(codex_connection_t * ssl, const char * expected);

/**
 * Return true if the connection has been closed by the far end.
 * @param ssl points to the connection.
 * @return true if connection has been closed by the far end, false otherwise.
 */
extern bool codex_connection_closed(codex_connection_t * ssl);

/**
 * Close a connection by sending a shutdown requested to the far end.
 * @param ssl points to the connection.
 * @return 0 if successful, <0 otherwise.
 */
extern int codex_connection_close(codex_connection_t * ssl);

/**
 * Free a connection.
 * @param ssl points to the connection.
 * @return NULL if successful, the original pointer otherwise.
 */
extern codex_connection_t * codex_connection_free(codex_connection_t * ssl);

/*******************************************************************************
 * INPUT/OUTPUT
 ******************************************************************************/

/**
 * Read data from a connection into a buffer of a specified size.
 * @param ssl points to the connection.
 * @param buffer points to the buffer.
 * @param size is the size of the buffer in bytes.
 * @return the number of bytes actually read, 0 if closed, <0 if in error.
 */
extern int codex_connection_read(codex_connection_t * ssl, void * buffer, int size);

/**
 * Write data to a connection from a buffer of a specified size.
 * @param ssl points to the connection.
 * @param buffer points to the buffer.
 * @param size is the size of the buffer in bytes.
 * @return the number of bytes actually written, 0 if closed, <0 if in error.
 */
extern int codex_connection_write(codex_connection_t * ssl, const void * buffer, int size);

/*******************************************************************************
 * MULTIPLEXING
 ******************************************************************************/

/**
 * Return the file descriptor associated with a rendezvous. This should ONLY
 * be used for multiplexing.
 * @param bio points to the rendezvous (a BIO).
 * @return a file descriptor >=0, or <0 if in error.
 */
extern int codex_rendezvous_descriptor(codex_rendezvous_t * bio);

/**
 * Return the file descriptor associated with a connection. This should ONLY
 * be used for multiplexing.
 * @param ssl points to the connection (an SSL).
 * @return a file descriptor >=0, or <0 if in error.
 */
extern int codex_connection_descriptor(codex_connection_t * ssl);

/*******************************************************************************
 * RENEGOTIATION (EXPERIMENTAL)
 ******************************************************************************/

/**
 * Immediate force a peer to renegotiate a connection. This occurs concurrently
 * and (it is said) transparently with ongoing input/output.
 * @param ssl points to the connection (an SSL).
 * @return 0 for success, <0 otherwise.
 */
extern int codex_connection_renegotiate(codex_connection_t * ssl);

/**
 * Return true if the connection is awaiting a pending renegotiation.
 * @param ssl points to the connection (an SSL).
 * @return !0 if a renegotiation is pending, 0 otherwise.
 */
extern int codex_connection_renegotiating(codex_connection_t * ssl);

/**
 * Return the number of renegotiations performed on a connection.
 * @param ssl points to the connection (an SSL).
 * @return the number of renegotiations if successful, <0 otherwise.
 */
extern long codex_connection_renegotiations(codex_connection_t * ssl);

/**
 * Set an I/O limit in bytes after which a connection will automatically be
 * renegotiated.
 * @param ssl points to the connection (an SSL).
 * @param bytes is the limit in bytes.
 * @return the prior limit in bytes if successful, <0 otherwise.
 */
extern long codex_connection_renegotiate_bytes(codex_connection_t * ssl, long bytes);

/**
 * Set a time limit in seconds after which a connection will automatically be
 * renegotiated.
 * @param ssl points to the connection (an SSL).
 * @param seconds is the limit in seconds.
 * @return the prior limit in seconds if successful, <0 otherwise.
 */
extern long codex_connection_renegotiate_seconds(codex_connection_t * ssl, long seconds);

/*******************************************************************************
 * CLIENT
 ******************************************************************************/

/**
 * Allocate a new OpenSSL client context.
 * @param env names the environmental variable containing the password.
 * @param caf names the certificate file or NULL if none.
 * @param cap names the certificate path or NULL if none.
 * @param crt names the certificate to use.
 * @param key names the private key to use.
 * @return a pointer to the new context if successful, or NULL otherwise.
 */
extern codex_context_t * codex_client_context_new(const char * caf, const char * cap, const char * crt, const char * key);

/**
 * Allocate a new connection using a context to a specified farend.
 * @param ctx points to the context.
 * @param farend names the far end in the form "IPADDR:PORT" or "HOST:SERVICE".
 * @return a pointer to the new connection if successful, or NULL otherwise.
 */
extern codex_connection_t * codex_client_connection_new(codex_context_t * ctx, const char * farend);

/*******************************************************************************
 * SERVER
 ******************************************************************************/

/**
 * Allocate a new OpenSSL server context.
 * @param env names the environmental variable containing the password.
 * @param caf names the certificate file or NULL if none.
 * @param cap names the certificate path or NULL if none.
 * @param crt names the certificate to use.
 * @param key names the private key to use.
 * @return a pointer to the context if successful, NULL otherwise.
 */
extern codex_context_t * codex_server_context_new(const char * caf, const char * cap, const char * crt, const char * key);

/**
 * Allocate a new server rendezvous (a BIO associated with a accepting socket).
 * @param nearend names the near end in the form "PORT" or "SERVICE".
 * @return a pointer to the new rendezvous if successful, or NULL otherwise.
 */
extern codex_rendezvous_t * codex_server_rendezvous_new(const char * nearend);

/**
 * Free a server rendezvous.
 * @param bio points to the server rendezvous.
 * @return NULL if successful, the original pointer otherwise.
 */
extern codex_rendezvous_t * codex_server_rendezvous_free(codex_rendezvous_t * bio);

/**
 * Accept and allocate a new connection using a server context and a rendezvous.
 * @param ctx points to the context.
 * @param bio points to the rendezvous.
 * @return a new connection if successful, or NULL otherwise.
 */
extern codex_connection_t * codex_server_connection_new(codex_context_t * ctx, codex_rendezvous_t * bio);

#endif
