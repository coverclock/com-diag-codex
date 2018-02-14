/* vi: set ts=4 expandtab shiftwidth=4: */
#ifndef _H_COM_DIAG_CODEX_CODEX_
#define _H_COM_DIAG_CODEX_CODEX_

/**
 * @file
 *
 * Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 */

/*******************************************************************************
 * HEADERS
 ******************************************************************************/

#include <stdint.h>
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
 * These are the values that the enumeration returned by codex_serror() may
 * assume.
 */
typedef enum CodexSerror {
	CODEX_SERROR_NONE		= '!', /* SSL_ERROR_NONE */
	CODEX_SERROR_SSL		= 'S', /* SSL_ERROR_SSL */
	CODEX_SERROR_READ		= 'R', /* SSL_ERROR_WANT_READ */
	CODEX_SERROR_WRITE		= 'W', /* SSL_ERROR_WANT_WRITE */
	CODEX_SERROR_LOOKUP		= 'L', /* SSL_ERROR_WANT_X509_LOOKUP */
	CODEX_SERROR_SYSCALL	= 'K', /* SSL_ERROR_SYSCALL */
	CODEX_SERROR_ZERO		= '0', /* SSL_ERROR_ZERO_RETURN */
	CODEX_SERROR_CONNECT	= 'C', /* SSL_ERROR_WANT_CONNECT */
	CODEX_SERROR_ACCEPT		= 'A', /* SSL_ERROR_WANT_ACCEPT */
	CODEX_SERROR_OTHER		= '?',
	CODEX_SERROR_OKAY		= '-',
} codex_serror_t;

/**
 * These are the values that the enumeration returned by
 * codex_connection_verify() may assume.
 */
typedef enum CodexConnectionVerify {
	CODEX_CONNECTION_VERIFY_FAILED	= -1,	/* Verification failed. */
	CODEX_CONNECTION_VERIFY_PASSED	=  0,	/* Verification passed with nothing expected. */
	CODEX_CONNECTION_VERIFY_CN		=  1,	/* Verification passed matching CN. */
	CODEX_CONNECTION_VERIFY_FQDN	=  2,	/* Verification passed matching FQDN. */
} codex_connection_verify_t;

/**
 * This defines the type of the header word that precedes every payload block
 * when using the reader and writer state machines. If the value of the header
 * word is not greater than or equal to zero, the header indicates a control
 * function instead of a payload block, and the header will be returned to the
 * application with nothing in the payload buffer and the operation will be
 * considered to be COMPLETE. Zero length payload blocks are silently ignored
 * by the reader state machine.
 */
typedef int32_t codex_header_t;

/**
 * This defines the states the reader and writer state machines may assume.
 * Initial states for a new connection may be START, but since the input and
 * output direction of a single connection have separate states, they may be
 * initialized to different values. The state for a connection that has a
 * payload available for the application is COMPLETE, for a connection that
 * has closed is FINAL, and for a connection whose packet has been consumed
 * and is ready for another is set by the application to RESTART. IDLE is a
 * do-nothing state.
 */
typedef enum CodexState {
	CODEX_STATE_START		= 'S',	/* Verify identity and read header. */
	CODEX_STATE_RESTART		= 'R',	/* Read header. */
	CODEX_STATE_HEADER		= 'H',	/* Continue reading header. */
	CODEX_STATE_PAYLOAD		= 'P',	/* Read payload. */
	CODEX_STATE_SKIP		= 'K',	/* Skip payload. */
	CODEX_STATE_COMPLETE	= 'C',	/* Payload available for application. */
	CODEX_STATE_IDLE		= 'I',	/* Do nothing. */
	CODEX_STATE_FINAL		= 'F',	/* Far end closed connection. */
} codex_state_t;

/**
 * These are the the indications that may be carried in a packet header that
 * the handshake unit tests use to quiesce and then resume the data stream when
 * doing a handshake for renegotiation. Applications using the Codex library
 * don't have to use these; their use isn't baked into the library in any way.
 * But they're useful enough to include here as a common convention.
 */
typedef enum CodexIndication {
	CODEX_INDICATION_PENDING	= -5,	/* NE told FE to prepare for action. */
	CODEX_INDICATION_NEAREND	= -4,	/* NE preparing for action. */
	CODEX_INDICATION_DONE		= -3,	/* Tell FE action complete. */
	CODEX_INDICATION_READY		= -2,	/* Tell NE that FE ready for action. */
	CODEX_INDICATION_FAREND		= -1,	/* Tell FE to prepare for action. */
	CODEX_INDICATION_NONE		=  0,	/* No action pending or in progress. */
} codex_indication_t;

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
 * @return an enumerated value indicating what action to take.
 */
extern codex_serror_t codex_serror(const char * str, const codex_connection_t * ssl, int rc);

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
 * @param mode defines the peer verification mode.
 * @param depth defines the maximum certificate depth (9 works well).
 * @param options defines the SSL protocol options.
 * @return a pointer to the new context if successful, NULL otherwise.
 */
extern codex_context_t * codex_context_new(const char * env, const char * caf, const char * cap, const char * crt, const char * key, int mode, int depth, int options);

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
 * @return an enumeration indicating the result of the verification.
 */
extern codex_connection_verify_t codex_connection_verify(codex_connection_t * ssl, const char * expected);

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

/**
 * Return true if the connection is a server, false if it is a client.
 * @param ssl points to the connection.
 * @return true if the connection is a server, false if it is a client.
 */
extern bool codex_connection_is_server(const codex_connection_t * ssl);

/*******************************************************************************
 * INPUT/OUTPUT
 ******************************************************************************/

/**
 * Read data from a connection into a buffer of a specified size.
 * @param ssl points to the connection.
 * @param buffer points to the buffer.
 * @param size is the size of the buffer in bytes.
 * @param serror points to the variable into which an OpenSSL error is returned.
 * @return the number of bytes actually read, 0 if closed, <0 if in error.
 */
extern int codex_connection_read_generic(codex_connection_t * ssl, void * buffer, int size, codex_serror_t * serror);

/**
 * Read data from a connection into a buffer of a specified size.
 * @param ssl points to the connection.
 * @param buffer points to the buffer.
 * @param size is the size of the buffer in bytes.
 * @return the number of bytes actually read, 0 if closed, <0 if in error.
 */
static inline int codex_connection_read(codex_connection_t * ssl, void * buffer, int size)
{
	return codex_connection_read_generic(ssl, buffer, size, (codex_serror_t *)0);
}

/**
 * Write data to a connection from a buffer of a specified size.
 * @param ssl points to the connection.
 * @param buffer points to the buffer.
 * @param size is the size of the buffer in bytes.
 * @param serror points to the variable into which an OpenSSL error is returned.
 * @return the number of bytes actually written, 0 if closed, <0 if in error.
 */
extern int codex_connection_write_generic(codex_connection_t * ssl, const void * buffer, int size, codex_serror_t * serror);

/**
 * Write data to a connection from a buffer of a specified size.
 * @param ssl points to the connection.
 * @param buffer points to the buffer.
 * @param size is the size of the buffer in bytes.
 * @return the number of bytes actually written, 0 if closed, <0 if in error.
 */
static inline int codex_connection_write(codex_connection_t * ssl, const void * buffer, int size)
{
	return codex_connection_write_generic(ssl, buffer, size, (codex_serror_t *)0);
}

/**
 * Return true if there is data in the connection waiting to be read, false
 * otherwise.
 * @param ssl points to the connection (an SSL).
 * @return true if there is data waiting to be read.
 */
extern bool codex_connection_is_ready(codex_connection_t * ssl);

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

/*******************************************************************************
 * HANDSHAKE
 ******************************************************************************/

/**
 * Immediately force a peer to renegotiate a connection. This has the effect of
 * generating new temporary encryption keys for the peers to use; this is a good
 * thing to do for very long lived connections, since the encryption is more
 * likely to be broken by evil actors the longer it is used. Empirical evidence
 * suggests that regardless of what the OpenSSL documentation may suggest, both
 * unidirectional streams of the full-duplex connections must be empty of
 * application data for the renegotiation to succeed. See the handshake unit
 * test for an example.
 * @param ssl points to the connection (an SSL).
 * @return 0 for success, <0 otherwise.
 */
extern int codex_handshake_renegotiate(codex_connection_t * ssl);

/*******************************************************************************
 * MACHINES
 ******************************************************************************/

/**
 * Implement a state machine for reading packet data from an SSL, handling
 * verification and closing automatically. Except for ssl and size, all of the
 * parameters for the reader must be independent of those of the writer. If the
 * received header indicates a packet size larger than the buffer, only as much
 * of the packet as will fit in the buffer will be returned; the header will
 * still indicate the original transmitted packet size.
 * @param state is the current state whose initial value depends on the application.
 * @param expected is the expected FQDN or CN for verification.
 * @param ssl points to the SSL.
 * @param header points to where the header will be stored.
 * @param buffer points to where the payload will be stored.
 * @param size is the size of the payload buffer in bytes.
 * @param here points to where the current buffer pointer will be stored.
 * @param length points to where the remaining buffer length will be stored.
 * @param serror points to the variable into which an OpenSSL error is returned.
 * @return the new state.
 */
extern codex_state_t codex_machine_reader_generic(codex_state_t state, const char * expected, codex_connection_t * ssl, codex_header_t * header, void * buffer, int size, uint8_t ** here, int * length, codex_serror_t * serror);

/**
 * Implement a state machine for reading packet data from an SSL, handling
 * verification and closing automatically. Except for ssl and size, all of the
 * parameters for the reader must be independent of those of the writer. If the
 * received header indicates a packet size larger than the buffer, only as much
 * of the packet as will fit in the buffer will be returned; the header will
 * still indicate the original received packet size.
 * @param state is the current state whose initial value depends on the application.
 * @param expected is the expected FQDN or CN for verification.
 * @param ssl points to the SSL.
 * @param header points to where the header will be stored.
 * @param buffer points to where the payload will be stored.
 * @param size is the size of the payload buffer in bytes.
 * @param here points to where the current buffer pointer will be stored.
 * @param length points to where the remaining buffer length will be stored.
 * @return the new state.
 */
static inline codex_state_t codex_machine_reader(codex_state_t state, const char * expected, codex_connection_t * ssl, codex_header_t * header, void * buffer, int size, uint8_t ** here, int * length)
{
	return codex_machine_reader_generic(state, expected, ssl, header, buffer, size, here, length, (codex_serror_t *)0);
}

/**
 * Implement a state machine for writing packet data to an SSL, handling
 * verification and closing automatically. Except for ssl and size, all of the
 * parameters for the reader must be independent of those of the writer.
 * @param state is the current state whose initial value depends on the application.
 * @param expected is the expected FQDN or CN for verification.
 * @param ssl points to the SSL.
 * @param header points to where the header will be stored.
 * @param buffer points to where the payload will be stored.
 * @param size is the size of the payload buffer in bytes.
 * @param here points to where the current buffer pointer will be stored.
 * @param length points to where the remaining buffer length will be stored.
 * @param serror points to the variable into which an OpenSSL error is returned.
 * @return the new state.
 */
extern codex_state_t codex_machine_writer_generic(codex_state_t state, const char * expected, codex_connection_t * ssl, codex_header_t * header, void * buffer, int size, uint8_t ** here, int * length, codex_serror_t * serror);

/**
 * Implement a state machine for writing packet data to an SSL, handling
 * verification and closing automatically. Except for ssl and size, all of the
 * parameters for the reader must be independent of those of the writer.
 * @param state is the current state whose initial value depends on the application.
 * @param expected is the expected FQDN or CN for verification.
 * @param ssl points to the SSL.
 * @param header points to where the header will be stored.
 * @param buffer points to where the payload will be stored.
 * @param size is the size of the payload buffer in bytes.
 * @param here points to where the current buffer pointer will be stored.
 * @param length points to where the remaining buffer length will be stored.
 * @return the new state.
 */
static inline codex_state_t codex_machine_writer(codex_state_t state, const char * expected, codex_connection_t * ssl, codex_header_t * header, void * buffer, int size, uint8_t ** here, int * length)
{
	return codex_machine_writer_generic(state, expected, ssl, header, buffer, size, here, length, (codex_serror_t *)0);
}

#endif
