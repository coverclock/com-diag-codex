/* vi: set ts=4 expandtab shiftwidth=4: */
#ifndef _H_COM_DIAG_CODEX_CODEX_
#define _H_COM_DIAG_CODEX_CODEX_

/**
 * @file
 *
 * Copyright 2018-2020 Digital Aggregates Corporation, Colorado, USA.
 * Licensed under the terms in LICENSE.txt.
 *
 * The Codex package implements a slightly simpler interface to the
 * Open Secure Socket Layer (OpenSSL) library and its variations like
 * BoringSSL.
 *
 * REFERENCES
 * 
 * D. Adrian, et al., "Imperfect Forward Secrecy: How Diffie-Hellman Fails
 * in Practice", 22nd ACM Conference on Computer and Communication Security,
 * 2015-10, <https://weakdh.org/imperfect-forward-secrecy-ccs15.pdf>
 * 
 * K. Ballard, "Secure Programming with the OpenSSL API",
 * <https://www.ibm.com/developerworks/library/l-openssl/>, IBM, 2012-06-28
 * 
 * E. Barker, et al., "Transitions: Recommendation for Transitioning the
 * Use of Cryptographic Algorithms and Key Lengths", NIST, SP 800-131A
 * Rev. 1, 2015-11
 * 
 * D. Barrett, et al., _SSH, The Secure Shell_, 2nd ed.,
 * O'Reilly, 2005
 * 
 * D. Cooper, et al., "Internet X.509 Public Key Infrastructure Certificate
 * and Certificate Revocation List (CRL) Profile", RFC 5280, 2008-05
 * 
 * J. Davies, _Implementing SSL/TLS_, Wiley, 2011
 * 
 * A. Diquet, "Everything You've Always Wanted to Know About Certificate
 * Validation with OpenSSL (but Were Afraid to Ask)", iSECpartners, 2012-10-29,
 * <https://github.com/iSECPartners/ssl-conservatory/blob/master/openssl/everything-you-wanted-to-know-about-openssl.pdf?raw=true>
 * 
 * Frank4DD, "certserial.c", 2014,
 * <http://fm4dd.com/openssl/certserial.htm>
 * 
 * V. Geraskin, "OpenSSL and select()", 2014-02-21,
 * <http://www.past5.com/tutorials/2014/02/21/openssl-and-select/>
 * 
 * M. Georgiev, et. al., "The Most Dangerous Code in the World: Validating SSL
 * Certificates in Non-Browser Software", 19nd ACM Conference on Computer and
 * Communication Security (CCS'12), Raleigh NC USA, 2012-10-16..18,
 * <https://www.cs.utexas.edu/~shmat/shmat_ccs12.pdf>
 * 
 * D. Gibbons, personal communication, 2018-01-17
 * 
 * D. Gibbons, personal communication, 2018-02-12
 * 
 * D. Gillmor, "Negotiated Finite Diffie-Hellman Ephemeral Parameters for
 * Transport Layer Security (TLS)", RFC 7919, 2016-08
 * 
 * HP, "SSL Programming Tutorial", HP OpenVMS Systems Documentation,
 * <http://h41379.www4.hpe.com/doc/83final/ba554_90007/ch04s03.html>
 * 
 * Karthik, et al., "SSL Renegotiation with Full Duplex Socket Communication",
 * Stack Overflow, 2013-12-14,
 * <https://stackoverflow.com/questions/18728355/ssl-renegotiation-with-full-duplex-socket-communication>
 * 
 * V. Kruglikov et al., "Full-duplex SSL/TLS renegotiation failure", OpenSSL
 * Ticket #2481, 2011-03-26,
 * <https://rt.openssl.org/Ticket/Display.html?id=2481&user=guest&pass=guest>
 * 
 * OpenSSL, documentation, <https://www.openssl.org/docs/>
 * 
 * OpenSSL, "HOWTO keys", ```openssl/doc/HOWTO/keys.txt```
 * 
 * OpenSSL, "HOWTO proxy certificates",
 * ```openssl/doc/HOWTO/proxy_certificates.txt```
 * 
 * OpenSSL, "HOWTO certificates", ```openssl/doc/HOWTO/certificates.txt```
 * 
 * OpenSSL, "Fingerprints for Signing Releases", ```openssl/doc/fingerprints.txt```
 * 
 * OpenSSL Wiki, "FIPS mode and TLS",
 * <https://wiki.openssl.org/index.php/FIPS_mode_and_TLS>
 * 
 * E. Rescorla, "An Introduction to OpenSSL Programming (Part I)", Version
 * 1.0, 2001-10-05, <http://www.past5.com/assets/post_docs/openssl1.pdf>
 * (also Linux Journal, September 2001)
 * 
 * E. Rescorla, "An Introduction to OpenSSL Programming (Part II)", Version
 * 1.0, 2002-01-09, <http://www.past5.com/assets/post_docs/openssl2.pdf>
 * (also Linux Journal, September 2001)
 * 
 * I. Ristic, _OpenSSL Cookbook_, Feisty Duck,
 * <https://www.feistyduck.com/books/openssl-cookbook/>
 * 
 * I. Ristic, "SSL and TLS Deployment Best Practices", Version 1.6-draft,
 * Qualys/SSL Labs, 2017-05-13,
 * <https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices>
 * 
 * L. Rumcajs, "How to perform a rehandshake (renegotiation) with OpenSSL API",
 * Stack Overflow, 2015-12-04,
 * <https://stackoverflow.com/questions/28944294/how-to-perform-a-rehandshake-renegotiation-with-openssl-api>
 * 
 * J. Viega, et al., _Network Security with OpenSSL_, O'Reilly,
 * 2002
 * 
 * J. Viega, et al., _Secure Programming Cookbook for C and C++_, O'Reilly,
 * 2003
 */

/*******************************************************************************
 * HEADERS
 ******************************************************************************/

/* Hopefully benign if not BoringSSL. */
#define BORINGSSL_SHARED_LIBRARY 1

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/asn1.h>
#include "com/diag/codex/codex_platform.h"

/*******************************************************************************
 * TYPES
 ******************************************************************************/

/**
 * Declares a type used by OpenSSL to define a method.
 */
typedef const SSL_METHOD * (*codex_method_t)(void);

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
	CODEX_SERROR_OTHER		= '?', /* Undefined SSL error. */
	CODEX_SERROR_SUCCESS	= '-', /* No SSL error occurred. */
} codex_serror_t;

/**
 * These are the bits that may be set in the value that
 * codex_connection_verify() may return. It is up to the application to decide
 * what is sufficient verification.
 */
typedef enum CodexVerify {
	CODEX_VERIFY_FAILED	= (0     ),	/* 0x0 Verification failed. */
	CODEX_VERIFY_PASSED	= (1 << 0),	/* 0x1 Nothing expected but otherwise valid. */
	CODEX_VERIFY_CN		= (1 << 1),	/* 0x2 CN matched expected. */
	CODEX_VERIFY_IPV4	= (1 << 2),	/* 0x4 DNS matched IPv4 far end. */
	CODEX_VERIFY_IPV6	= (1 << 3),	/* 0x4 DNS matched IPv6 far end. */
	CODEX_VERIFY_DNS	= (1 << 4),	/* 0x4 DNS matched either IP far end. */
	CODEX_VERIFY_FQDN	= (1 << 5),	/* 0x8 FQDN matched expected. */
} codex_verify_t;

/**
 * This defines the type of the header word that precedes every payload block
 * when using the reader and writer state machines. If the value of the header
 * word is not greater than or equal to zero, the header indicates a control
 * function instead of a payload block, and the header will be returned to the
 * application with nothing in the payload buffer and the operation will be
 * considered to be COMPLETE. Zero length payload blocks are silently ignored
 * by the reader state machine. This value is passed to the peer in network
 * byte order.
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
	CODEX_STATE_COMPLETE	= 'C',	/* Payload (or SSL serror) available. */
	CODEX_STATE_IDLE		= 'I',	/* Do nothing. */
	CODEX_STATE_FINAL		= 'F',	/* Connection closed. */
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

/**
 * @def COM_DIAG_CODEX_SERIALNUMBER_BUFSIZE
 * Generates the minimum size of a buffer that can contain the ASCII hexadecimal
 * representation of a X.509 certificate serial number according to RFC 5280
 * 4.1.2.2 plus a trailing NUL.
 */
#define COM_DIAG_CODEX_SERIALNUMBER_BUFSIZE ((20 * 2) + 1)

/**
 * This defines a type that is a character array large enough to contain the
 * ASCII hexadecimal representation of a X.509 certificate serial number
 * including a trailing NUL. By convention, in Codex the certificate serial
 * number is represented as a hexadecimal number in which the alphabetic digits
 * are all upper case.
 */
typedef char (codex_serialnumber_t)[COM_DIAG_CODEX_SERIALNUMBER_BUFSIZE];

/*******************************************************************************
 * ERRORS
 ******************************************************************************/

/**
 * Logs the error messages found on the OpenSSL error queue.
 * @param file points to the string generated by __FILE__.
 * @param line is the interger generated by __LINE__.
 * @param str points to the prefix string printed before each message.
 */
extern void codex_perror_f(const char * file, int line, const char * str);

/**
 * @def codex_perror
 * Calls codex_perror_f with __FILE__, __LINE__, and @a _STR_.
 */
#define codex_perror(_STR_) codex_perror_f(__FILE__, __LINE__, _STR_)

/**
 * Logs the error message associated with a particular connection and return
 * code.
 * @param file points to the string generated by __FILE__.
 * @param line is the interger generated by __LINE__.
 * @param str points to the prefix string printed before each message.
 * @param ssl points to the connection.
 * @param rc is the return code returned by the failing function.
 * @return an enumerated value indicating what action to take.
 */
extern codex_serror_t codex_serror_f(const char * file, int line, const char * str, const codex_connection_t * ssl, int rc);

/**
 * @def codex_serror
 * Calls codex_serror_f with __FILE__, __LINE__, @a _STR_, @a _SSL_, and @a _RC_.
 */
#define codex_serror(_STR_, _SSL_, _RC_) codex_serror_f(__FILE__, __LINE__, _STR_, _SSL_, _RC_)

/*******************************************************************************
 * INITIALIZATION
 ******************************************************************************/

/**
 * Initializes the OpenSSL stack, loads the Diffie-Hellman (DH) parameter
 * file used for key exchange of the symmetric keys for data stream encryption,
 * and optionally loads the text file containing an ASCII list of serial
 * numbers identifying revoked certificates.
 * Only needs to be called once per application.
 * @param cnf points to the OpenSSL configuration file or null for default.
 * @param dhf names the DH parameter file.
 * @param crl names the certificate revocation list file or null if none.
 * @return 0 if successful, <0 otherwise.
 */
extern int codex_initialize(const char * cnf, const char * dhf, const char * crl);

/*******************************************************************************
 * CONTEXT
 ******************************************************************************/

/**
 * Allocate a new OpenSSL context. This is the generic context generating
 * function on which the more specific (and simpler) client and server context
 * generating functions are based. The more specific functions supply
 * appropriate parameters based either on the role (client or server) or based
 * on the default values established at build time and which can be set at run
 * time by settor functions defined in the private API.
 * @param env names the environmental variable containing the password.
 * @param caf names the certificate file or NULL if none.
 * @param cap names the certificate path or NULL if none.
 * @param crt names the certificate to use.
 * @param key names the private key to use.
 * @param flags defines the peer verification mode.
 * @param depth defines the maximum certificate depth (9 works well).
 * @param options defines the SSL protocol options.
 * @param method points to the selected method function.
 * @param list is the cipher algorithm list.
 * @param context is the session identifier context string.
 * @return a pointer to the new context if successful, NULL otherwise.
 */
extern codex_context_t * codex_context_new(const char * env, const char * caf, const char * cap, const char * crt, const char * key, int flags, int depth, int options, codex_method_t method, const char * list, const char * context);

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
 * N.B. For OpenSSL implementations that do not support the SSL_is_server()
 * query (e.g. OpenSSL 1.0.1), this function always returns true. This
 * prevents the verification code as used in the reader and writer state
 * machines from breaking, but prevents the client from being able to
 * verify the server after connecting but before an initial read or write.
 * @param ssl points to the connection.
 * @return true if the connection is a server, false if it is a client.
 */
extern bool codex_connection_is_server(const codex_connection_t * ssl);

/*******************************************************************************
 * VERIFICATION
 ******************************************************************************/

/**
 * Walk the peer X309 certificate and verify that it came from the expected host
 * by comparing the provided string against the FQDN or the CN, and furthermore
 * examine the OpenSSL verification status. A bit mask is returned containing
 * bits defined in CodexConnectionVerify; it is up to the application to
 * determine what bits are important.
 * @param ssl points to the connection.
 * @param expected names the expected host FQDN or CN or NULL if none.
 * @return a bit mask indicating the result of the verification.
 */
extern int codex_connection_verify(codex_connection_t * ssl, const char * expected);

/**
 * This is a helper that checks the verifier bit mask for commonly used
 * acceptable patterns. Applications are welcome to come up with their
 * own combinations that they like better.
 * @param mask is the bit mask returned by the verifier.
 * @return true if the bit mask fits some common criteria.
 */
static inline bool codex_connection_verified(int mask) {
	return (((mask & CODEX_VERIFY_DNS) != 0) && ((mask & (CODEX_VERIFY_PASSED | CODEX_VERIFY_CN | CODEX_VERIFY_FQDN)) != 0));
}

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
extern ssize_t codex_connection_read_generic(codex_connection_t * ssl, void * buffer, size_t size, codex_serror_t * serror);

/**
 * Read data from a connection into a buffer of a specified size.
 * @param ssl points to the connection.
 * @param buffer points to the buffer.
 * @param size is the size of the buffer in bytes.
 * @return the number of bytes actually read, 0 if closed, <0 if in error.
 */
static inline ssize_t codex_connection_read(codex_connection_t * ssl, void * buffer, int size)
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
extern ssize_t codex_connection_write_generic(codex_connection_t * ssl, const void * buffer, size_t size, codex_serror_t * serror);

/**
 * Write data to a connection from a buffer of a specified size.
 * @param ssl points to the connection.
 * @param buffer points to the buffer.
 * @param size is the size of the buffer in bytes.
 * @return the number of bytes actually written, 0 if closed, <0 if in error.
 */
static inline ssize_t codex_connection_write(codex_connection_t * ssl, const void * buffer, size_t size)
{
	return codex_connection_write_generic(ssl, buffer, size, (codex_serror_t *)0);
}

/**
 * Return true if there is data in the connection waiting to be read, false
 * otherwise.
 * @param ssl points to the connection (an SSL).
 * @return true if there is data waiting to be read.
 */
static inline bool codex_connection_is_ready(codex_connection_t * ssl)
{
	return !!SSL_pending(ssl);
}

/*******************************************************************************
 * MULTIPLEXING
 ******************************************************************************/

/*
 * I've successfully multiplexed multiple SSL connections using select(2) via
 * the Diminuto mux feature. But in SSL there is a *lot* going on under the
 * hood. The byte stream the application reads and writes is an artifact of
 * all the authentication and crypto going on in libssl and libcrypto. The
 * Linux socket and multiplexing implementation in the kernel lies below all
 * of this and knows *nothing* about it. So the fact that there's data to be
 * read on the socket doesn't mean there's _application_ data to be read. And
 * the fact that the select() doesn't fire doesn't mean there isn't application
 * data waiting to be read in a decryption buffer. A lot of application reads
 * and writes may merely be driving the underlying protocol and associated state
 * machines in the SSL implementation. Hence multiplexing isn't as useful as it
 * might seem, and certainly not as easy as in non-OpenSSL applications. A
 * multi-threaded server approach, which uses blocking reads and writes, albeit
 * less scalable, might ultimately be more useful.
 */

/**
 * Return the file descriptor associated with a rendezvous. This should ONLY
 * be used for multiplexing.
 * @param bio points to the rendezvous (a BIO).
 * @return a file descriptor >=0, or <0 if in error.
 */
static inline int codex_rendezvous_descriptor(codex_rendezvous_t * bio)
{
	return BIO_get_fd(bio, (int *)0);
}

/**
 * Return the file descriptor associated with a connection. This should ONLY
 * be used for multiplexing or similar socket management, *never* for I/O.
 * @param ssl points to the connection (an SSL).
 * @return a file descriptor >=0, or <0 if in error.
 */
static inline int codex_connection_descriptor(codex_connection_t * ssl)
{
	return SSL_get_fd(ssl);
}

/*******************************************************************************
 * CLIENT
 ******************************************************************************/

/**
 * Allocate a new OpenSSL client context.
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
 * still indicate the original transmitted packet size. If an exceptional
 * condition occurred, a note will be passed back in the serror variable if it
 * is supplied; otherwise the connection may be automatically shut down. If no
 * exceptional condition occurred, serror will be set to CODEX_SERROR_SUCCESS.
 * Basic verification is performed on the connection in the START state, and if
 * it fails, the connection is closed and transitions immediately to FINAL.
 * The verification mask is returned to the caller if so desired, upon transition
 * from the START state, where it can be further examined.
 * @param state is the current state whose initial value depends on the application.
 * @param expected is the expected FQDN or CN for verification.
 * @param ssl points to the SSL.
 * @param header points to where the header will be stored.
 * @param buffer points to where the payload will be stored.
 * @param size is the size of the payload buffer in bytes.
 * @param here points to where the current buffer pointer will be stored.
 * @param length points to where the remaining buffer length will be stored.
 * @param serror points to the variable into which an OpenSSL error is returned.
 * @param mask points to the variable into which the verification mask is returned.
 * @return the new state.
 */
extern codex_state_t codex_machine_reader_generic(codex_state_t state, const char * expected, codex_connection_t * ssl, codex_header_t * header, void * buffer, size_t size, uint8_t ** here, size_t * length, codex_serror_t * serror, int * mask);

/**
 * Implement a state machine for reading packet data from an SSL, handling
 * verification and closing automatically. Except for ssl and size, all of the
 * parameters for the reader must be independent of those of the writer. If the
 * received header indicates a packet size larger than the buffer, only as much
 * of the packet as will fit in the buffer will be returned; the header will
 * still indicate the original received packet size.
 * Basic verification is performed on the connection in the START state, and if
 * it fails, the connection is closed and transitions immediately to FINAL.
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
static inline codex_state_t codex_machine_reader(codex_state_t state, const char * expected, codex_connection_t * ssl, codex_header_t * header, void * buffer, size_t size, uint8_t ** here, size_t * length)
{
	return codex_machine_reader_generic(state, expected, ssl, header, buffer, size, here, length, (codex_serror_t *)0, (int *)0);
}

/**
 * Implement a state machine for writing packet data to an SSL, handling
 * verification and closing automatically. Except for ssl and size, all of the
 * parameters for the reader must be independent of those of the writer. If an
 * exceptional condition occurred, a note will be passed back in the serror
 * variable if it is supplied; otherwise the connection may be automatically
 * shut down. If no exceptional condition occurred, serror will be set to
 * CODEX_SERROR_SUCCESS.
 * Basic verification is performed on the connection in the START state, and if
 * it fails, the connection is closed and transitions immediately to FINAL.
 * The verification mask is returned to the caller if so desired, upon transition
 * from the START state, where it can be further examined.
 * @param state is the current state whose initial value depends on the application.
 * @param expected is the expected FQDN or CN for verification.
 * @param ssl points to the SSL.
 * @param header points to where the header will be stored.
 * @param buffer points to where the payload will be stored.
 * @param size is the size of the payload buffer in bytes (or if negative an indication).
 * @param here points to where the current buffer pointer will be stored.
 * @param length points to where the remaining buffer length will be stored.
 * @param serror points to the variable into which an OpenSSL error is returned.
 * @param mask points to the variable into which the verification mask is returned.
 * @return the new state.
 */
extern codex_state_t codex_machine_writer_generic(codex_state_t state, const char * expected, codex_connection_t * ssl, codex_header_t * header, void * buffer, ssize_t size, uint8_t ** here, size_t * length, codex_serror_t * serror, int * mask);

/**
 * Implement a state machine for writing packet data to an SSL, handling
 * verification and closing automatically. Except for ssl and size, all of the
 * parameters for the reader must be independent of those of the writer.
 * Basic verification is performed on the connection in the START state, and if
 * it fails, the connection is closed and transitions immediately to FINAL.
 * @param state is the current state whose initial value depends on the application.
 * @param expected is the expected FQDN or CN for verification.
 * @param ssl points to the SSL.
 * @param header points to where the header will be stored.
 * @param buffer points to where the payload will be stored.
 * @param size is the size of the payload buffer in bytes (or if negative an indication).
 * @param here points to where the current buffer pointer will be stored.
 * @param length points to where the remaining buffer length will be stored.
 * @return the new state.
 */
static inline codex_state_t codex_machine_writer(codex_state_t state, const char * expected, codex_connection_t * ssl, codex_header_t * header, void * buffer, ssize_t size, uint8_t ** here, size_t * length)
{
	return codex_machine_writer_generic(state, expected, ssl, header, buffer, size, here, length, (codex_serror_t *)0, (int *)0);
}

#endif
