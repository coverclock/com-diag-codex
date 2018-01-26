/* vi: set ts=4 expandtab shiftwidth=4: */
#ifndef _H_COM_DIAG_CODEX_UNITTEST_
#define _H_COM_DIAG_CODEX_UNITTEST_

/**
 * @file
 *
 * Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock <coverclock@diag.com><BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 */

/*******************************************************************************
 * PARAMETERS
 ******************************************************************************/

#undef COM_DIAG_CODEX_CIPHER_LIST

#undef COM_DIAG_CODEX_CERTIFICATE_DEPTH

#undef COM_DIAG_CODEX_RENEGOTIATE_BYTES

#undef COM_DIAG_CODEX_RENEGOTIATE_SECONDS

/*******************************************************************************
 * GENERATORS
 ******************************************************************************/

/**
 * Generates the path that points to the certificates used by the unit tests.
 */
#define COM_DIAG_CODEX_OUT_CRT_PATH "out/host/crt"

/*******************************************************************************
 * RENEGOTIATION (EXPERIMENTAL)
 ******************************************************************************/

/**
 * Immediately force a peer to renegotiate a connection. This occurs concurrently
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

#endif
