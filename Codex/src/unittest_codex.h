/* vi: set ts=4 expandtab shiftwidth=4: */
#ifndef _H_COM_DIAG_CODEX_UNITTEST_
#define _H_COM_DIAG_CODEX_UNITTEST_

/**
 * @file
 *
 * Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 */

/*******************************************************************************
 * PARAMETERS
 ******************************************************************************/

#undef COM_DIAG_CODEX_CLIENT_PASSWORD_ENV

#undef COM_DIAG_CODEX_SERVER_PASSWORD_ENV

#undef COM_DIAG_CODEX_METHOD

#undef COM_DIAG_CODEX_CIPHER_LIST

#undef COM_DIAG_CODEX_SELF_SIGNED_CERTIFICATES

#undef COM_DIAG_CODEX_SESSION_ID_CONTEXT

#undef COM_DIAG_CODEX_CERTIFICATE_DEPTH

/*******************************************************************************
 * GENERATORS
 ******************************************************************************/

/**
 * @def COM_DIAG_CODEX_OUT_CRT_PATH
 * Generates the path that points to the certificates used by the unit tests.
 */
#define COM_DIAG_CODEX_OUT_CRT_PATH "out/host/crt"

/**
 * @def COM_DIAG_CODEX_OUT_CRL_PATH
 * Generates the path that points to the revocation lists used by the unit tests.
 */
#define COM_DIAG_CODEX_OUT_CRL_PATH "out/host/crl"

/**
 * @def SLL
 * Cast the argument to a signed long long (used for debug printing across
 * different hardware architectures).
 */
#define SLL(_THAT_) ((signed long long)(_THAT_))

/**
 * @def ULL
 * Cast the argument to a unsigned long long (used for debug printing across
 * different hardware architectures).
 */
#define ULL(_THAT_) ((unsigned long long)(_THAT_))

/**
 * @def SL
 * Cast the argument to a signed long (used for debug printing across
 * different hardware architectures).
 */
#define SL(_THAT_) ((signed long)(_THAT_))

/**
 * @def UL
 * Cast the argument to a unsigned long (used for debug printing across
 * different hardware architectures).
 */
#define UL(_THAT_) ((unsigned long)(_THAT_))

#endif
