/* vi: set ts=4 expandtab shiftwidth=4: */
#ifndef _H_COM_DIAG_CODEX_PLATFORM_
#define _H_COM_DIAG_CODEX_PLATFORM_

/**
 * @file
 *
 * Copyright 2020 Digital Aggregates Corporation, Colorado, USA.
 * Licensed under the terms in LICENSE.txt.
 *
 * The Codex Platform feature tries to determine what OpenSSL
 * implementation is being used. It does default to something
 * reasonable. But things work best if it can really tell, since
 * the API differs between implementations.
 */

/*******************************************************************************
 * PLATFORM
 ******************************************************************************/

#if defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER == 0x1010006f) && !defined(OPENSSL_IS_BORINGSSL)
#	define COM_DIAG_CODEX_PLATFORM "OpenSSL 1.1.0"
#	define COM_DIAG_CODEX_PLATFORM_OPENSSL 0x1010006fL
#	define COM_DIAG_CODEX_PLATFORM_OPENSSL_1_1_0 1
#elif defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER == 0x1000207f) && !defined(OPENSSL_IS_BORINGSSL)
#	define COM_DIAG_CODEX_PLATFORM "OpenSSL 1.0.2"
#	define COM_DIAG_CODEX_PLATFORM_OPENSSL 0x1000207fL
#	define COM_DIAG_CODEX_PLATFORM_OPENSSL_1_0_2 1
#elif defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER == 0x1000114fL) && !defined(OPENSSL_IS_BORINGSSL)
#	define COM_DIAG_CODEX_PLATFORM "OpenSSL 1.0.1"
#	define COM_DIAG_CODEX_PLATFORM_OPENSSL 0x1000114fL
#	define COM_DIAG_CODEX_PLATFORM_OPENSSL_1_0_1 1
#elif defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER == 0x1010100fL) && !defined(OPENSSL_IS_BORINGSSL)
#	define COM_DIAG_CODEX_PLATFORM "OpenSSL 1.1.1"
#	define COM_DIAG_CODEX_PLATFORM_OPENSSL 0x1010100fL
#	define COM_DIAG_CODEX_PLATFORM_OPENSSL_1_1_1 1
#elif defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER == 0x10101002L) && !defined(OPENSSL_IS_BORINGSSL)
#	define COM_DIAG_CODEX_PLATFORM "OpenSSL 1.1.1"
#	define COM_DIAG_CODEX_PLATFORM_OPENSSL 0x10101002L
#	define COM_DIAG_CODEX_PLATFORM_OPENSSL_1_1_1 1
#elif defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER == 0x1010102fL) && !defined(OPENSSL_IS_BORINGSSL)
#	define COM_DIAG_CODEX_PLATFORM "OpenSSL 1.1.1"
#	define COM_DIAG_CODEX_PLATFORM_OPENSSL 0x1010102fL
#	define COM_DIAG_CODEX_PLATFORM_OPENSSL_1_1_1 1
#elif defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER == 0x1010104fL) && !defined(OPENSSL_IS_BORINGSSL)
#	define COM_DIAG_CODEX_PLATFORM "OpenSSL 1.1.1"
#	define COM_DIAG_CODEX_PLATFORM_OPENSSL 0x1010104fL
#	define COM_DIAG_CODEX_PLATFORM_OPENSSL_1_1_1 1
#elif defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER == 0x1010007f) && defined(OPENSSL_IS_BORINGSSL)
#	define COM_DIAG_CODEX_PLATFORM "BoringSSL 1.1.0"
#	define COM_DIAG_CODEX_PLATFORM_BORINGSSL 0x1010007fL
#	define COM_DIAG_CODEX_PLATFORM_BORINGSSL_1_1_0 1
#elif defined(OPENSSL_IS_BORINGSSL)
#	warning This is not a known BoringSSL version (assuming 1.1.0).
#	define COM_DIAG_CODEX_PLATFORM "BoringSSL"
#	define COM_DIAG_CODEX_PLATFORM_BORINGSSL 0x10100000L
#	define COM_DIAG_CODEX_PLATFORM_BORINGSSL_1_1_0 1
#else
#	warning This is not a known OpenSSL version (assuming 1.1.1).
#	define COM_DIAG_CODEX_PLATFORM "OpenSSL"
#	define COM_DIAG_CODEX_PLATFORM_OPENSSL 0x10101000L
#	define COM_DIAG_CODEX_PLATFORM_OPENSSL_1_1_1 1
#endif

#endif
