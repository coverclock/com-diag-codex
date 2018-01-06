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
 *
 * REFERENCES
 * 
 * OpenSSL, documentation, <https://www.openssl.org/docs/>
 * 
 * J. Viega, M. Messier, P. Chandra, _Network Security with OpenSSL_, O'Reilly, 2002
 * 
 * J. Viega, M. Messier, _Secure Programming Cookbook_, O'Reilly, 2003
 * 
 * D. Barrett, R. Silverman, R. Byrnes, _SSH, The Secure Shell_, 2nd ed., O'Reilly, 2005
 * 
 * Ivan Ristic, _OpenSSL Cookbook_, Feisty Duck, <https://www.feistyduck.com/books/openssl-cookbook/>
 */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

extern void codex_perror(const char * s);

extern SSL_CTX * codex_client_new(const char * certificate, const char * privatekey);

extern SSL_CTX * codex_client_free(SSL_CTX * ctx);

#endif
