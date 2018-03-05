# Copyright 2018 Digital Aggregates Corporation
# Licensed under the terms in README.hz
# author:Chip Overclock
# mailto:coverclock@diag.com
# https://github.com/coverclock/com-diag-codex
# "Chip Overclock" is a registered trademark.
# "Digital Aggregates Corporation" is a registered trademark.

# These values control how the certificates used by the unit tests are
# generated at build-time, and how OpenSSL is configured for use at run-time.
# Some parameters in the latter category can also be changed at run-time
# using settors in the private API.

# SSL_ALG:		message digest cryptographic hash function for certificate signing
# SSL_CPW:		client unit test certificate password environmental variable name
# SSL_DEP:		maximum depth for chained certificates
# SSL_DHK:		Diffie-Hellman key size in bits for key exchange
# SSL_EXP:		certificate expiration period in days
# SSL_GEN:		Diffie-Hellman generator function for key exchange
# SSL_KEY:		asymmetric encryption algorithm:key size in bits for certificate public/private keys
# SSL_LST:		list of acceptable symmetric cryptographic ciphers
# SSL_MTH:		transport layer security standard to which to conform
# SSL_SID:		session identifier for session renegotiation or caching
# SSL_SPW:		server unit test certificate password environmental variable name
# SSL_SSC:		if true then accept self-signed certificates by default

SSL_ALG			:=	sha256
SSL_CPW			:=	COM_DIAG_CODEX_CLIENT_PASSWORD
SSL_DEP			:=	9
SSL_DHK			:=	2048
SSL_EXP			:=	365
SSL_GEN			:=	2
#SSL_GEN		:=	5
SSL_KEY 		:=	rsa:3072
SSL_LST			:=	TLSv1.2+FIPS:kRSA+FIPS:!eNULL:!aNULL
SSL_MTH			:=	TLSv1_2_method
#SSL_MTH		:=	TLS_method
SSL_SID			:=	com-diag-codex
SSL_SPW			:=	COM_DIAG_CODEX_SERVER_PASSWORD
SSL_SSC			:=	0
#SSL_SSC		:=	1
