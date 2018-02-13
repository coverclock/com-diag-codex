# Copyright 2018 Digital Aggregates Corporation
# Licensed under the terms in README.hz
# author:Chip Overclock
# mailto:coverclock@diag.com
# https://github.com/coverclock/com-diag-codex
# "Chip Overclock" is a registered trademark.
# "Digital Aggregates Corporation" is a registered trademark.

# These values control how the certificates used by the unit tests are
# generated at build-time, and how OpenSSL is configured for use at run-time.
# Those parameters in the latter category can also be changed at run-time
# using settors in the private API.

# SSL_KEY:		encryption algorithm:key size in bits
# SSL_ALG:		cryptograph hash function
# SSL_GEN:		Diffie Hellman generator function
# SSL_MTH:		cryptographic suite
# SSL_LST:		list of acceptable cryptographic choices
# SSL_SID:		session identifier
# SSL_DEP:		maximum certificate depth
# SSL_DHK:		Diffie Hellman key size
# SSL_EXP:		expiration period in days
# SSL_SPW:		server unit test certificate password environmental variable name
# SSL_CPW:		client unit test certificate password environmental variable name

SSL_KEY 		:=	rsa:3072
SSL_ALG			:=	sha256
SSL_GEN			:=	2
#SSL_GEN		:=	5
SSL_MTH			:=	TLSv1_2_method
#SSL_MTH		:=	TLS_method#TODO
SSL_LST			:=	TLSv1.2+FIPS:kRSA+FIPS:!eNULL:!aNULL
SSL_SID			:=	com-diag-codex
SSL_DEP			:=	9
SSL_DHK			:=	2048
SSL_EXP			:=	365
SSL_SPW			:=	COM_DIAG_CODEX_SERVER_PASSWORD
SSL_CPW			:=	COM_DIAG_CODEX_CLIENT_PASSWORD
