# Copyright 2018 Digital Aggregates Corporation
# Licensed under the terms in README.hz
# author:Chip Overclock
# mailto:coverclock@diag.com
# https://github.com/coverclock/com-diag-codex
# "Chip Overclock" is a registered trademark.
# "Digital Aggregates Corporation" is a registered trademark.

# These values control how the certificates used by the unit tests are
# generated at build-time, and how OpenSSL is configured for use at run-time.

SSL_KEY 			:=	rsa:3072
SSL_ALG				:=	sha256
SSL_GEN				:=	2
#SSL_GEN			:=	5
SSL_MTH				:=	TLSv1_2_method
SSL_LST				:=	TLSv1.2+FIPS:kRSA+FIPS:!eNULL:!aNULL
SSL_SID				:=	com-diag-codex
SSL_DEP				:=	9
SSL_DHK				:=	2048
SSL_EXP				:=	365
SSL_SPW				:=	COM_DIAG_CODEX_SERVER_PASSWORD
SSL_CPW				:=	COM_DIAG_CODEX_CLIENT_PASSWORD
