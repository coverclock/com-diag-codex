# vi: set ts=4 shiftwidth=4:
# Copyright 2018-2025 Digital Aggregates Corporation
# Licensed under the terms in LICENSE.txt
# author:Chip Overclock
# mailto:coverclock@diag.com
# https://github.com/coverclock/com-diag-codex
# "Chip Overclock" is a registered trademark.
# "Digital Aggregates Corporation" is a registered trademark.
#
#	make all [ TARGET=<target> ] [ FLAVOR=<flavor> ]	# Build libraries, unit tests, executables.
#
#	. out/host/bin/setup								# Sets up PATH and LD_LIBRARY_PATH for testing.
#

.PHONY:	default

default:	all

########## Customizations

TITLE				:=	Codex
PROJECT				:=	$(shell echo $(TITLE) | tr '[A-Z]' '[a-z]')
SYMBOL				:=	$(shell echo $(TITLE) | tr '[a-z]' '[A-Z]')

MAJOR				:=	11# API changes that may require that applications be modified.
MINOR				:=	0# Only functionality or features added with no legacy API changes.
BUILD				:=	0# Only bugs fixed with no API changes or new functionality.

# Disclaimer: the only target that I routinely build and test for is "host".

TARGET				:=	host

# Only very specific versions of selected SSL libraries are supported. You can
# change the default here, or pass the FLAVOR in as a parameter to make: e.g.
# make pristine depend all FLAVOR=boringssl-1.1.0 .

FLAVOR				:=	openssl
#FLAVOR				:=	openssl-1.0.1
#FLAVOR				:=	boringssl-1.1.0
#FLAVOR				:=	openssl-1.1.1

# Some certification, defense, or intelligence agencies (e.g. the U.S. Federal
# Aviation Administration or FAA) require that software builds for safety
# critical or national security applications generate exactly the same binary
# images bit for bit if the source code has not changed. (This is theoretically
# a more stringent requirement than requiring that checksums or cryptographic
# hashes are the same, although in practice it is the same thing.) This allows
# agency inspectors to verify the integrity of the binary software images. This
# makes embedding build timestamps inside compiled translation units problematic.
# If your application has this requirement, you can pass in any fixed string
# for the value of the VINTAGE make variable, and only use the value of this
# symbol as a build time stamp, and you should be able to generate identical
# images with subsequent builds of Codex. This string is embedded inside the
# Codex "vintage" application. The default build time stamp is an ISO-8601
# complaint string with the time specified in UTC with nanosecond resolution.

# This stuff all gets embedded in the vintage application.
COPYRIGHT			:=	2018-2025 Digital Aggregates Corporation
LICENSE				:=	GNU Lesser General Public License 2.1
CONTACT				:=	coverclock@diag.com
HOMEPAGE			:=	https://github.com/coverclock/com-diag-$(PROJECT)
HOST				:=	$(shell hostname -s)
BRANCH				:=	$(shell git rev-parse --abbrev-ref HEAD)
REVISION			:=	$(shell git rev-parse HEAD)
MODIFIED			:=	$(shell date -u -d @$(shell git log -1 --format="%at") +%Y-%m-%dT%H:%M:%S.%N%z)
ROOT				:=	$(shell git rev-parse --show-toplevel)
VINTAGE				:=	$(shell date -u +%Y-%m-%dT%H:%M:%S.%N%z)

# This is where I store collateral associated with projects that I have
# downloaded off the web and use without alteration. Examples: Linux kernel
# sources, toolchains, etc.
HOME_DIR			:=	$(HOME)/Projects

########## Directories

APP_DIR             :=  app# Application source directories
ARC_DIR				:=	arc# Archive files for static linking
BIN_DIR				:=	bin# Utility source files or stripped executable binaries
CFG_DIR				:=	cfg# Build configuration files
CRL_DIR				:=	crl# Certificate revocation lists
CRT_DIR				:=	crt# Certificate files
DEP_DIR				:=	dep# Generated dependencies and other make files
DOC_DIR				:=	doc# Documentation
ETC_DIR				:=	etc# Miscellaneous files
FUN_DIR				:=	fun# Functional tests
GEN_DIR				:=	gen# Generated source files
INC_DIR				:=	inc# Header files
LIB_DIR				:=	lib# Shared objects for dynamic linking
OBC_DIR				:=	obc# C object modules
OUT_DIR				:=	out# Build artifacts
PWD_DIR				:=	pwd# Password files
SRC_DIR				:=	src# Library source files
SYM_DIR				:=	sym# Unstripped executable binaries
TGZ_DIR				:=	tgz# Compressed tarballs
TST_DIR				:=	tst# Unit tests
TXT_DIR				:=	txt# Text files

########## Configuration

HERE				:=	$(shell pwd)
THERE				:=	$(shell realpath ../..)

OUT					:=	$(OUT_DIR)/$(TARGET)

TEMP_DIR			:=	/tmp
ROOT_DIR			:=	$(HOME_DIR)/$(TARGET)

GITURL				:=	https://github.com/coverclock/com-diag-$(PROJECT).git

GENERATED			:=	vintage generate setup
SYNTHESIZED			:=	$(PROJECT)_release.h $(PROJECT)_vintage.h $(PROJECT)_revision.h

ALIASES				:=	

NEW					:=	dummy
OLD					:=	dummy

PACKAGE				:=	$(OUT)/$(TGZ_DIR)/$(PROJECT)-$(TARGET)

MANIFEST			:=	$(APP_DIR) $(ARC_DIR) $(BIN_DIR) $(INC_DIR) $(LIB_DIR) $(TST_DIR) $(FUN_DIR)

DISTRIBUTION		:=	$(OUT)/$(TGZ_DIR)/$(PROJECT)-$(MAJOR).$(MINOR).$(BUILD)

TARBALL				:=	$(OUT)/$(TGZ_DIR)/$(PROJECT)

PROJECT_A			:=	lib$(PROJECT).a
PROJECT_SO			:=	lib$(PROJECT).so

CDEFINES			:=

# Typically for unit and functional testing this is the
# name of the build host, but your mileage may vary.
HOSTNAME			:=	$(shell hostname -s)

########## Target Makefile

TARGETMAKEFILE		:= $(CFG_DIR)/$(TARGET).mk

include $(TARGETMAKEFILE)

########## Flavor Configuration

FLAVORMAKEFILE		:= $(CFG_DIR)/$(FLAVOR).mk

include $(FLAVORMAKEFILE)

########## Project Makefile

PROJECTMAKEFILE		:= $(CFG_DIR)/$(PROJECT).mk

include $(PROJECTMAKEFILE)

########## Diminuto Makefile

DIMINUTO_TITLE		:=	Diminuto
DIMINUTO_PROJECT	:=	$(shell echo $(DIMINUTO_TITLE) | tr '[A-Z]' '[a-z]')
DIMINUTO_SYMBOL		:=	$(shell echo $(DIMINUTO_TITLE) | tr '[a-z]' '[A-Z]')

DIMINUTOMAKEFILE	:= $(CFG_DIR)/$(DIMINUTO_PROJECT).mk

include $(DIMINUTOMAKEFILE)

########## Codex Configuration

SSL_CRL				:=	$(OUT)/$(CRL_DIR)
SSL_CRT				:=	$(OUT)/$(CRT_DIR)
SSL_ETC				:=	$(OUT)/$(ETC_DIR)
SSL_PWD				:=	$(OUT)/$(PWD_DIR)
SSL_TXT				:=	$(OUT)/$(TXT_DIR)

CDEFINES			+=	-DCOM_DIAG_CODEX_CERTIFICATE_DEPTH=$(SSL_DEP)
CDEFINES			+=	-DCOM_DIAG_CODEX_CIPHER_LIST=\"$(SSL_LST)\"
CDEFINES			+=	-DCOM_DIAG_CODEX_CLIENT_PASSWORD_ENV=\"$(SSL_CPW)\"
CDEFINES			+=	-DCOM_DIAG_CODEX_METHOD=$(SSL_MTH)
CDEFINES			+=	-DCOM_DIAG_CODEX_SELF_SIGNED_CERTIFICATES=$(SSL_SSC)
CDEFINES			+=	-DCOM_DIAG_CODEX_SERVER_PASSWORD_ENV=\"$(SSL_SPW)\"
CDEFINES			+=	-DCOM_DIAG_CODEX_SESSION_ID_CONTEXT=\"$(SSL_SID)\"

########## Commands and Option Flags

CROSS_COMPILE		:=	$(TOOLCHAIN)

CC					:=	$(CROSS_COMPILE)gcc
AR					:=	$(CROSS_COMPILE)ar
RANLIB				:=	$(CROSS_COMPILE)ranlib
STRIP				:=	$(CROSS_COMPILE)strip

SOLIBRARIES			:=	$(SSL_SOFLAGS) $(DIMINUTO_SOFLAGS)
LDLIBRARIES			:=	$(SSL_LDFLAGS) $(DIMINUTO_LDFLAGS)

ARFLAGS				:=	crsv
CPPFLAGS			:=	$(CDEFINES) -iquote $(SRC_DIR) -iquote $(INC_DIR) -iquote $(OUT)/$(INC_DIR) $(SSL_CPPFLAGS) $(DIMINUTO_CPPFLAGS) $(CPPARCH)
CFLAGS				:=	$(CARCH) -g
CPFLAGS				:=	-i
MVFLAGS				:=	-i
LDFLAGS				:=	$(LDARCH) $(LDLIBRARIES)
SOFLAGS				:=	$(SOARCH) $(SOLIBRARIES)

########## Build Artifacts

TARGETAPPLICATIONS  :=  $(addprefix $(OUT)/,$(basename $(wildcard $(APP_DIR)/*)))

TARGETOBJECTS		:=	$(addprefix $(OUT)/$(OBC_DIR)/,$(addsuffix .o,$(basename $(wildcard $(SRC_DIR)/*.c))))

TARGETSCRIPTS		:=	$(addprefix $(OUT)/,$(basename $(wildcard $(BIN_DIR)/*.sh)))

TARGETBINARIES		:=	$(addprefix $(OUT)/,$(basename $(wildcard $(BIN_DIR)/*.c)))

TARGETGENERATED		:=	$(addprefix $(OUT)/$(BIN_DIR)/,$(GENERATED))
TARGETGENERATED		+=	$(addprefix $(OUT)/$(SYM_DIR)/,$(GENERATED))

TARGETSYNTHESIZED	:=	$(addprefix $(OUT)/$(INC_DIR)/com/diag/$(PROJECT)/,$(SYNTHESIZED))

TARGETALIASES		:=	$(addprefix $(OUT)/$(BIN_DIR)/,$(ALIASES))

TARGETUNITTESTS		:=	$(addprefix $(OUT)/,$(basename $(wildcard $(TST_DIR)/*.c)))
TARGETUNITTESTS		+=	$(addprefix $(OUT)/,$(basename $(wildcard $(TST_DIR)/*.sh)))
TARGETUNITTESTS		+=	$(addprefix $(OUT)/,$(wildcard $(TST_DIR)/*.awk))
TARGETUNITTESTS		+=	$(addprefix $(OUT)/,$(wildcard $(TST_DIR)/*.r))

TARGETFUNCTIONALS   :=  $(addprefix $(OUT)/,$(basename $(wildcard $(FUN_DIR)/*.c)))
TARGETFUNCTIONALS   +=  $(addprefix $(OUT)/,$(basename $(wildcard $(FUN_DIR)/*.sh)))

TARGETARCHIVE		:=	$(OUT)/$(ARC_DIR)/$(PROJECT_A)

TARGETSHARED		:=	$(OUT)/$(LIB_DIR)/$(PROJECT_SO).$(MAJOR).$(MINOR)
TARGETSHARED		+=	$(OUT)/$(LIB_DIR)/$(PROJECT_SO).$(MAJOR)
TARGETSHARED		+=	$(OUT)/$(LIB_DIR)/$(PROJECT_SO)

TARGETCONFIGS		:= $(wildcard $(ETC_DIR)/*.cnf)

TARGETCREDENTIALS	:=	$(addprefix $(SSL_TXT)/,$(addsuffix .txt,$(notdir $(basename $(wildcard $(ETC_DIR)/*.cnf)))))

TARGETPARAMETERS	:=	$(SSL_CRT)/dh.pem

TARGETPASSWORDS     :=  $(addprefix $(SSL_PWD)/,$(addsuffix .pwd,$(notdir $(basename $(wildcard $(ETC_DIR)/*.cnf)))))

TARGETREVOCATIONS	:=	$(SSL_CRL)/crl.txt
TARGETREVOCATIONS	+=	$(SSL_CRL)/crltwo.txt

TARGETLIBRARIES		:=	$(TARGETARCHIVE) $(TARGETSHARED)

TARGETPROGRAMS		:=	$(TARGETAPPLICATIONS) $(TARGETBINARIES) $(TARGETALIASES) $(TARGETUNITTESTS) $(TARGETGENERATED) $(TARGETSCRIPTS) $(TARGETFUNCTIONALS)

TARGETALL			:=	$(TARGETLIBRARIES) $(TARGETPROGRAMS) $(TARGETCONFIGS) $(TARGETCREDENTIALS) $(TARGETPASSWORDS) $(TARGETREVOCATIONS) $(TARGETPARAMETERS)

########## Troubleshooting Entry Points

show:
	echo NAMES
	echo $(notdir $(basename $(wildcard $(ETC_DIR)/*.cnf)))
	echo CONFIGS
	echo $(TARGETCONFIGS)
	echo CREDENTIALS
	echo $(TARGETCREDENTIALS)
	echo PASSWORDS
	echo $(TARGETPASSWORDS)

list:
	echo CONFIGS
	ls -l $(TARGETCONFIGS)
	echo CREDENTIALS
	ls -l $(TARGETCREDENTIALS)
	echo PASSWORDS
	ls -l $(TARGETPASSWORDS)

########## Main Entry Points

.PHONY:	all dist tidy clean pristine scratch clobber

all:	$(TARGETALL)

dist:	distribution

tidy:
	rm -rf $(OUT)/arc $(OUT)/bin $(OUT)/inc $(OUT)/lib $(OUT)/obc $(OUT)/sym $(OUT)/tst

clean:
	rm -rf $(OUT)

pristine:
	rm -rf $(OUT_DIR)

# This is not the same as simply listing the targets as dependencies.
scratch:
	make pristine
	make depend
	make all

clobber:	pristine
	rm -f .cscope.lst .cscope.out .cscope.out.in .cscope.out.po
	rm -rf *.gcda *.gcno *.gcov

########## Certificate and Key Generation (primarily for unit testing)

.PHONY:	credentials credentials-clean parameters parameters-clean passwords passwords-clean

##### Configurations

$(SSL_ETC)/%.cnf:	$(ETC_DIR)/%.cnf
	D=`dirname $@`; mkdir -p $$D
	sed -e 's/MYHOSTNAME/$(HOSTNAME)/g' $< > $@
	chmod 600 $@

##### Passwords

$(SSL_PWD)/%.pwd:	$(ETC_DIR)/%.cnf
	D=`dirname $@`; mkdir -p $$D
	grep output_password $< | sed -e 's/^.*=[ \t]*//' -e 's/#.*$$//' > $@
	chmod 600 $@

##### Text Dumps

$(SSL_TXT)/%.txt:	$(SSL_CRT)/%.pem
	D=`dirname $@`; mkdir -p $$D
	$(OPENSSL) x509 -text -noout -in $< > $@
	chmod 600 $@

##### Root

$(SSL_CRT)/rootreq.pem:	$(SSL_ETC)/root.cnf
	D=`dirname $@`; mkdir -p $$D
	$(OPENSSL) req -config $(SSL_ETC)/root.cnf -newkey $(SSL_KEY) -$(SSL_ALG) -keyout $(SSL_CRT)/rootkey.pem -out $@
	chmod 600 $@
	chmod 600 $(SSL_CRT)/rootkey.pem

$(SSL_CRT)/rootkey.pem:	$(SSL_CRT)/rootreq.pem

$(SSL_CRT)/rootcert.pem:	$(SSL_CRT)/rootreq.pem $(SSL_ETC)/root.cnf $(SSL_CRT)/rootkey.pem $(SSL_PWD)/root.pwd
	D=`dirname $@`; mkdir -p $$D
	$(OPENSSL) x509 -req -days $(SSL_EXP) -in $(SSL_CRT)/rootreq.pem -$(SSL_ALG) -extfile $(SSL_ETC)/root.cnf -extensions v3_ca -signkey $(SSL_CRT)/rootkey.pem -passin file:$(SSL_PWD)/root.pwd -out $@
	$(C_REHASH) $(SSL_CRT)
	ls --full-time $(SSL_CRT)
	chmod 600 $@

$(SSL_CRT)/root.pem:	$(SSL_CRT)/rootkey.pem $(SSL_CRT)/rootcert.pem
	D=`dirname $@`; mkdir -p $$D
	cat $^ > $@
	$(C_REHASH) $(SSL_CRT)
	$(OPENSSL) x509 -subject -issuer -noout -in $@
	chmod 600 $@

##### Certificate Authority

$(SSL_CRT)/careq.pem:	$(SSL_ETC)/ca.cnf
	D=`dirname $@`; mkdir -p $$D
	$(OPENSSL) req -config $(SSL_ETC)/ca.cnf -newkey $(SSL_KEY) -$(SSL_ALG) -keyout $(SSL_CRT)/cakey.pem -out $@
	chmod 600 $@
	chmod 600 $(SSL_CRT)/cakey.pem

$(SSL_CRT)/cakey.pem:	$(SSL_CRT)/careq.pem

$(SSL_CRT)/cacert.pem:	$(SSL_CRT)/careq.pem $(SSL_ETC)/ca.cnf $(SSL_CRT)/root.pem $(SSL_PWD)/root.pwd
	D=`dirname $@`; mkdir -p $$D
	$(OPENSSL) x509 -req -days $(SSL_EXP) -in $(SSL_CRT)/careq.pem -$(SSL_ALG) -extfile $(SSL_ETC)/ca.cnf -extensions v3_ca -CA $(SSL_CRT)/root.pem -passin file:$(SSL_PWD)/root.pwd -CAkey $(SSL_CRT)/root.pem -CAcreateserial -out $@
	$(C_REHASH) $(SSL_CRT)
	chmod 600 $@

$(SSL_CRT)/ca.pem:	$(SSL_CRT)/cacert.pem $(SSL_CRT)/cakey.pem $(SSL_CRT)/rootcert.pem
	D=`dirname $@`; mkdir -p $$D
	cat $^ > $@
	$(C_REHASH) $(SSL_CRT)
	$(OPENSSL) x509 -subject -issuer -noout -in $@
	chmod 600 $@

##### Server

$(SSL_CRT)/serverreq.pem:	$(SSL_ETC)/server.cnf
	D=`dirname $@`; mkdir -p $$D
	$(OPENSSL) req -config $(SSL_ETC)/server.cnf -newkey $(SSL_KEY) -$(SSL_ALG) -keyout $(SSL_CRT)/serverkey.pem -out $@
	chmod 600 $@
	chmod 600 $(SSL_CRT)/serverkey.pem

$(SSL_CRT)/serverkey.pem:	$(SSL_CRT)/serverreq.pem

$(SSL_CRT)/servercert.pem:	$(SSL_CRT)/serverreq.pem $(SSL_ETC)/server.cnf $(SSL_CRT)/ca.pem $(SSL_PWD)/ca.pwd
	D=`dirname $@`; mkdir -p $$D
	$(OPENSSL) x509 -req -days $(SSL_EXP) -in $(SSL_CRT)/serverreq.pem -$(SSL_ALG) -extfile $(SSL_ETC)/server.cnf -extensions usr_cert -CA $(SSL_CRT)/ca.pem -passin file:$(SSL_PWD)/ca.pwd -CAkey $(SSL_CRT)/ca.pem -CAcreateserial -out $@
	$(C_REHASH) $(SSL_CRT)
	chmod 600 $@

$(SSL_CRT)/server.pem:	$(SSL_CRT)/servercert.pem $(SSL_CRT)/serverkey.pem $(SSL_CRT)/cacert.pem $(SSL_CRT)/rootcert.pem
	D=`dirname $@`; mkdir -p $$D
	cat $^ > $@
	$(C_REHASH) $(SSL_CRT)
	$(OPENSSL) x509 -subject -issuer -noout -in $@
	chmod 600 $@

##### Client

$(SSL_CRT)/clientreq.pem:	$(SSL_ETC)/client.cnf
	D=`dirname $@`; mkdir -p $$D
	$(OPENSSL) req -config $(SSL_ETC)/client.cnf -newkey $(SSL_KEY) -$(SSL_ALG) -keyout $(SSL_CRT)/clientkey.pem -out $@
	chmod 600 $@
	chmod 600 $(SSL_CRT)/clientkey.pem

$(SSL_CRT)/clientkey.pem:	$(SSL_CRT)/clientreq.pem

$(SSL_CRT)/clientcert.pem:	$(SSL_CRT)/clientreq.pem $(SSL_ETC)/client.cnf $(SSL_CRT)/root.pem $(SSL_PWD)/root.pwd
	D=`dirname $@`; mkdir -p $$D
	$(OPENSSL) x509 -req -days $(SSL_EXP) -in $(SSL_CRT)/clientreq.pem -$(SSL_ALG) -extfile $(SSL_ETC)/client.cnf -extensions usr_cert -CA $(SSL_CRT)/root.pem -passin file:$(SSL_PWD)/root.pwd -CAkey $(SSL_CRT)/root.pem -CAcreateserial -out $@
	$(C_REHASH) $(SSL_CRT)
	chmod 600 $@

$(SSL_CRT)/client.pem:	$(SSL_CRT)/clientcert.pem $(SSL_CRT)/clientkey.pem $(SSL_CRT)/rootcert.pem
	D=`dirname $@`; mkdir -p $$D
	cat $^ > $@
	$(C_REHASH) $(SSL_CRT)
	$(OPENSSL) x509 -subject -issuer -noout -in $@
	chmod 600 $@

##### Bogus

$(SSL_CRT)/bogusreq.pem:	$(SSL_ETC)/bogus.cnf
	D=`dirname $@`; mkdir -p $$D
	$(OPENSSL) req -config $(SSL_ETC)/bogus.cnf -newkey $(SSL_KEY) -$(SSL_ALG) -keyout $(SSL_CRT)/boguskey.pem -out $@
	chmod 600 $@
	chmod 600 $(SSL_CRT)/boguskey.pem

$(SSL_CRT)/boguskey.pem:	$(SSL_CRT)/bogusreq.pem

$(SSL_CRT)/boguscert.pem:	$(SSL_CRT)/bogusreq.pem $(SSL_ETC)/bogus.cnf $(SSL_CRT)/root.pem $(SSL_PWD)/root.pwd
	D=`dirname $@`; mkdir -p $$D
	$(OPENSSL) x509 -req -days $(SSL_EXP) -in $(SSL_CRT)/bogusreq.pem -$(SSL_ALG) -extfile $(SSL_ETC)/bogus.cnf -extensions usr_cert -CA $(SSL_CRT)/root.pem -passin file:$(SSL_PWD)/root.pwd -CAkey $(SSL_CRT)/root.pem -CAcreateserial -out $@
	$(C_REHASH) $(SSL_CRT)
	chmod 600 $@

$(SSL_CRT)/bogus.pem:	$(SSL_CRT)/boguscert.pem $(SSL_CRT)/boguskey.pem $(SSL_CRT)/rootcert.pem
	D=`dirname $@`; mkdir -p $$D
	cat $^ > $@
	$(C_REHASH) $(SSL_CRT)
	$(OPENSSL) x509 -subject -issuer -noout -in $@
	chmod 600 $@

##### Self-signed

$(SSL_CRT)/selfcert.pem:	$(SSL_ETC)/self.cnf
	D=`dirname $@`; mkdir -p $$D
	$(OPENSSL) req -new -x509 -config $(SSL_ETC)/self.cnf -extensions usr_cert -newkey $(SSL_KEY) -nodes -$(SSL_ALG) -keyout $(SSL_CRT)/selfkey.pem -out $@
	chmod 600 $@
	chmod 600 $(SSL_CRT)/selfkey.pem

$(SSL_CRT)/selfkey.pem:	$(SSL_CRT)/selfcert.pem

$(SSL_CRT)/self.pem:	$(SSL_CRT)/selfcert.pem $(SSL_CRT)/selfkey.pem
	D=`dirname $@`; mkdir -p $$D
	cat $^ > $@
	$(C_REHASH) $(SSL_CRT)
	$(OPENSSL) x509 -subject -issuer -noout -in $@
	chmod 600 $@

##### Revoked

$(SSL_CRT)/revokedreq.pem:	$(SSL_ETC)/revoked.cnf
	D=`dirname $@`; mkdir -p $$D
	$(OPENSSL) req -config $(SSL_ETC)/revoked.cnf -newkey $(SSL_KEY) -$(SSL_ALG) -keyout $(SSL_CRT)/revokedkey.pem -out $@
	chmod 600 $@
	chmod 600 $(SSL_CRT)/revokedkey.pem

$(SSL_CRT)/revokedkey.pem:	$(SSL_CRT)/revokedreq.pem

$(SSL_CRT)/revokedcert.pem:	$(SSL_CRT)/revokedreq.pem $(SSL_ETC)/revoked.cnf $(SSL_CRT)/root.pem $(SSL_PWD)/root.pwd
	D=`dirname $@`; mkdir -p $$D
	$(OPENSSL) x509 -req -days $(SSL_EXP) -in $(SSL_CRT)/revokedreq.pem -$(SSL_ALG) -extfile $(SSL_ETC)/revoked.cnf -extensions usr_cert -CA $(SSL_CRT)/root.pem -passin file:$(SSL_PWD)/root.pwd -CAkey $(SSL_CRT)/root.pem -CAcreateserial -out $@
	$(C_REHASH) $(SSL_CRT)
	chmod 600 $@

$(SSL_CRT)/revoked.pem:	$(SSL_CRT)/revokedcert.pem $(SSL_CRT)/revokedkey.pem $(SSL_CRT)/rootcert.pem
	D=`dirname $@`; mkdir -p $$D
	cat $^ > $@
	$(C_REHASH) $(SSL_CRT)
	$(OPENSSL) x509 -subject -issuer -noout -in $@
	chmod 600 $@

##### Revoked Too

$(SSL_CRT)/revokedtooreq.pem:	$(SSL_ETC)/revokedtoo.cnf
	D=`dirname $@`; mkdir -p $$D
	$(OPENSSL) req -config $(SSL_ETC)/revokedtoo.cnf -newkey $(SSL_KEY) -$(SSL_ALG) -keyout $(SSL_CRT)/revokedtookey.pem -out $@
	chmod 600 $@
	chmod 600 $(SSL_CRT)/revokedtookey.pem

$(SSL_CRT)/revokedtookey.pem:	$(SSL_CRT)/revokedtooreq.pem

$(SSL_CRT)/revokedtoocert.pem:	$(SSL_CRT)/revokedtooreq.pem $(SSL_ETC)/revokedtoo.cnf $(SSL_CRT)/root.pem $(SSL_PWD)/root.pwd
	D=`dirname $@`; mkdir -p $$D
	$(OPENSSL) x509 -req -days $(SSL_EXP) -in $(SSL_CRT)/revokedtooreq.pem -$(SSL_ALG) -extfile $(SSL_ETC)/revokedtoo.cnf -extensions usr_cert -CA $(SSL_CRT)/root.pem -passin file:$(SSL_PWD)/root.pwd -CAkey $(SSL_CRT)/root.pem -CAcreateserial -out $@
	$(C_REHASH) $(SSL_CRT)
	chmod 600 $@

$(SSL_CRT)/revokedtoo.pem:	$(SSL_CRT)/revokedtoocert.pem $(SSL_CRT)/revokedtookey.pem $(SSL_CRT)/rootcert.pem
	D=`dirname $@`; mkdir -p $$D
	cat $^ > $@
	$(C_REHASH) $(SSL_CRT)
	$(OPENSSL) x509 -subject -issuer -noout -in $@
	chmod 600 $@

##### Certificate Revocation List

$(SSL_CRL)/crl.txt:	$(SSL_CRT)/revoked.pem $(SSL_CRT)/revokedtoo.pem
	D=`dirname $@`; mkdir -p $$D
	cp /dev/null $@
	for F in $^; do openssl x509 -in $$F -serial -noout | sed 's/^serial=//' >> $@; done
	chmod 600 $@

$(SSL_CRL)/crltwo.txt:	$(SSL_CRL)/crl.txt
	cat $< $< > $@
	chmod 600 $@

##### Diffie Hellman Parameters

# dhparam -out seems to be broken in OpenSSL 1.1.0 in Raspbian stretch.

$(SSL_CRT)/dh.pem:
	D=`dirname $@`; mkdir -p $$D
	$(OPENSSL) dhparam -check -text -$(SSL_GEN) -out $@ $(SSL_DHK) > $@.tmp
	test -f $@ || mv $@.tmp $@
	chmod 600 $@

##### Helpers

.PHONY:	credentials credentials-clean

credentials:	$(TARGETCREDENTIALS)

credentials-clean:
	( cd $(SSL_CRT); rm -f rootcert.pem rootkey.pem root.pem rootreq.pem root.srl )
	( cd $(SSL_CRT); rm -f cacert.pem cakey.pem ca.pem careq.pem ca.srl )
	( cd $(SSL_CRT); rm -f servercert.pem serverkey.pem server.pem serverreq.pem )
	( cd $(SSL_CRT); rm -f clientkey.pem client.pem clientreq.pem )
	( cd $(SSL_CRT); rm -f boguskey.pem bogus.pem bogusreq.pem )
	( cd $(SSL_CRT); rm -f selfkey.pem self.pem selfreq.pem )
	( cd $(SSL_CRT); rm -f revokedkey.pem revoked.pem revokedreq.pem )
	( cd $(SSL_CRT); rm -f revokedtookey.pem revokedtoo.pem revokedtooreq.pem )
	( cd $(SSL_CRL); rm -f crl.txt crltwo.txt )
	
.PHONY:	parameters parameters-clean

parameters:	 $(TARGETPARAMETERS)

parameters-clean:
	( cd $(SSL_CRT); rm -f dh.pem )
	
.PHONY:	passwords passwords-clean

passwords:	$(TARGETPASSWORDS)

passwords-clean:
	( cd $(SSL_PWD); rm -f ./*.pwd )

.PHONY:	exported

# The certificate authorities for the far end have to be something the near end
# trusts. Otherwise the handshake between the peers fails. The easiest way to do
# this for testing is to generate the credentials on the near end, and propagate
# them to the far end *before* the far end credentials are generated. This is
# basically what occurs when you install a root certificate using your browser.
# This helper uses scp(1) to copy the near end root certificate to the far end,
# where it will be used to sign the far end's credentials.
# E.g. make exported FAREND="pi@lead"

FAREND="root@192.0.2.0"

FARPATH=$(shell eval D=`realpath $(SSL_CRT)`; eval H="$(HOME)/"; eval P=$${D#$$H}; echo $$P)

exported:	$(SSL_CRT)/rootcert.pem $(SSL_CRT)/rootkey.pem $(SSL_CRT)/root.pem $(SSL_CRT)/rootreq.pem $(SSL_CRT)/root.srl $(SSL_CRT)/cacert.pem $(SSL_CRT)/cakey.pem $(SSL_CRT)/ca.pem $(SSL_CRT)/careq.pem $(SSL_CRT)/ca.srl
	echo "You will have to enter the password to ${FAREND} *twice*."
	D=`realpath $(SSL_CRT)`; H="$(HOME)/"; P=$${D#$$H}; \
	ssh $(FAREND) mkdir -p $$P; \
	scp $(SSL_CRT)/root* ${SSL_CRT}/ca* $(FAREND):$$P

########## Target C Libraries

$(OUT)/$(ARC_DIR)/$(PROJECT_A):	$(TARGETOBJECTS)
	D=`dirname $@`; mkdir -p $$D
	$(AR) $(ARFLAGS) $@ $^
	$(RANLIB) $@

$(OUT)/$(LIB_DIR)/$(PROJECT_SO).$(MAJOR).$(MINOR):	$(TARGETOBJECTS)
	D=`dirname $@`; mkdir -p $$D
	$(CC) $(CFLAGS) -shared -Wl,-soname,$(PROJECT_SO).$(MAJOR).$(MINOR) -o $@ $(SOFLAGS) $(TARGETOBJECTS)

$(OUT)/$(LIB_DIR)/$(PROJECT_SO).$(MAJOR):	$(OUT)/$(LIB_DIR)/$(PROJECT_SO).$(MAJOR).$(MINOR)
	D=`dirname $<`; F=`basename $<`; T=`basename $@`; ( cd $$D; ln -s -f $$F $$T ) 

$(OUT)/$(LIB_DIR)/$(PROJECT_SO):	$(OUT)/$(LIB_DIR)/$(PROJECT_SO).$(MAJOR)
	D=`dirname $<`; F=`basename $<`; T=`basename $@`; ( cd $$D; ln -s -f $$F $$T ) 


########## Target Unstripped Applications

$(OUT)/$(APP_DIR)/%:    $(APP_DIR)/% $(TARGETLIBRARIES)
	D=`dirname $@`; mkdir -p $$D
	$(CC) -iquote $< $(CPPFLAGS) $(CFLAGS) -o $@ $</*.c $(LDFLAGS)

########## Target Unstripped Binaries

$(OUT)/$(SYM_DIR)/%:	$(OUT)/$(OBC_DIR)/$(BIN_DIR)/%.o $(TARGETLIBRARIES)
	D=`dirname $@`; mkdir -p $$D
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

########## Unit Tests

$(OUT)/$(TST_DIR)/%:	$(OUT)/$(OBC_DIR)/$(TST_DIR)/%.o $(TARGETLIBRARIES)
	D=`dirname $@`; mkdir -p $$D
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

########## Functional Tests

$(OUT)/$(FUN_DIR)/%:	$(OUT)/$(OBC_DIR)/$(FUN_DIR)/%.o $(TARGETLIBRARIES)
	D=`dirname $@`; mkdir -p $$D
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

########## Generated Source Files

# For embedding in a system where it can be executed from a shell.
#
# The major.minor.build is emitted to standard error, a bunch more
# metadata to standard output. Hence, they can be redirected to separate
# files.
#
# Some of the information in this binary executable may be sensitive, for
# example, the Directory or the User. That's why it's in a form that doesn't
# have to be distributed with the product, unlike the shared objects.
#
# This program also serves as a unit test, so be careful about removing stuff
# from it that looks redundant or unused.
#
# The stdout stream from vintage is designed so that you can source it
# into a variety of tools including bash. e.g. eval $(vintage 2> /dev/null) .
#
# NOTE: in the generated C code below, whether you should have \\n or \n in the
# echo statements seems to depend on what version of make you are running. I
# tried (elsewhere) to automate that decision, but for reasons I haven't taken
# the time to understand, that mechanism quit working just recently.

SLASHES=2

ifeq ($(SLASHES), 1)

$(OUT)/$(GEN_DIR)/vintage.c:	Makefile
	@echo MAKE_VERSION=$(MAKE_VERSION) SLASHES=$(SLASHES)
	D=`dirname $@`; mkdir -p $$D
	echo '/* GENERATED FILE! DO NOT EDIT! */' > $@
	echo '#include "com/diag/$(PROJECT)/$(PROJECT)_release.h"' >> $@
	echo '#include "com/diag/$(PROJECT)/$(PROJECT)_release.h"' >> $@
	echo '#include "com/diag/$(PROJECT)/$(PROJECT)_vintage.h"' >> $@
	echo '#include "com/diag/$(PROJECT)/$(PROJECT)_vintage.h"' >> $@
	echo '#include "com/diag/$(PROJECT)/$(PROJECT)_revision.h"' >> $@
	echo '#include "com/diag/$(PROJECT)/$(PROJECT)_revision.h"' >> $@
	echo '#include <stdio.h>' >> $@
	echo '#include <assert.h>' >> $@
	echo 'static const char METADATA[] =' >> $@
	echo '    "Arch=\"$(ARCH)\"\n"' >> $@
	echo '    "Branch=\"$(BRANCH)\"\n"' >> $@
	echo '    "Contact=\"$(CONTACT)\"\n"' >> $@
	echo '    "Copyright=\"$(COPYRIGHT)\"\n"' >> $@
	echo '    "Flavor=\"$(FLAVOR)\"\n"' >> $@
	echo '    "Homepage=\"$(HOMEPAGE)\"\n"' >> $@
	echo '    "Repository=\"$(GITURL)\"\n"' >> $@
	echo '    "Host=\"$(HOST)\"\n"' >> $@
	echo '    "Kernel=\"$(KERNEL_REV)\"\n"' >> $@
	echo '    "License=\"$(LICENSE)\"\n"' >> $@
	echo '    "Modified=\"$(MODIFIED)\"\n"' >> $@
	echo '    "Os=\"$(OS)\"\n"' >> $@
	echo '    "Release=\"" COM_DIAG_$(SYMBOL)_RELEASE "\"\n"' >> $@
	echo '    "Revision=\"" COM_DIAG_$(SYMBOL)_REVISION "\"\n"' >> $@
	echo '    "Root=\"$(ROOT)\"\n"' >> $@
	echo '    "Target=\"$(TARGET)\"\n"' >> $@
	echo '    "Title=\"$(TITLE)\"\n"' >> $@
	echo '    "Toolchain=\"$(TOOLCHAIN)\"\n"' >> $@
	echo '    "User=\"$(USER)\"\n"' >> $@
	echo '    "Vintage=\"" COM_DIAG_$(SYMBOL)_VINTAGE "\"\n"' >> $@
	echo ';' >> $@
	echo 'extern const char COM_DIAG_$(SYMBOL)_RELEASE_KEYWORD[];' >> $@
	echo 'extern const char * COM_DIAG_$(SYMBOL)_RELEASE_VALUE;' >> $@
	echo 'extern const char COM_DIAG_$(SYMBOL)_VINTAGE_KEYWORD[];' >> $@
	echo 'extern const char * COM_DIAG_$(SYMBOL)_VINTAGE_VALUE;' >> $@
	echo 'extern const char COM_DIAG_$(SYMBOL)_REVISION_KEYWORD[];' >> $@
	echo 'extern const char * COM_DIAG_$(SYMBOL)_REVISION_VALUE;' >> $@
	echo 'int main(void) {' >> $@
	echo '    const char * release_keyword = (const char *)0;' >> $@
	echo '    const char * release_value = (const char *)0;' >> $@
	echo '    const char * vintage_keyword = (const char *)0;' >> $@
	echo '    const char * vintage_value = (const char *)0;' >> $@
	echo '    const char * revision_keyword = (const char *)0;' >> $@
	echo '    const char * revision_value = (const char *)0;' >> $@
	echo '    fputs(METADATA, stdout);' >> $@
	echo '    fputs("$(MAJOR).$(MINOR).$(BUILD)\n", stderr);' >> $@
	echo '    release_keyword = COM_DIAG_$(SYMBOL)_RELEASE_KEYWORD;' >> $@
	echo '    release_value = COM_DIAG_$(SYMBOL)_RELEASE_VALUE;' >> $@
	echo '    vintage_keyword = COM_DIAG_$(SYMBOL)_VINTAGE_KEYWORD;' >> $@
	echo '    vintage_value = COM_DIAG_$(SYMBOL)_VINTAGE_VALUE;' >> $@
	echo '    revision_keyword = COM_DIAG_$(SYMBOL)_REVISION_KEYWORD;' >> $@
	echo '    revision_value = COM_DIAG_$(SYMBOL)_REVISION_VALUE;' >> $@
	echo '    assert(release_keyword != (const char *)0);' >> $@
	echo '    assert(release_value != (const char *)0);' >> $@
	echo '    assert(vintage_keyword != (const char *)0);' >> $@
	echo '    assert(vintage_value != (const char *)0);' >> $@
	echo '    assert(release_keyword != (const char *)0);' >> $@
	echo '    assert(release_value != (const char *)0);' >> $@
	echo '    return 0;' >> $@
	echo '}' >> $@

endif

ifeq ($(SLASHES), 2)

$(OUT)/$(GEN_DIR)/vintage.c:	Makefile
	@echo MAKE_VERSION=$(MAKE_VERSION) SLASHES=$(SLASHES)
	D=`dirname $@`; mkdir -p $$D
	echo '/* GENERATED FILE! DO NOT EDIT! */' > $@
	echo '#include "com/diag/$(PROJECT)/$(PROJECT)_release.h"' >> $@
	echo '#include "com/diag/$(PROJECT)/$(PROJECT)_release.h"' >> $@
	echo '#include "com/diag/$(PROJECT)/$(PROJECT)_vintage.h"' >> $@
	echo '#include "com/diag/$(PROJECT)/$(PROJECT)_vintage.h"' >> $@
	echo '#include "com/diag/$(PROJECT)/$(PROJECT)_revision.h"' >> $@
	echo '#include "com/diag/$(PROJECT)/$(PROJECT)_revision.h"' >> $@
	echo '#include <stdio.h>' >> $@
	echo '#include <assert.h>' >> $@
	echo 'static const char METADATA[] =' >> $@
	echo '    "Arch=\\"$(ARCH)\\"\\n"' >> $@
	echo '    "Branch=\\"$(BRANCH)\\"\\n"' >> $@
	echo '    "Contact=\\"$(CONTACT)\\"\\n"' >> $@
	echo '    "Copyright=\\"$(COPYRIGHT)\\"\\n"' >> $@
	echo '    "Flavor=\\"$(FLAVOR)\\"\\n"' >> $@
	echo '    "Homepage=\\"$(HOMEPAGE)\\"\\n"' >> $@
	echo '    "Repository=\\"$(GITURL)\\"\\n"' >> $@
	echo '    "Host=\\"$(HOST)\\"\\n"' >> $@
	echo '    "Kernel=\\"$(KERNEL_REV)\\"\\n"' >> $@
	echo '    "License=\\"$(LICENSE)\\"\\n"' >> $@
	echo '    "Modified=\\"$(MODIFIED)\\"\\n"' >> $@
	echo '    "Os=\\"$(OS)\\"\\n"' >> $@
	echo '    "Release=\\"" COM_DIAG_$(SYMBOL)_RELEASE "\\"\\n"' >> $@
	echo '    "Revision=\\"" COM_DIAG_$(SYMBOL)_REVISION "\\"\\n"' >> $@
	echo '    "Root=\\"$(ROOT)\\"\\n"' >> $@
	echo '    "Target=\\"$(TARGET)\\"\\n"' >> $@
	echo '    "Title=\\"$(TITLE)\\"\\n"' >> $@
	echo '    "Toolchain=\\"$(TOOLCHAIN)\\"\\n"' >> $@
	echo '    "User=\\"$(USER)\\"\\n"' >> $@
	echo '    "Vintage=\\"" COM_DIAG_$(SYMBOL)_VINTAGE "\\"\\n"' >> $@
	echo ';' >> $@
	echo 'extern const char COM_DIAG_$(SYMBOL)_RELEASE_KEYWORD[];' >> $@
	echo 'extern const char * COM_DIAG_$(SYMBOL)_RELEASE_VALUE;' >> $@
	echo 'extern const char COM_DIAG_$(SYMBOL)_VINTAGE_KEYWORD[];' >> $@
	echo 'extern const char * COM_DIAG_$(SYMBOL)_VINTAGE_VALUE;' >> $@
	echo 'extern const char COM_DIAG_$(SYMBOL)_REVISION_KEYWORD[];' >> $@
	echo 'extern const char * COM_DIAG_$(SYMBOL)_REVISION_VALUE;' >> $@
	echo 'int main(void) {' >> $@
	echo '    const char * release_keyword = (const char *)0;' >> $@
	echo '    const char * release_value = (const char *)0;' >> $@
	echo '    const char * vintage_keyword = (const char *)0;' >> $@
	echo '    const char * vintage_value = (const char *)0;' >> $@
	echo '    const char * revision_keyword = (const char *)0;' >> $@
	echo '    const char * revision_value = (const char *)0;' >> $@
	echo '    fputs(METADATA, stdout);' >> $@
	echo '    fputs("$(MAJOR).$(MINOR).$(BUILD)\\n", stderr);' >> $@
	echo '    release_keyword = COM_DIAG_$(SYMBOL)_RELEASE_KEYWORD;' >> $@
	echo '    release_value = COM_DIAG_$(SYMBOL)_RELEASE_VALUE;' >> $@
	echo '    vintage_keyword = COM_DIAG_$(SYMBOL)_VINTAGE_KEYWORD;' >> $@
	echo '    vintage_value = COM_DIAG_$(SYMBOL)_VINTAGE_VALUE;' >> $@
	echo '    revision_keyword = COM_DIAG_$(SYMBOL)_REVISION_KEYWORD;' >> $@
	echo '    revision_value = COM_DIAG_$(SYMBOL)_REVISION_VALUE;' >> $@
	echo '    assert(release_keyword != (const char *)0);' >> $@
	echo '    assert(release_value != (const char *)0);' >> $@
	echo '    assert(vintage_keyword != (const char *)0);' >> $@
	echo '    assert(vintage_value != (const char *)0);' >> $@
	echo '    assert(revision_keyword != (const char *)0);' >> $@
	echo '    assert(revision_value != (const char *)0);' >> $@
	echo '    return 0;' >> $@
	echo '}' >> $@

endif

# For embedding in an application where it can be interrogated or displayed.
$(OUT)/$(INC_DIR)/com/diag/$(PROJECT)/$(PROJECT)_release.h:	Makefile
	D=`dirname $@`; mkdir -p $$D
	echo '/* GENERATED FILE! DO NOT EDIT! */' > $@
	echo '#ifndef _H_COM_DIAG_$(SYMBOL)_RELEASE_' >> $@
	echo '#define _H_COM_DIAG_$(SYMBOL)_RELEASE_' >> $@
	echo '#define COM_DIAG_$(SYMBOL)_RELEASE_MAJOR $(MAJOR)' >> $@
	echo '#define COM_DIAG_$(SYMBOL)_RELEASE_MINOR $(MINOR)' >> $@
	echo '#define COM_DIAG_$(SYMBOL)_RELEASE_BUILD $(BUILD)' >> $@
	echo '#define COM_DIAG_$(SYMBOL)_RELEASE "$(MAJOR).$(MINOR).$(BUILD)"' >> $@
	echo '#endif' >> $@

# For embedding in the library archive and shared object.
$(OUT)/$(OBC_DIR)/$(SRC_DIR)/$(PROJECT)_release.o:	$(OUT)/$(INC_DIR)/com/diag/$(PROJECT)/$(PROJECT)_release.h

# For embedding in an application where it can be interrogated or displayed.
$(OUT)/$(INC_DIR)/com/diag/$(PROJECT)/$(PROJECT)_vintage.h:	Makefile
	D=`dirname $@`; mkdir -p $$D
	echo '/* GENERATED FILE! DO NOT EDIT! */' > $@
	echo '#ifndef _H_COM_DIAG_$(SYMBOL)_VINTAGE_' >> $@
	echo '#define _H_COM_DIAG_$(SYMBOL)_VINTAGE_' >> $@
	echo '#define COM_DIAG_$(SYMBOL)_VINTAGE "$(VINTAGE)"' >> $@
	echo '#endif' >> $@

# For embedding in the library archive and shared object.
$(OUT)/$(OBC_DIR)/$(SRC_DIR)/$(PROJECT)_vintage.o:	$(OUT)/$(INC_DIR)/com/diag/$(PROJECT)/$(PROJECT)_vintage.h

# For embedding in an application where it can be interrogated or displayed.
$(OUT)/$(INC_DIR)/com/diag/$(PROJECT)/$(PROJECT)_revision.h:	Makefile
	D=`dirname $@`; mkdir -p $$D
	echo '/* GENERATED FILE! DO NOT EDIT! */' > $@
	echo '#ifndef _H_COM_DIAG_$(SYMBOL)_REVISION_' >> $@
	echo '#define _H_COM_DIAG_$(SYMBOL)_REVISION_' >> $@
	echo '#define COM_DIAG_$(SYMBOL)_REVISION "$(REVISION)"' >> $@
	echo '#endif' >> $@

# For embedding in the library archive and shared object.
$(OUT)/$(OBC_DIR)/$(SRC_DIR)/$(PROJECT)_revision.o:	$(OUT)/$(INC_DIR)/com/diag/$(PROJECT)/$(PROJECT)_revision.h

# For executing from the command line during testing.
$(OUT)/$(SYM_DIR)/vintage:	$(OUT)/$(GEN_DIR)/vintage.c
	D=`dirname $@`; mkdir -p $$D
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(LDFLAGS)

# For generating a setup script for a bash shell (for example, "bash generate > setup").
# (Because the Android bash doesn't seem to implement BASH_ARGV.)
$(OUT)/$(BIN_DIR)/generate:	Makefile
	D=`dirname $@`; mkdir -p $$D
	echo 'COM_DIAG_$(SYMBOL)_PATH=`dirname $$0`; COM_DIAG_$(SYMBOL)_ROOT=`cd $$COM_DIAG_$(SYMBOL)_PATH; pwd`' > $@
	echo 'echo export PATH=\\$$PATH:$$COM_DIAG_$(SYMBOL)_ROOT/../$(APP_DIR):$$COM_DIAG_$(SYMBOL)_ROOT/../$(BIN_DIR):$$COM_DIAG_$(SYMBOL)_ROOT/../$(TST_DIR):$$COM_DIAG_$(SYMBOL)_ROOT/../$(FUN_DIR)' >> $@
	echo 'echo export LD_LIBRARY_PATH=\\$$LD_LIBRARY_PATH:$$COM_DIAG_$(SYMBOL)_ROOT/../$(LIB_DIR):$(SSL_LIBRARIES)' >> $@
	echo 'echo export COM_DIAG_$(SYMBOL)_CLIENT_PASSWORD=\`cat $$COM_DIAG_$(SYMBOL)_ROOT/../$(PWD_DIR)/client.pwd\`' >> $@
	echo 'echo export COM_DIAG_$(SYMBOL)_SERVER_PASSWORD=\`cat $$COM_DIAG_$(SYMBOL)_ROOT/../$(PWD_DIR)/server.pwd\`' >> $@
	echo 'echo . $(DIMINUTO_ROOT)/$(OUT)/$(BIN_DIR)/setup' >> $@
	chmod 775 $@

# For generating a setup script for a bash shell (for example, "bash generate > setup").
# (Because the Android bash doesn't seem to implement BASH_ARGV.)
$(OUT)/$(SYM_DIR)/generate:	Makefile
	D=`dirname $@`; mkdir -p $$D
	echo 'COM_DIAG_$(SYMBOL)_PATH=`dirname $$0`; COM_DIAG_$(SYMBOL)_ROOT=`cd $$COM_DIAG_$(SYMBOL)_PATH; pwd`' > $@
	echo 'echo export PATH=\\$$PATH:$$COM_DIAG_$(SYMBOL)_ROOT/../$(APP_DIR):$$COM_DIAG_$(SYMBOL)_ROOT/../$(SYM_DIR):$$COM_DIAG_$(SYMBOL)_ROOT/../$(BIN_DIR):$$COM_DIAG_$(SYMBOL)_ROOT/../$(TST_DIR):$$COM_DIAG_$(SYMBOL)_ROOT/../$(FUN_DIR)' >> $@
	echo 'echo export LD_LIBRARY_PATH=\\$$LD_LIBRARY_PATH:$$COM_DIAG_$(SYMBOL)_ROOT/../$(LIB_DIR):$(SSL_LIBRARIES)' >> $@
	echo 'echo export COM_DIAG_$(SYMBOL)_CLIENT_PASSWORD=\`cat $$COM_DIAG_$(SYMBOL)_ROOT/../$(PWD_DIR)/client.pwd\`' >> $@
	echo 'echo export COM_DIAG_$(SYMBOL)_SERVER_PASSWORD=\`cat $$COM_DIAG_$(SYMBOL)_ROOT/../$(PWD_DIR)/server.pwd\`' >> $@
	echo 'echo . $(DIMINUTO_ROOT)/$(OUT)/$(SYM_DIR)/setup' >> $@
	chmod 775 $@

# For sourcing into a bash shell (for example, ". out/host/bin/setup").
$(OUT)/$(BIN_DIR)/setup:	$(OUT)/$(BIN_DIR)/generate
	$< > $@
	chmod 664 $@

# For sourcing into a bash shell (for example, ". out/host/sym/setup").
$(OUT)/$(SYM_DIR)/setup:	$(OUT)/$(SYM_DIR)/generate
	$< > $@
	chmod 664 $@

########## Helpers

.PHONY:	makeversion gccversion implicit defines iquotes isystems

makeversion:
	@echo $(MAKE_VERSION)

gccversion:
	@$(CC) -x c $(CPPFLAGS) $(CFLAGS) -E -v - < /dev/null

implicit:
	@$(CC) $(CFLAGS) -dM -E - < /dev/null
	
defines:
	@$(CC) $(CPPFLAGS) $(CFLAGS) -dM -E - < /dev/null

iquotes:
	@$(CC) -x c $(CPPFLAGS) $(CFLAGS) -E -v - < /dev/null 2>&1 | awk 'BEGIN { S=0; } ($$0=="#include \"...\" search starts here:") { S=1; next; } ($$0=="#include <...> search starts here:") { S=0; next; } (S!=0) { print $$1; } { next; }'

isystems:
	@$(CC) -x c $(CPPFLAGS) $(CFLAGS) -E -v - < /dev/null 2>&1 | awk 'BEGIN { S=0; } ($$0=="#include <...> search starts here:") { S=1; next; } ($$0=="End of search list.") { S=0; next; } (S!=0) { print $$1; } { next; }'

########## Documentation

# sudo apt-get install doxygen
# sudo apt-get install ghostscript
# sudo apt-get install latex
# sudo apt-get install texlive
# sudo apt-get install tabu
# sudo apt-get install texlive-latex-extra

.PHONY:	documentation manuals readme

DOCCOOKED := $(shell echo $(OUT)/$(DOC_DIR) | sed 's/\//\\\//g')

documentation $(OUT)/$(DOC_DIR)/latex $(OUT)/$(DOC_DIR)/man $(OUT)/$(DOC_DIR)/pdf:
	mkdir -p $(OUT)/$(DOC_DIR)/pdf
	cat doxygen.cf | \
		sed -e "s/\\\$$PROJECT_NUMBER\\\$$/$(MAJOR).$(MINOR).$(BUILD)/" | \
		sed -e "s/\\\$$OUTPUT_DIRECTORY\\\$$/$(DOCCOOKED)/" | \
		cat > $(OUT)/$(DOC_DIR)/doxygen-local.cf
	doxygen $(OUT)/$(DOC_DIR)/doxygen-local.cf

manuals:	$(OUT)/$(DOC_DIR)/latex $(OUT)/$(DOC_DIR)/man $(OUT)/$(DOC_DIR)/pdf
	$(MAKE) -C $(OUT)/$(DOC_DIR)/latex refman.pdf || exit 0
	cp $(OUT)/$(DOC_DIR)/latex/refman.pdf $(OUT)/$(DOC_DIR)/pdf
	cat $(OUT)/$(DOC_DIR)/man/man3/*.3 | groff -man -Tps - > $(OUT)/$(DOC_DIR)/pdf/manpages.ps
	ps2pdf $(OUT)/$(DOC_DIR)/pdf/manpages.ps $(OUT)/$(DOC_DIR)/pdf/manpages.pdf

$(OUT)/$(DOC_DIR)/html/README.html:	../README.md
	mkdir -p $(OUT)/$(DOC_DIR)/html
	grip ../README.md --export $(OUT)/$(DOC_DIR)/html/README.html

readme:	$(OUT)/$(DOC_DIR)/html/README.html

########## Diffs and Patches

.PHONY:	patch

patch:	$(OLD) $(NEW)
	diff -purN $(OLD) $(NEW)

########## Rules

$(OUT)/$(OBC_DIR)/%.txt:	%.c $(TARGETSYNTHESIZED)
	D=`dirname $@`; mkdir -p $$D
	$(CC) -E $(CPPFLAGS) -c $< > $@

$(OUT)/$(OBC_DIR)/%.o:	%.c $(TARGETSYNTHESIZED)
	D=`dirname $@`; mkdir -p $$D
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ -c $<

$(OUT)/%:	%.sh
	D=`dirname $@`; mkdir -p $$D
	cp $< $@
	chmod 755 $@

$(OUT)/%.awk:	%.awk
	D=`dirname $@`; mkdir -p $$D
	cp $< $@
	chmod 644 $@

$(OUT)/%.r:	%.r
	D=`dirname $@`; mkdir -p $$D
	cp $< $@
	chmod 644 $@

.SECONDARY:

$(OUT)/$(BIN_DIR)/%:	$(OUT)/$(SYM_DIR)/%
	D=`dirname $@`; mkdir -p $$D
	$(STRIP) -o $@ $<

########## Dependencies

.PHONY:	depend

DEPENDENCIES := $(OUT)/$(DEP_DIR)/dependencies.mk

depend:	$(TARGETSYNTHESIZED)
	M=`dirname $(DEPENDENCIES)`; mkdir -p $$M
	cp /dev/null $(DEPENDENCIES)
	for S in $(APP_DIR)/* $(BIN_DIR) $(SRC_DIR) $(TST_DIR) $(FUN_DIR); do \
		if [ -d $$S ]; then \
			for F in $$S/*.c; do \
				D=`dirname $$F`; \
				T=`mktemp "$(TEMP_DIR)/$(PROJECT).XXXXXXXXXX"`; \
				echo -n "$(OUT)/$(OBC_DIR)/$$D/" > $$T; \
				$(CC) $(CPPFLAGS) -MM -MG $$F >> $$T && cat $$T >> $(DEPENDENCIES); \
				rm -f $$T; \
			done; \
		fi; \
	done

-include $(DEPENDENCIES)

########## Installation

.PHONY:	install install-bin install-lib install-include

INSTALL_DIR := /usr/local
INSTALL_BIN := $(INSTALL_DIR)/bin
INSTALL_LIB := $(INSTALL_DIR)/lib
INSTALL_INC := $(INSTALL_DIR)/include

install:	install-bin install-lib install-include

install-bin:
	mkdir -p $(INSTALL_BIN)
	for B in $(OUT)/$(BIN_DIR)/*; do \
		install $$B $(INSTALL_BIN); \
	done

install-lib:
	mkdir -p $(INSTALL_LIB)
	for F in $(OUT)/$(LIB_DIR)/*.so; do \
		O=`basename $$F`; \
		cp $(OUT)/$(LIB_DIR)/$$O.$(MAJOR).$(MINOR) $(INSTALL_LIB); \
		( cd $(INSTALL_LIB); ln -s -f $$O.$(MAJOR).$(MINOR) $$O.$(MAJOR) ); \
		( cd $(INSTALL_LIB); ln -s -f $$O.$(MAJOR) $$O ); \
	done
	ldconfig -v $(INSTALL_LIB)

install-include:
	mkdir -p $(INSTALL_INC)
	tar -C $(OUT)/$(INC_DIR) -cvf - . | tar -C $(INSTALL_INC) -xvf -
	tar -C $(INC_DIR) -cvf - . | tar -C $(INSTALL_INC) -xvf -

########## Sanity Tests

.PHONY: sanity-test failures-test functional-test extra-test

sanity-test:
	echo "TEST SANITY" 1>&2
	unittest-sanity
	unittest-noverification-client
	unittest-noverification-server
	unittest-noverification-bogus
	unittest-noverification-self
	unittest-noverification-revoked

# Once I moved to OpenSSL 3.0.2 I had to put in some delay in between
# the unit tests to allow the socket to shutdown and the port to be
# recycled.

failures-test:
	echo "TEST FAILURES" 1>&2
	unittest-verification-client && false || true
	sleep 60
	unittest-verification-server && false || true
	sleep 60
	unittest-verification-bogus && false || true
	sleep 60
	unittest-verification-self && false || true
	sleep 60
	unittest-verification-noself && false || true
	sleep 60
	unittest-verification-revoked && false || true

# These take a while.

functional-test:
	echo "TEST FUNCTIONAL" 1>&2
	unittest-core
	unittest-machine

# The control feature runs a unit test with the same
# programming model as the SSL unit tests but without
# using SSL. It it doesn't work, the other unit tests
# aren't expected to work.

extra-test:
	echo "TEST EXTRA" 1>&2
	unittest-control

tests:	sanity-test failures-test functional-test extra-test
	echo "COMPLETE" 1>&2

##### Build certificates etc. for Wheatstone.

$(SSL_CRT)/wheatstone-serverreq.pem:	$(SSL_ETC)/wheatstone-server.cnf
	D=`dirname $@`; mkdir -p $$D
	$(OPENSSL) req -config $(SSL_ETC)/wheatstone-server.cnf -newkey $(SSL_KEY) -$(SSL_ALG) -keyout $(SSL_CRT)/wheatstone-serverkey.pem -out $@
	chmod 600 $@
	chmod 600 $(SSL_CRT)/wheatstone-serverkey.pem

$(SSL_CRT)/wheatstone-serverkey.pem:	$(SSL_CRT)/wheatstone-servercert.pem

$(SSL_CRT)/wheatstone-servercert.pem:	$(SSL_CRT)/wheatstone-serverreq.pem $(SSL_ETC)/wheatstone-server.cnf $(SSL_CRT)/ca.pem $(SSL_PWD)/ca.pwd
	D=`dirname $@`; mkdir -p $$D
	$(OPENSSL) x509 -req -days $(SSL_EXP) -in $(SSL_CRT)/wheatstone-serverreq.pem -$(SSL_ALG) -extfile $(SSL_ETC)/wheatstone-server.cnf -extensions usr_cert -CA $(SSL_CRT)/ca.pem -passin file:$(SSL_PWD)/ca.pwd -CAkey $(SSL_CRT)/ca.pem -CAcreateserial -out $@
	$(C_REHASH) $(SSL_CRT)
	chmod 600 $@

$(SSL_CRT)/wheatstone-server.pem:	$(SSL_CRT)/wheatstone-servercert.pem $(SSL_CRT)/wheatstone-serverkey.pem $(SSL_CRT)/cacert.pem $(SSL_CRT)/rootcert.pem
	D=`dirname $@`; mkdir -p $$D
	cat $^ > $@
	$(C_REHASH) $(SSL_CRT)
	$(OPENSSL) x509 -subject -issuer -noout -in $@
	chmod 600 $@

$(SSL_CRT)/wheatstone-clientcert.pem:	$(SSL_ETC)/wheatstone-client.cnf
	D=`dirname $@`; mkdir -p $$D
	$(OPENSSL) req -new -x509 -config $(SSL_ETC)/wheatstone-client.cnf -extensions usr_cert -newkey $(SSL_KEY) -nodes -$(SSL_ALG) -keyout $(SSL_CRT)/wheatstone-clientkey.pem -out $@
	chmod 600 $@
	chmod 600 $(SSL_CRT)/wheatstone-clientkey.pem

$(SSL_CRT)/wheatstone-clientkey.pem:	$(SSL_CRT)/wheatstone-clientcert.pem

$(SSL_CRT)/wheatstone-client.pem:	$(SSL_CRT)/wheatstone-clientcert.pem $(SSL_CRT)/wheatstone-clientkey.pem
	D=`dirname $@`; mkdir -p $$D
	cat $^ > $@
	$(C_REHASH) $(SSL_CRT)
	$(OPENSSL) x509 -subject -issuer -noout -in $@
	chmod 600 $@

##### Build certificates etc. for Stagecoach.

$(SSL_CRT)/stagecoach-serverreq.pem:	$(SSL_ETC)/stagecoach-server.cnf
	D=`dirname $@`; mkdir -p $$D
	$(OPENSSL) req -config $(SSL_ETC)/stagecoach-server.cnf -newkey $(SSL_KEY) -$(SSL_ALG) -keyout $(SSL_CRT)/stagecoach-serverkey.pem -out $@
	chmod 600 $@
	chmod 600 $(SSL_CRT)/stagecoach-serverkey.pem

$(SSL_CRT)/stagecoach-serverkey.pem:	$(SSL_CRT)/stagecoach-servercert.pem

$(SSL_CRT)/stagecoach-servercert.pem:	$(SSL_CRT)/stagecoach-serverreq.pem $(SSL_ETC)/stagecoach-server.cnf $(SSL_CRT)/ca.pem $(SSL_PWD)/ca.pwd
	D=`dirname $@`; mkdir -p $$D
	$(OPENSSL) x509 -req -days $(SSL_EXP) -in $(SSL_CRT)/stagecoach-serverreq.pem -$(SSL_ALG) -extfile $(SSL_ETC)/stagecoach-server.cnf -extensions usr_cert -CA $(SSL_CRT)/ca.pem -passin file:$(SSL_PWD)/ca.pwd -CAkey $(SSL_CRT)/ca.pem -CAcreateserial -out $@
	$(C_REHASH) $(SSL_CRT)
	chmod 600 $@

$(SSL_CRT)/stagecoach-server.pem:	$(SSL_CRT)/stagecoach-servercert.pem $(SSL_CRT)/stagecoach-serverkey.pem $(SSL_CRT)/cacert.pem $(SSL_CRT)/rootcert.pem
	D=`dirname $@`; mkdir -p $$D
	cat $^ > $@
	$(C_REHASH) $(SSL_CRT)
	$(OPENSSL) x509 -subject -issuer -noout -in $@
	chmod 600 $@

$(SSL_CRT)/stagecoach-clientcert.pem:	$(SSL_ETC)/stagecoach-client.cnf
	D=`dirname $@`; mkdir -p $$D
	$(OPENSSL) req -new -x509 -config $(SSL_ETC)/stagecoach-client.cnf -extensions usr_cert -newkey $(SSL_KEY) -nodes -$(SSL_ALG) -keyout $(SSL_CRT)/stagecoach-clientkey.pem -out $@
	chmod 600 $@
	chmod 600 $(SSL_CRT)/stagecoach-clientkey.pem

$(SSL_CRT)/stagecoach-clientkey.pem:	$(SSL_CRT)/stagecoach-clientcert.pem

$(SSL_CRT)/stagecoach-client.pem:	$(SSL_CRT)/stagecoach-clientcert.pem $(SSL_CRT)/stagecoach-clientkey.pem
	D=`dirname $@`; mkdir -p $$D
	cat $^ > $@
	$(C_REHASH) $(SSL_CRT)
	$(OPENSSL) x509 -subject -issuer -noout -in $@
	chmod 600 $@
