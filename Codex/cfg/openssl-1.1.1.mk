SSL_ROOT		:=	$(HOME)/src/openssl

SSL_CPPFLAGS	:=	-I$(SSL_ROOT)/include

SSL_LIBRARIES	:=	$(SSL_ROOT)

SSL_LDFLAGS		:=	-L$(SSL_LIBRARIES) -lssl -lcrypto

OPENSSL			:=	$(SSL_ROOT)/apps/openssl
C_REHASH		:=	$(SSL_ROOT)/tools/c_rehash
