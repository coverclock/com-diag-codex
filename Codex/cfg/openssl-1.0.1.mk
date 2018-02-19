SSL_ROOT		:=	$(THERE)/openssl-1.0.1t

SSL_CPPFLAGS	:=	-I$(SSL_ROOT)/include

SSL_LIBRARIES	:=	$(SSL_ROOT)

SSL_ARCHIVES	:=

SSL_SOFLAGS		:=	-L$(SSL_LIBRARIES) -lssl -lcrypto
SSL_LDFLAGS		:=	-L$(SSL_LIBRARIES) -lssl -lcrypto

OPENSSL			:=	$(SSL_ROOT)/apps/openssl
C_REHASH		:=	perl $(SSL_ROOT)/tools/c_rehash
