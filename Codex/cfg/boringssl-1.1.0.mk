SSL_ROOT		:=	$(HOME)/src/boringssl

SSL_LIBRARIES	:=

SSL_CPPFLAGS	:=	-I$(SSL_ROOT)/include
SSL_SOFLAGS		:=	$(SSL_ROOT)/build/ssl/libssl.a $(SSL_ROOT)/build/crypto/libcrypto.a
SSL_LDFLAGS		:=	$(SSL_ROOT)/build/ssl/libssl.a $(SSL_ROOT)/build/crypto/libcrypto.a

OPENSSL			:=	openssl
C_REHASH		:=	c_rehash
