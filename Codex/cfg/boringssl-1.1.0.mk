SSL_ROOT		:=	$(THERE)/boringssl

SSL_LIBRARIES	:=	$(SSL_ROOT)/build/ssl:$(SSL_ROOT)/build/crypto

SSL_CPPFLAGS	:=	-I$(SSL_ROOT)/include
SSL_SOFLAGS		:=	-L$(SSL_ROOT)/build/ssl -lssl -L$(SSL_ROOT)/build/crypto -lcrypto
SSL_LDFLAGS		:=	-L$(SSL_ROOT)/build/ssl -lssl -L$(SSL_ROOT)/build/crypto -lcrypto

OPENSSL			:=	openssl
C_REHASH		:=	c_rehash
