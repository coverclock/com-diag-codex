# Copyright 2018-2022 Digital Aggregates Corporation
# Licensed under the terms in LICENSE.txt
# author:Chip Overclock
# mailto:coverclock@diag.com
# https://github.com/coverclock/com-diag-codex
# "Chip Overclock" is a registered trademark.
# "Digital Aggregates Corporation" is a registered trademark.

# sudo apt-get install linux-headers-$(uname -r)

# host: most Linux/GNU systems hosting the native toolchain.

ARCH				:=	x86_64
OS					:=	linux
TOOLCHAIN			:=
KERNELCHAIN			:=
KERNEL_REV			:=	$(shell uname -r)
KERNEL_DIR			:=	/lib/modules/$(KERNEL_REV)/build
GNUARCH				:=	-D__USE_GNU -D_GNU_SOURCE
CPPARCH				:=	-isystem /usr/src/linux-headers-$(KERNEL_REV) $(GNUARCH)
CARCH				:=	-rdynamic -fPIC -Wall
LDARCH				:=	-L$(OUT)/$(LIB_DIR) -l$(PROJECT)
SOARCH				:=	-L$(OUT)/$(LIB_DIR)
KERNELARCH			:=
LDLIBRARIES			:=	-lm
