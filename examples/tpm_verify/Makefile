# Makefile
#
# Copyright (C) 2006-2025 wolfSSL Inc.
#
# This file is part of wolfModel.
#
# wolfModel is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfModel is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
#
# wolfModel + wolfTPM verification example
#
# Usage:
#   make                                      # build wolfmodel_tpm_verify
#   make WOLFSSL_ROOT=../../.. WOLFTPM_ROOT=../../..
#   make DEMO_ATTACK=1                        # enable attack demo
#   make clean

CC     ?= gcc
CFLAGS += -Wall -Werror -Wextra -I../../include

# wolfSSL detection via pkg-config (fallback to standard paths)
WOLFSSL_PKG_CFLAGS := $(shell pkg-config --cflags wolfssl 2>/dev/null)
WOLFSSL_PKG_LIBS   := $(shell pkg-config --libs wolfssl 2>/dev/null)

ifneq ($(WOLFSSL_PKG_CFLAGS),)
  CFLAGS  += $(WOLFSSL_PKG_CFLAGS)
  LDFLAGS += $(WOLFSSL_PKG_LIBS)
else
  LDFLAGS += -lwolfssl
endif

# wolfTPM detection via pkg-config (fallback to standard paths)
WOLFTPM_PKG_CFLAGS := $(shell pkg-config --cflags wolftpm 2>/dev/null)
WOLFTPM_PKG_LIBS   := $(shell pkg-config --libs wolftpm 2>/dev/null)

ifneq ($(WOLFTPM_PKG_CFLAGS),)
  CFLAGS  += $(WOLFTPM_PKG_CFLAGS)
  LDFLAGS += $(WOLFTPM_PKG_LIBS)
else
  LDFLAGS += -lwolftpm
endif

# Optional: wolfSSL source tree (for misc.c, user_settings.h, etc.)
ifdef WOLFSSL_ROOT
  CFLAGS += -I$(WOLFSSL_ROOT) -I$(WOLFSSL_ROOT)/include
endif

# Optional: wolfTPM source tree (for hal/tpm_io.h, examples/tpm_test.h)
ifdef WOLFTPM_ROOT
  CFLAGS  += -I$(WOLFTPM_ROOT) -I$(WOLFTPM_ROOT)/include
  LDFLAGS += -L$(WOLFTPM_ROOT)/src/.libs
endif

# Attack demo (compile with DEMO_ATTACK=1)
ifdef DEMO_ATTACK
  CFLAGS += -DWOLFMODEL_DEMO_ATTACK
endif

all: wolfmodel_tpm_verify

wolfmodel_tpm_verify: main.c ../../libwolfmodel.a
	$(CC) $(CFLAGS) -o $@ $< ../../libwolfmodel.a $(LDFLAGS)

clean:
	rm -f wolfmodel_tpm_verify

.PHONY: all clean
