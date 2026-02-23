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
# Usage:
#   make                          # build wolfmodel_verify
#   make WOLFSSL_ROOT=../../..    # if wolfSSL is not installed system-wide

CC     ?= gcc
CFLAGS += -Wall -Wextra -I../../include

# wolfSSL detection via pkg-config (fallback to standard paths)
WOLFSSL_PKG_CFLAGS := $(shell pkg-config --cflags wolfssl 2>/dev/null)
WOLFSSL_PKG_LIBS   := $(shell pkg-config --libs wolfssl 2>/dev/null)

ifneq ($(WOLFSSL_PKG_CFLAGS),)
  CFLAGS  += $(WOLFSSL_PKG_CFLAGS)
  LDFLAGS += $(WOLFSSL_PKG_LIBS)
else
  LDFLAGS += -lwolfssl
endif

ifdef WOLFSSL_ROOT
  CFLAGS += -I$(WOLFSSL_ROOT) -I$(WOLFSSL_ROOT)/include
endif

all: wolfmodel_verify

wolfmodel_verify: main.c ../../libwolfmodel.a
	$(CC) $(CFLAGS) -o $@ $< ../../libwolfmodel.a $(LDFLAGS)

clean:
	rm -f wolfmodel_verify

.PHONY: all clean
