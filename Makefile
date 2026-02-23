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
#   make                          # auto-detect wolfSSL, build libwolfmodel.a
#   make WOLFSSL_ROOT=../wolfssl  # use local wolfSSL source tree
#   make keytools                 # build signing/keygen tools
#   make test                     # build + run tests
#   make fixtures                 # generate test key + signed dummy model
#   make examples                 # build example programs
#   make install PREFIX=/usr/local
#   make CC=arm-none-eabi-gcc CFLAGS="-mcpu=cortex-m4 -mthumb"  # cross-compile

CC      ?= gcc
AR      ?= ar
CFLAGS  += -Wall -Werror -Wextra -Wdeclaration-after-statement
CFLAGS  += -Iinclude
LDFLAGS +=

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

# ------------------------------------------------------------------ #
# wolfSSL detection (3-tier, in priority order)                      #
# ------------------------------------------------------------------ #

# Tier 1: explicit WOLFSSL_ROOT (source tree — needed for misc.c include)
# Only adds include paths; library linking still uses pkg-config or -lwolfssl.
ifdef WOLFSSL_ROOT
  CFLAGS  += -I$(WOLFSSL_ROOT) -I$(WOLFSSL_ROOT)/include
  WOLFSSL_FOUND := 1
endif

# Tier 2: pkg-config (always try, even with WOLFSSL_ROOT, for link flags)
WOLFSSL_PKG_CFLAGS := $(shell pkg-config --cflags wolfssl 2>/dev/null)
WOLFSSL_PKG_LIBS   := $(shell pkg-config --libs wolfssl 2>/dev/null)
ifneq ($(WOLFSSL_PKG_CFLAGS),)
  ifndef WOLFSSL_FOUND
    CFLAGS  += $(WOLFSSL_PKG_CFLAGS)
  endif
  LDFLAGS += $(WOLFSSL_PKG_LIBS)
  WOLFSSL_FOUND := 1
endif

# Tier 2.5: macOS Homebrew detection
ifndef WOLFSSL_FOUND
  ifeq ($(UNAME_S),Darwin)
    BREW_PREFIX ?= $(shell brew --prefix 2>/dev/null)
    ifeq ($(BREW_PREFIX),)
      ifeq ($(UNAME_M),arm64)
        BREW_PREFIX := /opt/homebrew
      else
        BREW_PREFIX := /usr/local
      endif
    endif
    WOLFSSL_PREFIX := $(shell brew --prefix wolfssl 2>/dev/null)
    ifneq ($(WOLFSSL_PREFIX),)
      CFLAGS  += -I$(WOLFSSL_PREFIX)/include
      LDFLAGS += -L$(WOLFSSL_PREFIX)/lib -lwolfssl
      WOLFSSL_FOUND := 1
    endif
  endif
endif

# Tier 3: compile-probe (wolfIP-style)
ifndef WOLFSSL_FOUND
  HAVE_WOLFSSL := $(shell printf '#include <wolfssl/options.h>\nint main(void){return 0;}\n' \
                   | $(CC) $(CFLAGS) -x c - -c -o /dev/null 2>/dev/null && echo 1)
  ifeq ($(HAVE_WOLFSSL),1)
    LDFLAGS += -lwolfssl
    WOLFSSL_FOUND := 1
  endif
endif

# FreeBSD standard paths
ifeq ($(UNAME_S),FreeBSD)
  CFLAGS  += -I/usr/local/include
  LDFLAGS += -L/usr/local/lib
endif

# Require wolfSSL for build targets (not clean/cppcheck)
REQ_WOLFSSL_GOALS := $(filter-out clean cppcheck,$(MAKECMDGOALS))
ifeq ($(strip $(MAKECMDGOALS)),)
  REQ_WOLFSSL_GOALS := all
endif
ifneq ($(REQ_WOLFSSL_GOALS),)
  ifndef WOLFSSL_FOUND
    $(error wolfSSL not found. Set WOLFSSL_ROOT=<path>, install via package manager, or install to /usr/local)
  endif
endif

# Ensure -lwolfssl is in LDFLAGS if not already added
ifeq ($(findstring -lwolfssl,$(LDFLAGS)),)
  LDFLAGS += -lwolfssl
endif

# ------------------------------------------------------------------ #
# Build targets                                                      #
# ------------------------------------------------------------------ #

LIB     := libwolfmodel.a
OBJS    := build/wolfmodel.o
PREFIX  ?= /usr/local

.PHONY: all clean test fixtures keytools examples install cppcheck

all: $(LIB)

$(LIB): $(OBJS)
	@echo "[AR] $@"
	@$(AR) rcs $@ $^

build/wolfmodel.o: src/wolfmodel.c include/wolfmodel/wolfmodel.h
	@mkdir -p build
	@echo "[CC] $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# ------------------------------------------------------------------ #
# Key tools (C native, link against wolfCrypt — like wolfBoot)       #
# ------------------------------------------------------------------ #

keytools: build/wolfmodel_keygen build/wolfmodel_sign

build/wolfmodel_keygen: tools/keygen/keygen.c include/wolfmodel/wolfmodel.h
	@mkdir -p build
	@echo "[CC] tools/keygen/keygen.c"
	@$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

build/wolfmodel_sign: tools/sign/sign.c include/wolfmodel/wolfmodel.h
	@mkdir -p build
	@echo "[CC] tools/sign/sign.c"
	@$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# ------------------------------------------------------------------ #
# Test fixtures (uses C keytools)                                    #
# ------------------------------------------------------------------ #

FIXTURE_DIR := tests/fixtures

fixtures: build/wolfmodel_keygen build/wolfmodel_sign
	@mkdir -p $(FIXTURE_DIR)
	@echo "[KEYGEN] $(FIXTURE_DIR)/"
	@build/wolfmodel_keygen $(FIXTURE_DIR)
	@echo "[GEN] $(FIXTURE_DIR)/dummy.bin"
	@dd if=/dev/urandom of=$(FIXTURE_DIR)/dummy.bin bs=1024 count=4 2>/dev/null
	@echo "[SIGN] $(FIXTURE_DIR)/dummy.wmdl"
	@build/wolfmodel_sign \
		--key $(FIXTURE_DIR)/ecc256.der \
		--image $(FIXTURE_DIR)/dummy.bin \
		--output $(FIXTURE_DIR)/dummy.wmdl \
		--version 1 --type tflite
	@echo "Fixtures generated OK."

# ------------------------------------------------------------------ #
# Tests                                                              #
# ------------------------------------------------------------------ #

test: $(LIB)
	@echo "[CC] tests/wolfmodel_test.c"
	@$(CC) $(CFLAGS) -o build/wolfmodel_test \
		tests/wolfmodel_test.c $(LIB) $(LDFLAGS) -lm
	@echo "[TEST] build/wolfmodel_test"
	@build/wolfmodel_test

# ------------------------------------------------------------------ #
# Examples                                                           #
# ------------------------------------------------------------------ #

examples: $(LIB)
	@echo "[CC] examples/basic_verify/main.c"
	@$(CC) $(CFLAGS) -o build/wolfmodel_verify \
		examples/basic_verify/main.c $(LIB) $(LDFLAGS)
	@echo "Built: build/wolfmodel_verify"

# ------------------------------------------------------------------ #
# Install                                                            #
# ------------------------------------------------------------------ #

install: $(LIB)
	install -d $(PREFIX)/lib $(PREFIX)/include/wolfmodel
	install -m 644 $(LIB) $(PREFIX)/lib/
	install -m 644 include/wolfmodel/wolfmodel.h $(PREFIX)/include/wolfmodel/

# ------------------------------------------------------------------ #
# Static analysis                                                    #
# ------------------------------------------------------------------ #

CPPCHECK      := cppcheck
CPPCHECK_FLAGS := --enable=warning,performance,portability \
                  --suppress=missingIncludeSystem \
                  --suppress=unmatchedSuppression \
                  --std=c99 --language=c \
                  --error-exitcode=1

cppcheck:
	$(CPPCHECK) $(CPPCHECK_FLAGS) -Iinclude src/

# ------------------------------------------------------------------ #
# Clean                                                              #
# ------------------------------------------------------------------ #

clean:
	rm -rf build/ $(LIB)
