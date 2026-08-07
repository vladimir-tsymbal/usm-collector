#
# Copyright (C) 2023 Intel Corporation
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License, as published
# by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.
#
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

TARGET := i915_mem

PRJ_DIR = $(shell pwd)/..
DST_DIR ?= $(PRJ_DIR)/lib64

LLC ?= llc
CLANG ?= clang
CC ?= gcc

LIBBPF_DIR=$(PRJ_DIR)/libbpf/src
LIBBPF_INSTALL_DIR=$(LIBBPF_DIR)/root
LIBBPF_STATIC_LIB = $(LIBBPF_INSTALL_DIR)/usr/lib64/libbpf.a

KERN_C = ${TARGET:=_kern.c}
KERN_OBJ = ${KERN_C:.c=.o}
USER_C = ${TARGET:=_user.c}
USER_H = ${TARGET:=_user.h}
USER_OBJ = ${USER_C:.c=.o}
USER_LIB = $(addprefix lib,${USER_OBJ:.o=.so})

CFLAGS ?= -I$(LIBBPF_INSTALL_DIR)/usr/include

SHARED_CFLAGS += -fPIC -shared

LDFLAGS ?= -L$(LIBBPF_INSTALL_DIR)/usr/lib64

LIBS = -lelf -lz

.PHONY: default all clean distclean install $(CLANG) $(LLC)

default: all

all: llvm-check $(KERN_OBJ) $(USER_LIB)

clean:
	rm -f $(USER_LIB)
	rm -f $(KERN_OBJ)
	rm -f $(USER_OBJ)
	rm -f *.ll
	rm -rf $(LIBBPF_INSTALL_DIR)
	cd $(LIBBPF_DIR) && $(MAKE) clean

distclean: clean
	rm -rf $(DST_DIR)

llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}"; \
			exit 1; \
		else true; fi; \
	done

$(LIBBPF_STATIC_LIB):
	@if [ ! -d $(LIBBPF_DIR) ]; then \
		echo "Error: Need libbpf submodule"; \
		echo "May need to run git submodule update --init"; \
		exit 1; \
	else \
		cd $(LIBBPF_DIR) && mkdir -p $(LIBBPF_INSTALL_DIR) && \
		DESTDIR=$(LIBBPF_INSTALL_DIR) BUILD_STATIC_ONLY=y EXTRA_CFLAGS=-fPIC $(MAKE) install; \
	fi

$(USER_LIB): $(USER_C) $(USER_H) $(LIBBPF_STATIC_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -fPIC  -Wl,-soname,$(USER_LIB) -o $(USER_LIB) -Wl,--whole-archive $(LIBBPF_STATIC_LIB) -Wl,--no-whole-archive $< $(LIBS)

$(KERN_OBJ): %.o: %.c $(LIBBPF_STATIC_LIB)
	$(CLANG) -S \
	    -D __BPF_TRACING__ \
	    $(CFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

install: llvm-check $(KERN_OBJ) $(USER_LIB)
	install -d $(DST_DIR)/
	install -m 775 $(USER_LIB) $(DST_DIR)/
	install -m 664 $(KERN_OBJ) $(DST_DIR)/
