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

TARGET := fuzz_collector

PRJ_DIR = $(shell pwd)/..
DST_DIR ?= $(PRJ_DIR)/bin64
INC_DIR = $(PRJ_DIR)/include
SRC_DIR = $(PRJ_DIR)/src/linux

VPATH = $(SRC_DIR)

CXX = clang++

CFLAGS ?= -I$(INC_DIR)
CFLAGS += -I$(PRJ_DIR)/lib
CFLAGS += -g -fsanitize=address,fuzzer
LDFLAGS ?= -fsanitize=address,fuzzer

_DEPS = collector.hpp prof_options.hpp
DEPS = $(patsubst %,$(INC_DIR)/%,$(_DEPS))

LIB_DIR=$(PRJ_DIR)/lib

LIBS= -ldl
LDFLAGS += -L$(LIB_DIR)


OBJ = collector.o fuzz_collector.o

.PHONY: default all clean distclean install

default: all

all: $(TARGET)

clean:
	rm -f $(TARGET)
	rm -f *.o

distclean: clean
	rm -rf $(DST_DIR)

%.o: %.cpp $(DEPS)
	$(CXX) -c -o $@ $< $(CFLAGS)

$(TARGET): $(OBJ)
	$(CXX) -o $@ $^ $(CFLAGS) $(LDFLAGS) $(LIBS)
