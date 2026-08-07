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

DST_DIR ?= $(shell pwd)

.PHONY: default install clean distclean

default: install

install:
	cd lib && DST_DIR=$(DST_DIR)/lib64 $(MAKE) install
	cd src/linux && DST_DIR=$(DST_DIR)/bin64 $(MAKE) install

clean:
	cd lib && $(MAKE) clean
	cd src/linux && $(MAKE) clean

distclean:
	cd lib && DST_DIR=$(DST_DIR)/lib64 $(MAKE) distclean
	cd src/linux && DST_DIR=$(DST_DIR)/bin64 $(MAKE) distclean
