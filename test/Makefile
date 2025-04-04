# SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#
# Copyright (c) 2024, Oracle and/or its affiliates.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public
# License v2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this program; if not, write to the
# Free Software Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 021110-1307, USA.
#

DEFAULT_TESTS = basic \
		getuid_setuid \
		getgid_setgid

TESTS = $(DEFAULT_TESTS)

LIBS = test_lib.sh

LDLIBS = -lpthread

LDFLAGS = -L../src

PROGS = getpid \
	getuid \
	getgid \
	getrusage

WRAPS = $(PROGS:%=-Wl,--wrap=%)

PROGSLINKED = $(PROGS:%=%_linked) gettid_linked

INSTALLFILES = $(DEFAULT_TESTS:%=%.sh) $(LIBS)

DESTDIR ?=
prefix ?= /usr
installprefix ?= $(DESTDIR)/$(prefix)

INSTALLPATH = $(installprefix)/lib/tcptune_test/

install_sh_PROGRAM = install
install_sh_DIR = install -dv

all: $(PROGS) $(PROGSLINKED)
	
PHONY: clean
	
clean:
	rm -f $(PROGS) $(PROGSLINKED)

test: $(TESTS)
	
test_perf: $(PERF_TESTS)

test_tuner: $(TUNER_TESTS)
	
install: $(INSTALLFILES)
	$(install_sh_DIR) -d $(INSTALLPATH) ; \
	$(install_sh_PROGRAM) $^ -t $(INSTALLPATH) ; \

$(TESTS): %:%.sh
	TEST_ID=$$PPID  bash $<

$(PROGS): %:%.c
	$(CC) $(CFLAGS) -o $@ $@.c $(LDFLAGS) $(LDLIBS)

$(PROGSLINKED): %_linked:%.c
	$(CC) $(CFLAGS) -o $@ $^ -lbysyscall $(WRAPS) $(LDFLAGS) $(LDLIBS)

PHONY: clean
