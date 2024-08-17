# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# Copyright (c) 2022, Oracle and/or its affiliates.

SRCARCH := $(shell uname -m | sed -e s/i.86/x86/ -e s/x86_64/x86/ \
                                  -e /arm64/!s/arm.*/arm/ -e s/sa110/arm/ \
                                  -e s/aarch64.*/arm64/ )
CLANG ?= clang
LLC ?= llc
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
BPF_INCLUDE := /usr/local/include
INCLUDES := -I. -I$(BPF_INCLUDE) -I../include/uapi

DESTDIR ?= /
prefix ?= /usr
installprefix = $(DESTDIR)/$(prefix)

INSTALLPATH = $(installprefix)

INSTALL ?= install

CFLAGS = -fPIC -Wall -Wextra -march=native -g -std=c99

FNS =	getpid \
	getuid \
	getgid \
	fork

WRAPS = $(FNS:%=--wrap=%)

LDLIBS := -ldl -lbpf

VMLINUX_BTF_PATH := /sys/kernel/btf/vmlinux

OPATH :=
ifeq ($(SANITIZE),1)
CFLAGS += -fsanitize=address
OPATH := .sanitize/
endif

ifeq ($(V),1)
Q =
else
Q = @
MAKEFLAGS += --no-print-directory
submake_extras := feature_display=0
endif

.DELETE_ON_ERROR:

.PHONY: all clean $(PROG)

PROG := bysyscall
LIB := lib$(PROG)

all: analyze $(PROG) $(LIB)
	
analyze: bysyscall.skel.h
	$(CLANG) --analyze $(INCLUDES) $(LIB).c $(PROG).c

clean:
	$(call QUIET_CLEAN, $(PROG))
	$(Q)$(RM) *.o $(PROG) $(LIB).so
	$(Q)$(RM) *.skel.h vmlinux.h

install: $(PROG) $(LIB) bysyscall.service
	$(INSTALL) -m 0755 -d $(INSTALLPATH)/sbin
	$(INSTALL) $(PROG) $(INSTALLPATH)/sbin
	$(INSTALL) -m 0755 -d $(INSTALLPATH)/lib64
	$(INSTALL) $(LIB).so $(INSTALLPATH)/lib64
	$(INSTALL) -m 0755 -d $(INSTALLPATH)/lib/systemd/system
	$(INSTALL) -m 644 bysyscall.service $(INSTALLPATH)/lib/systemd/system

$(PROG): $(PROG).o
	$(QUIET_LINK)$(CC) $(CFLAGS) $^ -lbpf -o $@

$(PROG).o: $(PROG).skel.h         \
	   $(PROG).bpf.o

VERSION = 0.1.0
VERSION_SCRIPT  := libbysyscall.map

$(LIB): $(LIB).c $(LIB).o $(PROG).skel.h
	$(Q)$(CC) $(CFLAGS) -fPIC \
			-shared -o $(@).so \
			$(patsubst %,%.o,$(@)) \
			$(LDLIBS) $(LDFLAGS)

%.skel.h: %.bpf.o
	$(QUIET_GEN)$(BPFTOOL) gen skeleton $< > $@

$(PROG).bpf.o: $(PROG).bpf.c vmlinux.h
	$(QUIET_GEN)$(CLANG) -g -D__TARGET_ARCH_$(SRCARCH) -O2 -target bpf \
		$(INCLUDES) -c $(PROG).bpf.c -o $@ &&                   \
	$(LLVM_STRIP) -g $@

%.o: %.c
	$(QUIET_CC)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

vmlinux.h:
	$(QUIET_GEN)$(BPFTOOL) btf dump file $(VMLINUX_BTF_PATH) format c > $@

