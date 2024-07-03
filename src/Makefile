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

INSTALL ?= install

CFLAGS := -g -Wall

VMLINUX_BTF_PATH := /sys/kernel/btf/vmlinux

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

all: $(PROG)
	
clean:
	$(call QUIET_CLEAN, $(PROG))
	$(Q)$(RM) *.o
	$(Q)$(RM) *.skel.h vmlinux.h

install: $(PROG)
	$(Q)$(INSTALL) -m 0755 -d $(DESTDIR)$(prefix)/sbin
	$(Q)$(INSTALL) $(PROG) $(DESTDIR)$(prefix)/sbin

$(PROG): $(PROG).o
	$(QUIET_LINK)$(CC) $(CFLAGS) $^ -lbpf -o $@

$(PROG).o: $(PROG).skel.h         \
	   $(PROG).bpf.o

%.skel.h: %.bpf.o
	$(QUIET_GEN)$(BPFTOOL) gen skeleton $< > $@

$(PROG).bpf.o: vmlinux.h
	$(QUIET_GEN)$(CLANG) -g -D__TARGET_ARCH_$(SRCARCH) -O2 -target bpf \
		$(INCLUDES) -c $(PROG).bpf.c -o $@ &&                   \
	$(LLVM_STRIP) -g $@

%.o: %.c
	$(QUIET_CC)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

vmlinux.h:
	$(QUIET_GEN)$(BPFTOOL) btf dump file $(VMLINUX_BTF_PATH) format c > $@


