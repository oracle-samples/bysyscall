// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024, Oracle and/or its affiliates. */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/klog.h>
#include <sys/syslog.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <bpf/bpf.h>

#include "libbysyscall.h"
#include "sdt.h"

int bysyscall_pertask_fd = -1;
volatile int bysyscall_pertask_data_idx = -1;

struct bysyscall_pertask_data *bysyscall_pertask_data;

void *dlh = NULL;

void *bysyscall_real_fns[BYSYSCALL_CNT];

int bysyscall_loglevel = LOG_ERR;

void bysyscall_log(int level, const char *fmt, ...)
{
	if (level <= bysyscall_loglevel) {
		va_list args;

		va_start(args, fmt);
		vfprintf(stderr, fmt, args);
		va_end(args);
	}
}

__attribute__((noinline)) void __bysyscall_init(__attribute__((unused))volatile int *pertask_data_idx)
{
}

void __attribute__ ((constructor)) bysyscall_init(void)
{
	const char *libc, *debug;
	int i;

	debug = getenv("DEBUG");
	if (debug && atoi(debug) > 0) {
		bysyscall_loglevel = LOG_DEBUG;
		bysyscall_log(LOG_DEBUG, "set loglevel to DEBUG...\n");
	}
	libc = getenv("LIBC");
	if (!libc)
		libc = "libc.so.6";

	dlh = dlopen(libc, RTLD_NOW);
	if (!dlh)
		return;
	for (i = 0; i < BYSYSCALL_CNT; i++) {
		bysyscall_real_fns[i] = dlsym(RTLD_NEXT, bysyscall_names[i]);
		if (!bysyscall_real_fns[i]) {
			bysyscall_log(LOG_ERR, "could not link '%s'\n",
				      bysyscall_names[i]);
		} else {
			bysyscall_log(LOG_DEBUG, "linked '%s'(%d) to %p\n",
				      bysyscall_names[i], i, bysyscall_real_fns[i]);
		}
	}

	/* This call triggers a bysyscall uprobe program to run;
	 * this alerts bysyscall that we need to record info about this
	 * task and its children.
	 *
	 * The associated BPF program writes to bysyscall_pertask_data_idx
	 * to tell us the index of the per-task data.
	 */
	__bysyscall_init(&bysyscall_pertask_data_idx);

	bysyscall_pertask_fd = bpf_obj_get(BYSYSCALL_PERTASK_DATA_PIN);
	if (bysyscall_pertask_fd >= 0) {
		bysyscall_pertask_data = mmap(NULL,
					      sizeof (*bysyscall_pertask_data) *
					      BYSYSCALL_PERTASK_DATA_CNT,
					      PROT_READ,
					      MAP_SHARED,
					      bysyscall_pertask_fd,
					      0);
		if (bysyscall_pertask_data == MAP_FAILED) {
			bysyscall_log(LOG_ERR, "could not mmap() pertask data from '%s': %s\n",
				      BYSYSCALL_PERTASK_DATA_PIN,
				      strerror(errno));
			bysyscall_pertask_data = NULL;
		}
	}
}

__attribute__((noinline)) void __bysyscall_fini(__attribute__((unused))volatile int pertask_data_idx)
{
}

void __attribute__ ((destructor)) bysyscall_fini(void)
{
	__bysyscall_fini(bysyscall_pertask_data_idx);
	if (dlh)
		dlclose(dlh);
}

static inline bool have_bysyscall_pertask_data(void)
{
	return bysyscall_pertask_fd > 0 && bysyscall_pertask_data &&
	       bysyscall_idx_valid(bysyscall_pertask_data_idx);
}

pid_t getpid(void)
{
	bysyscall_log(LOG_DEBUG,  "getpid (fd %d, data idx %d)\n",
		      bysyscall_pertask_fd, bysyscall_pertask_data_idx);
	if (have_bysyscall_pertask_data())
		return bysyscall_pertask_data[bysyscall_pertask_data_idx].pid;
	return ((pid_t (*)())(bysyscall_real_fns[BYSYSCALL_getpid]))();
}
