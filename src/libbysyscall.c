/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (c) 2024, Oracle and/or its affiliates.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/klog.h>
#include <sys/syslog.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <bpf/bpf.h>

#include "libbysyscall.h"

static int bysyscall_pertask_fd = -1;

__thread volatile int bysyscall_pertask_data_idx = -1;

/* offset of per-thread variable from the associated pthread_t; we use
 * this to set bysyscall_pertask_data_idx for the created thread after
 * calling pthread_create().
 */
static long __perthread_data_off = 0;

struct bysyscall_pertask_data *bysyscall_pertask_data;

static void *bysyscall_real_fns[BYSYSCALL_CNT] = {};
static unsigned long bysyscall_stats[BYSYSCALL_CNT];

int bysyscall_loglevel = LOG_ERR;

void bysyscall_log(int level, const char *fmt, ...)
{
	if (level <= bysyscall_loglevel) {
		va_list args;

		va_start(args, fmt);
		vfprintf(level <= LOG_WARNING ? stderr : stdout, fmt, args);
		va_end(args);
	}
}

/* This function is instrumented to allow us to set the pertask data idx
 * from BPF context via bpf_probe_write_user().
 */
__attribute__((noinline)) void __bysyscall_init(__attribute__((unused))volatile int *pertask_data_idxp)
{
}

void __attribute__ ((constructor)) bysyscall_init(void)
{
	const char *log;
	int i;

	if (!__perthread_data_off) {
		pthread_t self = pthread_self();

		__perthread_data_off = (long)&bysyscall_pertask_data_idx - self;
	}
	log = getenv("BYSYSCALL_LOG");
	if (log) {
		if (strcmp(log, "info") == 0)
			bysyscall_loglevel = LOG_INFO;
		if (strcmp(log, "err") == 0)
			bysyscall_loglevel = LOG_ERR;
		if (strcmp(log,  "debug") == 0)
			bysyscall_loglevel = LOG_DEBUG;
	}
	bysyscall_log(LOG_DEBUG, "set loglevel to DEBUG...\n");

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
	if (bysyscall_pertask_fd < 0) {
		bysyscall_log(LOG_DEBUG, "could not get '%s': %s\n",
			      BYSYSCALL_PERTASK_DATA_PIN, strerror(errno));
		return;
	}

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
		close(bysyscall_pertask_fd);
		bysyscall_pertask_fd = -1;
	}
}

__attribute__((noinline)) void __bysyscall_fini(__attribute__((unused))volatile int pertask_data_idx)
{
}

static void bysyscall_stat(void)
{
	unsigned int i;

	for (i = 0; i < BYSYSCALL_CNT; i++) {
		if (bysyscall_stats[i])
			bysyscall_log(LOG_INFO, "%s: bypassed %ld times\n",
				      bysyscall_names[i], bysyscall_stats[i]);
	}
	fflush(stderr);
}
     
void __attribute__ ((destructor)) bysyscall_fini(void)
{
	__bysyscall_fini(bysyscall_pertask_data_idx);
	bysyscall_stat();
}

static inline bool have_bysyscall_pertask_data(void)
{
	return bysyscall_pertask_fd > 0 && bysyscall_pertask_data &&
	       bysyscall_idx_valid(bysyscall_pertask_data_idx);
}

pid_t getpid(void)
{
	if (have_bysyscall_pertask_data()) {
		bysyscall_stats[BYSYSCALL_getpid]++;
		return bysyscall_pertask_data[bysyscall_pertask_data_idx].pid;
	}
	return ((pid_t (*)())bysyscall_real_fns[BYSYSCALL_getpid])();
}

pid_t __wrap_getpid(void)
{
	return getpid();
}

uid_t getuid(void)
{
	if (have_bysyscall_pertask_data()) {
		bysyscall_stats[BYSYSCALL_getuid]++;
		return bysyscall_pertask_data[bysyscall_pertask_data_idx].uid;
	}
	return ((uid_t (*)())(bysyscall_real_fns[BYSYSCALL_getuid]))();
}

uid_t __wrap_getuid(void)
{
	return getuid();
}

gid_t getgid(void)
{
	if (have_bysyscall_pertask_data()) {
		bysyscall_stats[BYSYSCALL_getgid]++;
		return bysyscall_pertask_data[bysyscall_pertask_data_idx].gid;
	}
	return ((gid_t (*)())(bysyscall_real_fns[BYSYSCALL_getgid]))();
}

gid_t __wrap_getgid(void)
{
	return getgid();
}

static inline void addrusage(struct rusage *tot, struct rusage *cur)
{
	tot->ru_utime.tv_sec += cur->ru_utime.tv_sec;
	tot->ru_utime.tv_usec += cur->ru_utime.tv_usec;
	tot->ru_stime.tv_sec += cur->ru_stime.tv_sec;
	tot->ru_stime.tv_usec += cur->ru_stime.tv_usec;
	tot->ru_nvcsw += cur->ru_nvcsw;	
	tot->ru_nivcsw += cur->ru_nivcsw;
	tot->ru_minflt += cur->ru_minflt;
	tot->ru_majflt += cur->ru_majflt;
	tot->ru_inblock += cur->ru_inblock;
	tot->ru_oublock += cur->ru_oublock;
	if (cur->ru_maxrss > tot->ru_maxrss)
		tot->ru_maxrss = cur->ru_maxrss;
}

int getrusage(int who, struct rusage *usage)
{
	if (have_bysyscall_pertask_data() &&
	    bysyscall_pertask_data[bysyscall_pertask_data_idx].rusage_gen) {
		struct rusage *self, *children;
		pid_t pid;
		int i;

		self = &bysyscall_pertask_data[bysyscall_pertask_data_idx].rusage[_RUSAGE_SELF];
		children = &bysyscall_pertask_data[bysyscall_pertask_data_idx].rusage[_RUSAGE_CHILDREN];
		switch (who) {
		case RUSAGE_THREAD:
			memcpy(usage, self, sizeof(*usage));
			bysyscall_stats[BYSYSCALL_getrusage]++;
			return 0;
		case RUSAGE_SELF:
			pid = bysyscall_pertask_data[bysyscall_pertask_data_idx].pid;
			/* fastpath for single-threaded tasks */
			if (pid == bysyscall_pertask_data[bysyscall_pertask_data_idx].tid &&
			    bysyscall_pertask_data[bysyscall_pertask_data_idx].child_threads == 0) {
				memcpy(usage, self, sizeof(*usage));
				bysyscall_stats[BYSYSCALL_getrusage]++;
				return 0;
			}
			memset(usage, 0, sizeof(*usage));
			/* collect usage for all threads in task */
			for (i = 0; i < BYSYSCALL_PERTASK_DATA_CNT; i++) {
				if (bysyscall_pertask_data[i].pid != pid)
					continue;
				addrusage(usage,
					  &bysyscall_pertask_data[i].rusage[_RUSAGE_SELF]);
			}
			bysyscall_stats[BYSYSCALL_getrusage]++;
			return 0;
		case RUSAGE_CHILDREN:
			memcpy(usage, children, sizeof(*usage));
			bysyscall_stats[BYSYSCALL_getrusage]++;
			return 0;
		default:
			break;
		}
	}
	return ((int (*)(int, struct rusage *))(bysyscall_real_fns[BYSYSCALL_getrusage]))(who, usage);
}

int __wrap_getrusage(int who, struct rusage *usage)
{
	return getrusage(who, usage);
}
