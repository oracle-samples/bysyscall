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
		vfprintf(stderr, fmt, args);
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

pid_t fork(void)
{
	pid_t ret = ((pid_t (*)())bysyscall_real_fns[BYSYSCALL_fork])();

	/* in child, init pertask idx */
	if (ret == 0)
		__bysyscall_init(&bysyscall_pertask_data_idx);
	return ret;
}

struct bysyscall_thread_arg {
	void *(*start)(void *);
	void *arg;
};

struct bysyscall_thread_arg ta;

static void *bysyscall_pthread_start(void *arg)
{
	struct bysyscall_thread_arg *ta = arg;

	__bysyscall_init(&bysyscall_pertask_data_idx);

	return ta->start(ta->arg);
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
	       void *(*start)(void *), void *arg)
{
	ta.start = start;
	ta.arg = arg;
	return ((int (*)(pthread_t *, const pthread_attr_t *,
			 void *(*)(void *), void *))
		bysyscall_real_fns[BYSYSCALL_pthread_create])(thread, attr,
							      bysyscall_pthread_start,
							      &ta);
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

uid_t getuid(void)
{
	if (have_bysyscall_pertask_data()) {
		bysyscall_stats[BYSYSCALL_getuid]++;
		return bysyscall_pertask_data[bysyscall_pertask_data_idx].uid;
	}
	return ((uid_t (*)())(bysyscall_real_fns[BYSYSCALL_getuid]))();
}

gid_t getgid(void)
{
	if (have_bysyscall_pertask_data()) {
		bysyscall_stats[BYSYSCALL_getgid]++;
		return bysyscall_pertask_data[bysyscall_pertask_data_idx].gid;
	}
	return ((gid_t (*)())(bysyscall_real_fns[BYSYSCALL_getgid]))();
}
