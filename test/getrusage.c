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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <sys/syscall.h>

static void *runtest(void *);

int verbose = 0;

int main(int argc, char *argv[])
{
	int i, count = 1, dofork = 0, dopthread = 0, ret = 0;
	pid_t newpid;

	if (argc > 1)
		count = atoi(argv[1]);
	if (argc > 2) {
		dofork = strcmp(argv[2], "fork") == 0;
		dopthread = strcmp(argv[2], "pthread") == 0;
	}
	if (argc > 3)
		verbose = strcmp(argv[3], "verbose") == 0;


	if (dofork) {
		int status = 0;

		newpid = fork();
		if (newpid > 0) {
			while ((ret = wait(&status)) > 0 && ret != newpid)
				sleep(1);
			if (ret < 0)
				status = -1;
			if (WEXITSTATUS(status) == 0) {
				/* ensure parent pid still matches syscall */
				ret = count;
				runtest(&ret);
				return ret;
			} else {
				return status;
			}
		}
		if (newpid < 0)
			exit(newpid);
	}

	ret = count;
	if (dopthread) {
		pthread_t tid;
		pthread_attr_t attr;
		void *rv;

		if (pthread_attr_init(&attr)) {
			perror("pthread_attr_init");
			return -1;
		}
		if (pthread_create(&tid, &attr, &runtest, &ret)) {
			perror("pthread_create");
			return -1;
		}
		(void)pthread_join(tid, &rv);
		/* ensure main thread pid still matches */
		ret = count;
	}
	runtest(&ret);
	return ret;
}

static void printrusage(const char *name, struct rusage *usage)
{
	if (!verbose)
		return;

	printf("%s.utime = %ld.%ld\n", name, usage->ru_utime.tv_sec, usage->ru_utime.tv_usec);
	printf("%s.stime = %ld.%ld\n", name, usage->ru_stime.tv_sec, usage->ru_stime.tv_usec);
	printf("%s.maxrss = %ld\n", name, usage->ru_maxrss);
	printf("%s.minflt = %ld\n", name, usage->ru_minflt);
	printf("%s.majflt = %ld\n", name, usage->ru_majflt);
	printf("%s.inblock = %ld\n", name, usage->ru_inblock);
	printf("%s.oublock = %ld\n", name, usage->ru_oublock);
	printf("%s.nvcsw = %ld\n", name, usage->ru_nvcsw);
	printf("%s.nivcsw = %ld\n", name, usage->ru_nivcsw);
}
  
#define ASSERT_RUSAGE_VAL(s, r, field)					\
do {									\
	if (s->field && !r->field) {					\
		fprintf(stderr, "unexpected rusage val %s (syscall) %ld, (bysyscall) %ld\n", \
			#field, s->field, r->field);			\
		return -EINVAL;						\
	}								\
} while (0)

static int checkrusage(struct rusage *s, struct rusage *r)
{
	ASSERT_RUSAGE_VAL(s, r, ru_maxrss);
	ASSERT_RUSAGE_VAL(s, r, ru_minflt);
	ASSERT_RUSAGE_VAL(s, r, ru_majflt);
	ASSERT_RUSAGE_VAL(s, r, ru_inblock);
	ASSERT_RUSAGE_VAL(s, r, ru_oublock);
	ASSERT_RUSAGE_VAL(s, r, ru_nvcsw);
	ASSERT_RUSAGE_VAL(s, r, ru_nivcsw);
	return 0;
}

static void *runtest(void *data)
{
	int i, count, *ret = (int *)data;
	struct rusage srself, srthread, srchildren;
	struct rusage rself, rthread, rchildren;

	count = *ret;

	*ret = syscall(__NR_getrusage, RUSAGE_SELF, &srself);
	if (*ret) {
		fprintf(stderr, "RUSAGE_SELF (syscall) failed: %d\n", *ret);
		return NULL;
	}
	printrusage("syscall_self", &srself);
	*ret = syscall(__NR_getrusage, RUSAGE_CHILDREN, &srchildren);
	if (*ret) {
		fprintf(stderr, "RUSAGE_CHILDREN (syscall) failed: %d\n", *ret);
		return NULL;
        }
	printrusage("syscall_children", &srchildren);
	*ret = syscall(__NR_getrusage, RUSAGE_THREAD, &srthread);
	if (*ret) {
		fprintf(stderr, "RUSAGE_THREAD (syscall) failed: %d\n", *ret);
		return NULL;
	}
	printrusage("syscall_thread", &srthread);

	for (i = 0; i < count; i++) {
		*ret = getrusage(RUSAGE_SELF, &rself);
		if (!*ret) {
			printrusage("self", &rself);
			*ret = checkrusage(&srself, &rself);
		}
		if (*ret) {
			fprintf(stderr, "RUSAGE_SELF failed: %d\n", *ret);
			return NULL;
		}
		*ret = getrusage(RUSAGE_CHILDREN, &rchildren);
		if (*ret) {
			fprintf(stderr, "RUSAGE_CHILDREN failed %d\n", *ret);
			return NULL;
		}
		printrusage("children", &rchildren);
		*ret = getrusage(RUSAGE_THREAD, &rthread);
		if (!*ret) {
			printrusage("thread", &rthread);
			*ret = checkrusage(&srthread, &rthread);
		}
		if (*ret) {
			fprintf(stderr, "RUSAGE_THREAD failed %d\n", *ret);
			return NULL;
		}
	}
	printf("getrusage() calls succeeded\n");
	*ret = 0;
	return NULL;
}
