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
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/syscall.h>

static void *runtest(void *);

extern pid_t gettid(void);

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

static void *runtest(void *data)
{
	pid_t pid1, pid2, lastpid = 0;
	int i, count, *ret = (int *)data;

	count = *ret;

	for (i = 0; i < count; i++) {
		pid1 = gettid();
		if (lastpid && lastpid != pid1) {
			fprintf(stderr, "pid differed across 2 calls to gettid(); last (%d), curr (%d)\n",
				lastpid, pid1);
			exit(1);
		}
		lastpid = pid1;
	}
	pid2 = syscall(__NR_gettid);

	if (pid1 != pid2) {
		fprintf(stderr, "pid from gettid() (%d) != pid from syscall (%d)\n",
			pid1, pid2);
		*ret = -1;
		return NULL;
	}
	printf("%d pid from gettid() (%d) matches pid from syscall (%d)\n",
	       count, pid1, pid2);
	*ret = 0;
	return NULL;
}
