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
#include <errno.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ftw.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>

#include "bysyscall.h"

#include "bysyscall.skel.h"

struct bysyscall_bpf *skel = NULL;

static int unlink_cb(const char *path,
		     __attribute__((unused))const struct stat *s,
		     __attribute__((unused))int flag,
		     __attribute__((unused))struct FTW *f)
{
	remove(path);
	return 0;
}

static void rmpin(const char *path)
{
	nftw(path, unlink_cb, 64, FTW_DEPTH | FTW_PHYS);
	unlink(path);
}

static void cleanup(__attribute__((unused))int sig)
{
	bysyscall_bpf__destroy(skel);
	rmpin(BYSYSCALL_PINDIR);
}

__thread int perthread_data;

int main(int argc, char *argv[])
{
	int map_dir_fd, err = 0;
	struct bpf_link **links;
	unsigned int i;

	cleanup(0);

	signal(SIGINT, cleanup);

	if (argc > 1 && strcmp(argv[1], "stop") == 0) {
		cleanup(1);
		return 0;
	}

	signal(SIGINT, cleanup);

	skel = bysyscall_bpf__open();
	if (!skel)
		return -1;

	/* specify perthread data offset from pthread_t */
	skel->data->bysyscall_perthread_data_offset = (long)&perthread_data -
						      (long)pthread_self();

	skel->data->bysyscall_page_size = getpagesize();
	err = bysyscall_bpf__load(skel);
	if (err) {
		fprintf(stderr, "could not load bysyscall object: %d\n", err);
		goto done;
	}
	map_dir_fd = open(BYSYSCALL_PINDIR, O_RDONLY);
	close(map_dir_fd);
	if (map_dir_fd < 0) {
		if (mkdir(BYSYSCALL_PINDIR, 0755)) {
			fprintf(stderr, "could not create '%s': %s\n",
				BYSYSCALL_PINDIR, strerror(errno));
			err = 1;
			goto done;
		}
	}
	err = bysyscall_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "could not attach bysyscall progs: %d\n",
			err);
		goto done;
	}
	err = bpf_object__pin_maps(skel->obj, BYSYSCALL_PINDIR);
	if (!err)
		err = bpf_object__pin_programs(skel->obj, BYSYSCALL_PINDIR);
	if (err) {
		fprintf(stderr, "could not pin bsyscall progs/maps to '%s': %s\n",
			BYSYSCALL_PINDIR, strerror(errno));
		err = 1;
		goto done;
	}
	links = (struct bpf_link **)&skel->links;
	for (i = 0; i < sizeof(skel->links)/sizeof(struct bpf_link *); i++) {
		char linkname[PATH_MAX];

		snprintf(linkname, sizeof(linkname), BYSYSCALL_PINDIR "link%d", i);
		err = bpf_link__pin(links[i], linkname);
		if (err) {
			fprintf(stderr, "could not pin bysyscall link to '%s': %s\n",
				linkname, strerror(errno));
			err = 1;
			goto done;
		}
	}
	chmod(BYSYSCALL_PERTASK_DATA_PIN,
	      S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);

done:
	if (err)
		cleanup(1);
	
	return err;
}
