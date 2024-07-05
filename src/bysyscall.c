// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024, Oracle and/or its affiliates. */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

#include "bysyscall.h"

#include "bysyscall.skel.h"

struct bysyscall_bpf *skel = NULL;

bool exiting = false;

static void cleanup(int sig)
{
	if (sig)
		exiting = true;
	bysyscall_bpf__destroy(skel);
	system("rm -fr " BYSYSCALL_PINDIR);
}

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

	skel = bysyscall_bpf__open_and_load();
	if (!skel)
		return -1;

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
		fprintf(stderr, "could not attack bysyscall progs: %d\n",
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
	chmod(BYSYSCALL_PERTASK_DATA_PIN, 0777);

done:
	if (err)
		cleanup(1);
	
	return err;
}
