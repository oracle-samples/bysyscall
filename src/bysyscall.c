#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "bysyscall.h"

#include "bysyscall.skel.h"

struct bysyscall_bpf *skel = NULL;

static void cleanup(void)
{
	bysyscall_bpf__destroy(skel);
	system("rm -fr " BYSYSCALL_PINDIR);
}

int main(int argc, char *argv[])
{
	int map_dir_fd, err = 0;

	cleanup();

	if (argc > 1 && strcmp(argv[1], "stop") == 0)
		return 0;

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
	err = bpf_object__pin_maps(skel->obj, BYSYSCALL_PINDIR);
	if (!err)
		err = bpf_object__pin_programs(skel->obj, BYSYSCALL_PINDIR);
	if (err) {
		fprintf(stderr, "could not pin bsyscall progs/maps to '%s': %s\n",
			BYSYSCALL_PINDIR, strerror(errno));
		err = 1;
	}
	chmod(BYSYSCALL_PERTASK_DATA_PIN, 0755);

done:
	if (err)
		cleanup();
	
	return err;
}
