#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/syscall.h>


int main(int argc, char *argv[])
{
	uid_t uid1, uid2, lastuid;
	pid_t newpid;
	int i, count = 1, dofork = 0;

	if (argc > 1)
		count = atoi(argv[1]);
	if (argc > 2)
		dofork = strcmp(argv[2], "fork") == 0;

	if (dofork) {
		int ret, status = 0;

		newpid = fork();
		if (newpid > 0) {
			while ((ret = wait(&status)) > 0 && ret != newpid)
				sleep(1);
			if (ret < 0)
				status = -1;
			if (WEXITSTATUS(status) == 0)
				status = 0;
			return status;
		}
		if (newpid < 0)
			exit(newpid);
	}
	for (i = 0; i < count; i++) {
		uid1 = getuid();
		if (lastuid && lastuid != uid1) {
			fprintf(stderr, "uid differed across 2 calls to getuid(); last (%d), curr (%d)\n",
				lastuid, uid1);
			exit(1);
		}
		lastuid = uid1;
	}
	uid2 = syscall(__NR_getuid);

	if (uid1 != uid2) {
		fprintf(stderr, "uid from getuid() (%d) != uid from syscall (%d)\n",
			uid1, uid2);

		return 1;
	}
	printf("%d uid from getuid() (%d) matches uid from syscall (%d)\n",
	       count, uid1, uid2);
	return 0;
}
