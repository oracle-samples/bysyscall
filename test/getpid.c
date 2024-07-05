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
	pid_t pid1, pid2, lastpid, newpid;
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
		pid1 = getpid();
		if (lastpid && lastpid != pid1) {
			fprintf(stderr, "pid differed across 2 calls to getpid(); last (%d), curr (%d)\n",
				lastpid, pid1);
			exit(1);
		}
		lastpid = pid1;
	}
	pid2 = syscall(__NR_getpid);

	if (pid1 != pid2) {
		fprintf(stderr, "pid from getpid() (%d) != pid from syscall (%d)\n",
			pid1, pid2);

		return 1;
	}
	printf("%d pid from getpid() (%d) matches pid from syscall (%d)\n",
	       count, pid1, pid2);
	return 0;
}
