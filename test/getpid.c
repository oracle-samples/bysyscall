#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>


int main(int argc, char *argv[])
{
	pid_t pid1, pid2, lastpid;
	int i, count = 1;

	if (argc > 1)
		count = atoi(argv[1]);

	for (i = 0; i < count; i++) {
		pid1 = getpid();
		if (lastpid && lastpid != pid1) {
			fprintf(stderr, "pid differed across 2 calls to getpid(); last (%d), curr (%d)\n",
				lastpid, pid1);
			return 1;
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
