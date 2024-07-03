#define _GNU_SOURCE

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>


int main(int argc, char *argv[])
{
	pid_t pid1, pid2;

	pid1 = __getpid();

	pid2 = syscall(__NR_getpid);

	if (pid1 != pid2)
		return 1;
	return 0;
}
