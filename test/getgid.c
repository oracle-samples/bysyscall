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
			if (WEXITSTATUS(status) == 0)
				status = 0;
			return status;
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
	} else {
		runtest(&ret);
	}
	return ret;
}

static void *runtest(void *data)
{
	gid_t gid1, gid2, lastgid = 0;
	int i, count, *ret = (int *)data;

	count = *ret;

	for (i = 0; i < count; i++) {
		gid1 = getgid();
		if (lastgid && lastgid != gid1) {
			fprintf(stderr, "gid differed across 2 calls to getgid(); last (%d), curr (%d)\n",
				lastgid, gid1);
			exit(1);
		}
		lastgid = gid1;
	}
	gid2 = syscall(__NR_getgid);

	if (gid1 != gid2) {
		fprintf(stderr, "gid from getgid() (%d) != gid from syscall (%d)\n",
			gid1, gid2);
		*ret = -1;
		return NULL;
	}
	printf("%d gid from getgid() (%d) matches gid from syscall (%d)\n",
	       count, gid1, gid2);
	*ret = 0;
	return NULL;
}
