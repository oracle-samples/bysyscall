#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>

#include "libbysyscall.h"
#include "sdt.h"

int bysyscall_pertask_fd = -1;
volatile int bysyscall_pertask_data_idx = -1;

struct bysyscall_pertask_data bysyscall_pertask_data[BYSYSCALL_PERTASK_DATA_CNT];

void *dlh = NULL;

void *bysyscall_real_fns[BYSYSCALL_CNT];

void __attribute__ ((constructor)) bysyscall_init(void)
{
	int i;

	dlh = dlopen("libc.so", RTLD_NOW);
	if (!dlh)
		return;
	for (i = 0; i < BYSYSCALL_CNT; i++)
		bysyscall_real_fns[i] = dlsym(RTLD_NEXT, bysyscall_names[i]);

	/* This tracepoint triggers a bysyscall USDT program to run;
	 * this alerts bysyscall that we need to record info about this
	 * task and its children.
	 */
	DTRACE_PROBE1(bysyscall, init, bysyscall_pertask_data_idx);

	bysyscall_pertask_fd = open(BYSYSCALL_PERTASK_DATA_PIN, O_RDONLY);
}

void __attribute__ ((destructor)) bysyscall_fini(void)
{
	DTRACE_PROBE1(bysyscall, fini, bysyscall_pertask_data_idx);
	if (dlh)
		dlclose(dlh);
}

pid_t getpid(void)
{
	if (bysyscall_pertask_fd > 0 && bysyscall_idx_valid(bysyscall_pertask_data_idx))
		return bysyscall_pertask_data[bysyscall_pertask_data_idx].pid;
	return ((pid_t (*)())(bysyscall_real_fns[BYSYSCALL_getpid]))();
}
