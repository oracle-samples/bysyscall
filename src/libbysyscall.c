#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/klog.h>
#include <sys/syslog.h>
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

int bysyscall_loglevel = LOG_ERR;

void bysyscall_log(int level, const char *fmt, ...)
{
	if (level <= bysyscall_loglevel) {
		va_list args;

		va_start(args, fmt);
		vfprintf(stderr, fmt, args);
		va_end(args);
	}
}

void __attribute__ ((constructor)) bysyscall_init(void)
{
	int i;

	if (getenv("DEBUG")) {
		bysyscall_loglevel = LOG_DEBUG;
		bysyscall_log(LOG_DEBUG, "set loglevel to DEBUG...\n");
	}

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

pid_t __getpid(void)
{
	bysyscall_log(LOG_ERR, "got here, %d\n", bysyscall_pertask_fd);
	if (bysyscall_pertask_fd > 0 && bysyscall_idx_valid(bysyscall_pertask_data_idx))
		return bysyscall_pertask_data[bysyscall_pertask_data_idx].pid;
	return ((pid_t (*)())(bysyscall_real_fns[BYSYSCALL___getpid]))();
}
