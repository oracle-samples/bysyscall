#include "bsyscall.h"
#include "sdt.h"

int bsyscall_shared_fd = -1;

void __attribute__ ((constructor)) bysyscall_init(void)
{
	/* This tracepoint triggers a bsyscall USDT program to run;
	 * this alerts bsyscall that we need to record info about this
	 * task and its children.
	 */
	DTRACE_PROBE0(bsyscall_init);

	bsyscall_shared_fd = open(O_RDONLY, BYSYSCALL_MAP_SHARED);
}

void __attribute__ ((destructor)) bysyscall_fini(void)
{
	DTRACE_PROBE0(bsyscall_fini);
}
