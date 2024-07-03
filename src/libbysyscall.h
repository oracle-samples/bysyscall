#include "bysyscall.h"

/* Add new bysyscalls here */
#define __BYSYSCALL_MAPPER(FN)	\
	FN(__getpid),

#define __BYSYSCALL_ENUM_FN(x)	BYSYSCALL_ ## x
enum bysyscall_id {
	__BYSYSCALL_MAPPER(__BYSYSCALL_ENUM_FN)
	BYSYSCALL_CNT
};

#define __BYSYSCALL_NAME_FN(x)	#x
const char *bysyscall_names[] = {
	__BYSYSCALL_MAPPER(__BYSYSCALL_NAME_FN)
};
