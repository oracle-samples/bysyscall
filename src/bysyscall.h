#ifndef __BYSYSCALL_H__
#define __BYSYSCALL_H__

#define BYSYSCALL_PERTASK_DATA_CNT	8192

struct bysyscall_pertask_data {
	pid_t	pid;
	pid_t	ppid;
	uid_t	uid;
	uid_t	euid;
};

/* a task will map to an idx_data structure; this allows us to
 * simulate a hashmap using a mmap-able array map.
 * Also allows us to track the address of the bysyscall_pertask_data_idx
 * variable.
 */
struct bysyscall_idx_data {
	void	*ptr;
	int	flags;
	int	value;
};

#define BYSYSCALL_IDX_IN_USE		1
#define bysyscall_idx_in_use(i)		(i->flags & BYSYSCALL_IDX_IN_USE)
#define bysyscall_idx(i)		(i->value & (BYSYSCALL_PERTASK_DATA_CNT - 1))

#endif /* __BYSYSCALL_H__ */
