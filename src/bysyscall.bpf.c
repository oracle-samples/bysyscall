// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024, Oracle and/or its affiliates. */

#include "vmlinux.h"
#include "bysyscall.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/usdt.bpf.h>

struct bysyscall_pertask_data bysyscall_pertask_data[BYSYSCALL_PERTASK_DATA_CNT];

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct bysyscall_idx_data *);
} bysyscall_pertask SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, BYSYSCALL_PERTASK_DATA_CNT);
	__type(key, int);
	__type(value, struct bysyscall_idx_data);
} bysyscall_pertask_idx_hash SEC(".maps");

/* Fire when bysyscall init is triggered; this can happen for either
 * an explicit USDT probe firing in libbysyscall init() or via a
 * task_newtask() tracepoint firing for a child process of the current
 * task.  In response
 * - find an available index using the pertask_idx map
 * - create per-task storage to store the per-task data index for this task
 * - populate some initial values
 * - if present, write it to the USDT caller context via bpf_probe_write_user()
 *
 * Now the user can use that index to look up the appropriate values.
 */
static __always_inline int do_bysyscall_init(struct task_struct *task, int *pertask_idx)
{
	struct bysyscall_idx_data *idxval = NULL, *newidxval;
	struct bysyscall_idx_data **ptr;
	int pid, ret;
	int idx = 0;

	task = bpf_get_current_task_btf();
	if (!task)
		return 0;
	pid = task->pid;

	idxval = bpf_map_lookup_elem(&bysyscall_pertask_idx_hash, &pid);
	if (!idxval || bysyscall_idx_in_use(idxval))
		return 0;
	idxval->flags |= BYSYSCALL_IDX_IN_USE;
	if (idxval)
		idx = idxval->value & (BYSYSCALL_PERTASK_DATA_CNT - 1);
	else
		return 0;
	idx = bysyscall_idx(idxval);
	bysyscall_pertask_data[idx].pid = pid;
	*ptr = idxval;
	if (!pertask_idx)
		pertask_idx = idxval->ptr;
	if (pertask_idx) {
		ret = bpf_probe_write_user(pertask_idx, ptr,sizeof(*pertask_idx));
		if (!ret)
			return 0;
	}
	newidxval = idxval;	
	ptr = bpf_task_storage_get(&bysyscall_pertask, task, &idxval,
                                   BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (!ptr)
                return 0;
	*ptr = idxval;
	return 0;
}

SEC("usdt//user/lib64/libbysyscall.so:bysyscall:init")
int BPF_USDT(bysyscall_init, int *pertask_idx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	if (!task)
		return 0;

	return do_bysyscall_init(task, pertask_idx);
}

SEC("tp_btf/task_newtask")
int BPF_PROG(bysyscall_task_newtask, struct task_struct *task, u64 clone_flags)
{
	struct task_struct *current = bpf_get_current_task_btf();
	struct bysyscall_idx_data *idxval = NULL;

	if (!current)
		return 0;
	/* is the currrent (parent process) instrumented for bysyscall? */
	idxval = bpf_task_storage_get(&bysyscall_pertask, current, &idxval, 0);
	if (!idxval)
		return 0;
	return do_bysyscall_init(task, idxval->ptr);
}

int do_bysyscall_fini(void)
{
	struct task_struct *task;
	struct bysyscall_idx_data *idxval;
	int pid;

	task = bpf_get_current_task_btf();
	if (!task)
		return 0;
	pid = task->pid;
	bpf_task_storage_delete(&bysyscall_pertask, task);
	idxval = bpf_map_lookup_elem(&bysyscall_pertask_idx_hash, &pid);
	if (!idxval || bysyscall_idx_in_use(idxval))
		return 0;
	idxval->flags &= ~BYSYSCALL_IDX_IN_USE;
	return 0;
}

SEC("usdt//user/lib64/libbysyscall.so:bysyscall:fini")
int BPF_USDT(bysyscall_fini, int pertask_idx)
{
	return do_bysyscall_fini();
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(bysyscall_process_exit)
{
	return do_bysyscall_fini();
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(bysyscall_process_exec)
{
	return do_bysyscall_fini();
}

char _license[] SEC("license") = "GPL v2";
