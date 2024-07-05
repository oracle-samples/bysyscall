// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024, Oracle and/or its affiliates. */

#include "vmlinux.h"
#include "bysyscall.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/usdt.bpf.h>

#define printk	__bpf_printk

struct bysyscall_pertask_data bysyscall_pertask_data[BYSYSCALL_PERTASK_DATA_CNT];

long next_idx = -1;

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
	__u64 uid_gid = 0;
	int pid, ret;
	int idx = 0;

	if (!task)
		return 0;
	pid = task->pid;

	idxval = bpf_map_lookup_elem(&bysyscall_pertask_idx_hash, &pid);
	if (!idxval) {
		struct bysyscall_idx_data d = {};

		/* we will get hash misses until the index is full */
		d.value = ++next_idx;

		if (bpf_map_update_elem(&bysyscall_pertask_idx_hash, &pid, &d, BPF_ANY))
			return 0;
		idxval = bpf_map_lookup_elem(&bysyscall_pertask_idx_hash, &pid);
	}
	if (!idxval || bysyscall_idx_in_use(idxval))
		return 0;
	idxval->flags |= BYSYSCALL_IDX_IN_USE;
	idx = idxval->value & (BYSYSCALL_PERTASK_DATA_CNT - 1);
	bysyscall_pertask_data[idx].pid = task->tgid;
	bysyscall_pertask_data[idx].tid = pid;
	uid_gid = bpf_get_current_uid_gid();
	bysyscall_pertask_data[idx].gid = uid_gid >> 32;
	bysyscall_pertask_data[idx].uid = uid_gid & 0xffffffff;
	if (pertask_idx)
		idxval->ptr = pertask_idx;
	if (idxval->ptr) {
		ret = bpf_probe_write_user(idxval->ptr, &idx,sizeof(*pertask_idx));
		if (ret) {
			printk("bpf_probe_write_user (to 0x%lx) returned %d\n",
			       pertask_idx, ret);
			return 0;
		}
	}
	newidxval = idxval;	
	return 0;
}

SEC("uprobe//usr/lib64/libbysyscall.so:__bysyscall_init")
int BPF_UPROBE(bysyscall_init, int *pertask_idx)
{
	struct task_struct *task = bpf_get_current_task_btf();

	if (!task)
		return 0;

	return do_bysyscall_init(task, pertask_idx);
}

static __always_inline int do_bysyscall_fini(void)
{
	struct task_struct *task;
	struct bysyscall_idx_data *idxval;
	int pid;

	task = bpf_get_current_task_btf();
	if (!task)
		return 0;
	pid = task->pid;
	idxval = bpf_map_lookup_elem(&bysyscall_pertask_idx_hash, &pid);
	if (!idxval || bysyscall_idx_in_use(idxval))
		return 0;
	idxval->flags &= ~BYSYSCALL_IDX_IN_USE;
	return 0;
}

SEC("uprobe//usr/lib64/libbysyscall.so:__bysyscall_fini")
int BPF_UPROBE(bysyscall_fini, int pertask_idx)
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
