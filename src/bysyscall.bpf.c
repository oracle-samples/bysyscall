/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (c) 2024, Oracle and/or its affiliates.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */

#include "vmlinux.h"
#include "bysyscall.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define NANOSEC 1000000000L

#define printk	__bpf_printk

/* pertask data will be in skel bss map */
volatile struct bysyscall_pertask_data bysyscall_pertask_data[BYSYSCALL_PERTASK_DATA_CNT];

/* initialize as non-zero to ensure these will be in skel data */
long bysyscall_perthread_data_offset = BYSYSCALL_PERTHREAD_OFF_INVAL;
long bysyscall_page_size = 4096;

static long next_idx = -1;

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
 *
 * Returns index used for task, -1 on error.
 */
static __always_inline int do_bysyscall_init(struct task_struct *task, int *pertask_idx)
{
	struct bysyscall_idx_data *idxval = NULL, *newidxval;
	__u64 uid_gid = 0;
	int pid, ret;
	int idx = 0;

	if (!task)
		return -1;
	pid = task->pid;

	idxval = bpf_map_lookup_elem(&bysyscall_pertask_idx_hash, &pid);
	if (!idxval) {
		struct bysyscall_idx_data d = {};

		/* we will get hash misses until the index is full */
		d.value = ++next_idx;

		if (bpf_map_update_elem(&bysyscall_pertask_idx_hash, &pid, &d, BPF_ANY))
			return -1;
		idxval = bpf_map_lookup_elem(&bysyscall_pertask_idx_hash, &pid);
	}
	if (!idxval || bysyscall_idx_in_use(idxval))
		return -1;
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
			return idx;
		}
	}
	newidxval = idxval;	
	return idx;
}

SEC("uprobe/libbysyscall.so:__bysyscall_init")
int BPF_UPROBE(bysyscall_init, int *pertask_idx)
{
	struct task_struct *task = bpf_get_current_task_btf();

	if (!task)
		return 0;

	do_bysyscall_init(task, pertask_idx);

	return 0;
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

/* Assign a new index, data on pthread_create(), update index in userspace.
 *
 * start_thread() is passed the pthread_t; we can compute the __thread
 * variable offset using it and the global bysyscall_perthread_data_offset
 * which bysyscall set by computing the difference between pthread_self
 * and the first __thread variable addresses.
 */
SEC("uprobe/libpthread.so:start_thread")
int BPF_UPROBE(bysyscall_start_thread, void *arg)
{
	struct task_struct *task;
	struct bysyscall_idx_data *idxval;
	int pid;
	int *pertask_idx = NULL;
	int idx;

	task = bpf_get_current_task_btf();
	if (!task)
		return 0;
	pid = task->tgid;
	/* are we collecting data for this process? if not, bail. */
	idxval = bpf_map_lookup_elem(&bysyscall_pertask_idx_hash, &pid);
	if (!idxval)
		return 0;
	if (bysyscall_perthread_data_offset == BYSYSCALL_PERTHREAD_OFF_INVAL)
		return 0;
	pertask_idx = (int *)(arg + bysyscall_perthread_data_offset);
	idx = do_bysyscall_init(task, pertask_idx);
	if (idx < 0)
		return 0;
	idx = idx & (BYSYSCALL_PERTASK_DATA_CNT - 1);
	/* this task has multiple threads */
	__sync_fetch_and_add(&bysyscall_pertask_data[idx].child_threads, 1);
	return 0;
}

/* Assign a new index, cached data on fork() success, update the index in
 * userspace for the newly-created task.
 *
 * Note we look for fork() return value of 0 indicating we are in child process.
 */
SEC("uretprobe/libc.so.6:fork")
int BPF_URETPROBE(bysyscall_fork_return, pid_t ret)
{
	struct task_struct *task;
	struct bysyscall_idx_data *idxval;
	int pid, ppid;
	int *pertask_idx = NULL;

	/* failed or in parent. */
	if (ret < 0 || ret > 0)
		return 0;
	task = bpf_get_current_task_btf();
	if (!task)
		return 0;
	ppid = task->real_parent->tgid;

	/* are we collecting data for the parent process? if not, bail. */
	idxval = bpf_map_lookup_elem(&bysyscall_pertask_idx_hash, &ppid);
	if (!idxval)
		return 0;
	do_bysyscall_init(task, idxval->ptr);
	return 0;
}

/* Catch explicit library cleanup to free bysyscall array index for re-use */
SEC("uprobe/libbysyscall.so:__bysyscall_fini")
int BPF_UPROBE(bysyscall_fini, int pertask_idx)
{
	return do_bysyscall_fini();
}

/* Catch exit, exec to free bysyscall array index for re-use */
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

/* Catch successful setuid() system calls, update cache */
SEC("fexit/__sys_setuid")
int BPF_PROG(bysyscall_setuid, uid_t uid, long ret)
{
	struct bysyscall_idx_data *idxval;
	struct task_struct *task;
	int pid, idx = 0;

	if (ret)
		return 0;
	/* are we collecting data for the process? if not, bail. */
	task = bpf_get_current_task_btf();
	if (!task)
		return 0;
	pid = task->tgid;
        idxval = bpf_map_lookup_elem(&bysyscall_pertask_idx_hash, &pid);	
	if (!idxval)
		return 0;
	idx = idxval->value & (BYSYSCALL_PERTASK_DATA_CNT - 1);
	bysyscall_pertask_data[idx].uid = uid;
	return 0;
}

SEC("fexit/__sys_setgid")
int BPF_PROG(bysyscall_setgid, gid_t gid, long ret)
{
	struct bysyscall_idx_data *idxval;
	struct task_struct *task;
	int pid, idx = 0;

	if (ret)
		return 0;
	/* are we collecting data for the process? if not, bail. */
	task = bpf_get_current_task_btf();
	if (!task)
		return 0;
	pid = task->tgid;
	idxval = bpf_map_lookup_elem(&bysyscall_pertask_idx_hash, &pid);
	if (!idxval)
		return 0;
	idx = idxval->value & (BYSYSCALL_PERTASK_DATA_CNT - 1);
	bysyscall_pertask_data[idx].gid = gid;
	return 0;
}

#define update_rusage_val(idx, field, val) \
	__sync_val_compare_and_swap(&bysyscall_pertask_data[idx].rusage[_RUSAGE_SELF].field, 0, val)

#define update_rusage_cval(idx, field, val) \
	__sync_val_compare_and_swap(&bysyscall_pertask_data[idx].rusage[_RUSAGE_CHILDREN].field, 0, val)

static __s64 read_mm_stat(struct mm_struct *mm, int idx)
{
	return mm->rss_stat[idx & (NR_MM_COUNTERS - 1)].count;
}

static inline __u64 get_mm_maxrss(struct task_struct *task)
{
	struct mm_struct *mm = task->mm;
	__u64 mm_tot = 0;

	if (!mm)
		return 0;
	mm_tot = read_mm_stat(mm, MM_FILEPAGES);
	mm_tot += read_mm_stat(mm, MM_ANONPAGES);
	mm_tot += read_mm_stat(mm, MM_SHMEMPAGES);
	if (mm_tot > mm->hiwater_rss)
		return mm_tot;
	return mm->hiwater_rss;
}

static inline __u64 get_maxrss(__u64 maxrss, __u64 mm_maxrss)
{
	if (mm_maxrss > maxrss)
		maxrss = mm_maxrss;
	return maxrss * bysyscall_page_size / 1024;
}

SEC("fexit/update_process_times")
int BPF_PROG(update_process_times, int user_tick, int ret)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct bysyscall_idx_data *idxval;
	__u64 utime = 0, stime = 0;
	struct signal_struct *sig;
	int pid, tgid, idx = 0;
	__u64 mm_maxrss;

	if (task == NULL)
		return 0;

	pid = task->pid;
	idxval = bpf_map_lookup_elem(&bysyscall_pertask_idx_hash, &pid);
	if (!idxval)
		return 0;
	idx = idxval->value & (BYSYSCALL_PERTASK_DATA_CNT - 1);

	sig = task->signal;
	if (!sig)
		return 0;

	mm_maxrss = get_mm_maxrss(task);
	utime = task->utime;
	stime = task->stime;
	update_rusage_val(idx, ru_utime.tv_sec, utime / NANOSEC);
	update_rusage_val(idx, ru_utime.tv_usec, (utime % NANOSEC)/1000);
	update_rusage_val(idx, ru_stime.tv_sec, stime / NANOSEC);
	update_rusage_val(idx, ru_stime.tv_usec, (stime % NANOSEC)/1000);
	update_rusage_val(idx, ru_nvcsw, sig->nvcsw + task->nvcsw);
	update_rusage_val(idx, ru_nivcsw, sig->nivcsw + task->nivcsw);
	update_rusage_val(idx, ru_minflt, sig->min_flt + task->min_flt);
	update_rusage_val(idx, ru_majflt, sig->maj_flt + task->maj_flt);
	update_rusage_val(idx, ru_inblock, sig->inblock);
	update_rusage_val(idx, ru_oublock, sig->oublock);
	update_rusage_val(idx, ru_maxrss, get_maxrss(sig->maxrss, mm_maxrss));
	utime = sig->cutime;
	stime = sig->cstime;
	update_rusage_cval(idx, ru_utime.tv_sec, utime / NANOSEC);
	update_rusage_cval(idx, ru_utime.tv_usec, (utime % NANOSEC)/1000);
	update_rusage_cval(idx, ru_stime.tv_sec, stime / NANOSEC);
	update_rusage_cval(idx, ru_stime.tv_usec, (stime % NANOSEC)/1000);
	update_rusage_cval(idx, ru_nvcsw, sig->cnvcsw);
	update_rusage_cval(idx, ru_nivcsw, sig->cnivcsw);
	update_rusage_cval(idx, ru_minflt, sig->cmin_flt);
	update_rusage_cval(idx, ru_majflt, sig->cmaj_flt);
	update_rusage_cval(idx, ru_inblock, sig->cinblock);
	update_rusage_cval(idx, ru_oublock, sig->coublock);
	update_rusage_cval(idx, ru_maxrss, sig->cmaxrss);
	__sync_fetch_and_add(&bysyscall_pertask_data[idx].rusage_gen, 1);

	asm volatile ("" ::: "memory");
	return 0;
}

char _license[] SEC("license") = "GPL v2";
