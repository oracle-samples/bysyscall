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

#ifndef __BYSYSCALL_H__
#define __BYSYSCALL_H__

#define BYSYSCALL_PINDIR		"/sys/fs/bpf/bysyscall/"
#define BYSYSCALL_PERTASK_PIN		BYSYSCALL_PINDIR "pertask"
#define BYSYSCALL_PERTASK_DATA_PIN	BYSYSCALL_PINDIR "bysyscal_bss"

#define BYSYSCALL_PERTASK_DATA_CNT	8192

#define BYSYSCALL_PERTHREAD_OFF_INVAL	-1

enum {
	_RUSAGE_SELF,
	_RUSAGE_CHILDREN,
	_RUSAGE_NUM
};

struct bysyscall_pertask_data {
	pid_t	pid;
	pid_t	tid;
	uid_t	uid;
	uid_t	euid;
	gid_t	gid;
	gid_t	egid;
	int child_threads;
	int rusage_gen;
	struct rusage rusage[_RUSAGE_NUM];
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
#define bysyscall_idx(i)		(i ? (i->value & (BYSYSCALL_PERTASK_DATA_CNT - 1)) : 0)
#define bysyscall_idx_valid(i)	 	(i >= 0 && i < BYSYSCALL_PERTASK_DATA_CNT)

#endif /* __BYSYSCALL_H__ */
