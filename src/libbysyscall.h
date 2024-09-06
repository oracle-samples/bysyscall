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
#include <sys/time.h>
#include <sys/resource.h>

#include "bysyscall.h"

/* Add new bysyscalls here */
#define __BYSYSCALL_MAPPER(FN)	\
	FN(getpid),		\
	FN(gettid),		\
	FN(getuid),		\
	FN(getgid),		\
	FN(getrusage),


#define __BYSYSCALL_ENUM_FN(x)	BYSYSCALL_ ## x
enum bysyscall_id {
	__BYSYSCALL_MAPPER(__BYSYSCALL_ENUM_FN)
	BYSYSCALL_CNT
};

#define __BYSYSCALL_NAME_FN(x)	#x
const char *bysyscall_names[] = {
	__BYSYSCALL_MAPPER(__BYSYSCALL_NAME_FN)
};
