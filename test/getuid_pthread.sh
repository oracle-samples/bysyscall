#!/usr/bin/bash
#
# SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#
# Copyright (c) 2024, Oracle and/or its affiliates.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public
# License v2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this program; if not, write to the
# Free Software Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 021110-1307, USA.
#

. ./test_lib.sh

test_setup true
test_start "$0: verify uid match after pthread_create (baseline)"

test_run_cmd_local "./getuid 1 pthread" true

test_pass

COUNT=1000

test_start "$0: verify $COUNT uid matches after pthread_create (baseline)"

test_run_cmd_local "./getuid $COUNT 1000 pthread" true

test_pass

test_start "$0: verify uid match after pthread_create (test)"

$BYSYSCALL_CMD

if [[ ! -d "/sys/fs/bpf/bysyscall" ]]; then 
	echo "no bysyscall pin"
	test_cleanup
fi


eval $BYSYSCALL_LD_PRELOAD ./getuid 1 pthread_create 2>&1|grep "bypassed 1"

test_pass

test_start "$0: verify $COUNT uid matches after pthread_create (test)"

eval $BYSYSCALL_LD_PRELOAD ./getuid $COUNT pthread_create 2>&1|grep "bypassed $COUNT"

test_pass

test_cleanup

test_exit
