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
test_start "$0: verify pid match (baseline)"

test_run_cmd_local "./getpid"

test_pass

COUNT=1000

test_start "$0: verify $COUNT pid matches (baseline)"

test_run_cmd_local "./getpid $COUNT"

test_pass

test_start "$0: verify pid match (test)"

$BYSYSCALL_CMD &

export $BYSYSCALL_LD_PRELOAD
test_run_cmd_local "./getpid"

test_pass

test_start "$0: verify $COUNT pid matches (test)"

test_run_cmd_local "./getpid $COUNT"

test_pass


test_cleanup

test_exit
