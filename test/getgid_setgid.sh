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

GROUPID=$(id -g $BPFUSER)

test_setup true

for MODE in "none" "fork" "pthread" ; do

for PROG in getgid ; do

for SUFFIX in "" "_linked" ; do

test_start "$0: verify $PROG match when setting $GROUPID (baseline)"

test_run_cmd_local "./${PROG} 1 $MODE $GROUPID" true

test_pass

COUNT=1000

test_start "$0: verify $COUNT $PROG matches when setting $GROUPID (baseline) $MODE"

test_run_cmd_local "./${PROG} $COUNT $MODE $GROUPID" true

test_pass

test_start "$0: verify ${PROG}${SUFFIX} match when setting $GROUPID (test$SUFFIX) $MODE"

$BYSYSCALL_CMD

if [[ ! -d "/sys/fs/bpf/bysyscall" ]]; then 
	echo "no bysyscall pin"
	test_cleanup
fi


if [[ -z "$SUFFIX" ]]; then
	PL=$BYSYSCALL_LD_PRELOAD
else
	PL=""
fi
eval $PL ./${PROG}${SUFFIX} 1 $MODE |grep "bypassed"

test_pass

test_start "$0: verify $COUNT $PROG matches when setting $GROUPID (test$SUFFIX) $MODE"

eval $PL ./${PROG}${SUFFIX} $COUNT $MODE |grep "bypassed"

test_pass

test_start "$0: verify $COUNT $PROG matches when setting $GROUPID (test$SUFFIX, user $BPFUSER) $MODE"

sudo -u $BPFUSER $PL BYSYSCALL_LOG=info $PL ./${PROG}${SUFFIX} $COUNT |\
        grep "bypassed"

test_pass

done

done

done

test_cleanup

test_exit
