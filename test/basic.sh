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

for MODE in "" "fork" "pthread" ; do

for PROG in getpid gettid getuid getgid getrusage ; do

for SUFFIX in "" "_linked" ; do

# only have _linked variant for gettid
if [ $PROG == "gettid" ]; then
	if [[ -z "$SUFFIX" ]]; then
		continue
	fi
else
	test_start "$0: verify $PROG match (baseline)"

	test_run_cmd_local "./${PROG} 1 $MODE" true

	test_pass

	COUNT=1000

	test_start "$0: verify $COUNT $PROG matches (baseline) $MODE"

	test_run_cmd_local "./${PROG} $COUNT $MODE" true

	test_pass
fi
if [[ -z "$SUFFIX" ]]; then
	PL="BYSYSCALL_LOG=info $BYSYSCALL_LD_PRELOAD"
else
	PL="BYSYSCALL_LOG=info"
fi

# skip single test for getrusage as we may not have cached data
# for first syscall
if [[ $PROG != "getrusage" ]]; then
test_start "$0: verify ${PROG}${SUFFIX} match (test$SUFFIX) $MODE"

$BYSYSCALL_CMD

if [[ ! -d "/sys/fs/bpf/bysyscall" ]]; then 
	echo "no bysyscall pin"
	test_cleanup
fi

eval $PL ./${PROG}${SUFFIX} 1 $MODE |grep "bypassed"

test_pass

fi

test_start "$0: verify $COUNT $PROG matches (test$SUFFIX) $MODE"

eval $PL ./${PROG}${SUFFIX} $COUNT $MODE |grep "bypassed"

test_pass

test_start "$0: verify $COUNT $PROG matches (test$SUFFIX, user $BPFUSER) $MODE"

sudo -u $BPFUSER $PL ./${PROG}${SUFFIX} $COUNT $MODE | grep "bypassed"

test_pass

done

done

done

test_cleanup

test_exit
