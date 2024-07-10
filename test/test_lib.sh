#!/usr/bin/bash
#
# SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#
# Copyright (c) 2023, Oracle and/or its affiliates.
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

# Setup/teardown code for testing.

export TEST_ID=${TEST_ID:-}
export TESTDIR="/tmp/bysyscalltest"
export TESTLOG_PREFIX="${TESTDIR}/testlog"
export TESTLOG=${TESTLOG:-"${TESTLOG_PREFIX}.${PPID}"}
export TESTLOG_LAST="${TESTDIR}/testlog.last"
export TESTLOG_COUNT="${TESTDIR}/testcount.$TEST_ID"

export SETUPTIME=5
export SLEEPTIME=1

# 1: more output, >1: xtrace
export VERBOSE=${VERBOSE:-0}

export BYSYSCALL_LOG=${BYSYSCALL_LOG:-}

if [[ "$VERBOSE" == "1" ]]; then
	export DEBUG=1
	export BYSYSCALL_LOG="debug"
else
	export DEBUG=${DEBUG:-0}
	export BYSYSCALL_LOG="info"
fi
# Set the following to 1 if you want to see state after failure.
export SKIP_CLEANUP=${SKIP_CLEANUP:-0}

check_prog()
{
	PROGPATH=$1
	PROGNAME=$2
	PKGNAME=$3

	if [ -z "$PROGPATH" ]; then
		echo "no '$PROGNAME'; install $PKGNAME"
		exit 1
	fi
}

export NC=$(which nc 2>/dev/null)
check_prog "$NC" nc nmap-ncat
export TC=$(which tc 2>/dev/null)
check_prog "$TC" tc iproute-tc
export IPERF3=$(which iperf3 2>/dev/null)
check_prog "$IPERF3" iperf3 iperf3
export QPERF=$(which qperf 2>/dev/null)
export FIREWALL_CMD=$(which firewall-cmd 2>/dev/null)
export AUDIT_CMD=$(which auditctl 2>/dev/null)
export LOGFILE=${LOGFILE:-"/var/log/messages"}

export B=$(tput -Tvt100 bold)
export N=$(tput -Tvt100 sgr0)

test_init()
{
	if [ $VERBOSE -gt 0 ]; then
		set -o xtrace
	fi
	set -o nounset
	set -o errexit

	mkdir -p $TESTDIR
	if [[ -n "$TEST_ID" ]]; then
		if [[ ! -f $TESTLOG_COUNT ]]; then
			echo 0 > $TESTLOG_COUNT
		fi
		export PASSED=${PASSED:-$(cat $TESTLOG_COUNT)}
	else
		export PASSED=${PASSED:-0}
	fi
}

export CMD_PIDFILE="${TESTDIR}/.current_test_cmd.pid"

export BANDWIDTH=${BANDWIDTH:-"0"}

export TIMEOUT=${TIMEOUT:-"30"}

export TEST_INFO="No test running yet"
export NUM_TESTS=0

export TARGET=127.0.0.1

if [[ "$DEBUG" != 0 ]]; then
	export BYSYSCALL_FLAGS="${BYSYSCALL_FLAGS} -d"
fi
export BYSYSCALL_PROG=${BYSYSCALL_PROG:-"/usr/sbin/bysyscall"}
export BYSYSCALL="${BYSYSCALL_PROG} $BYSYSCALL_FLAGS"
export BYSYSCALL_CMD=${BYSYSCALL_CMD:-"$BYSYSCALL"}
export BYSYSCALL_LIB=${BYSYSCALL_LIB:-"/usr/lib64/libbysyscall.so"}
export BYSYSCALL_LD_PRELOAD=${BYSYSCALL_LD_PRELOAD:-"LD_PRELOAD=$BYSYSCALL_LIB "}

# Don't want __pycache__ files hanging around.
export PYTHONCMD="python3 -B"

export EXITCODE=1

bold()
{
	echo "${B}$1${N}"
}

test_run_cmd_local()
{
	CMDLOG="${TESTDIR}/testlog.$$"
	CMD="$1"
	DO_REDIRECT=${2:-"false"}

	if [[ $VERBOSE -gt 0 ]]; then
		echo "Running \"$CMD\" on $(uname -n)."
	fi

	if [[ "$DO_REDIRECT" == "true" ]]; then
		rm -f $TESTLOG_LAST
		touch $CMDLOG
		ln -s $CMDLOG $TESTLOG_LAST
		if [[ $VERBOSE -gt 0 ]]; then
			echo "For output see ${CMDLOG}"
		fi
        fi

	BGCMD="&"
	if [[ "$CMD" =~ $BGCMD ]]; then
		NOBGCMD="$(echo $CMD | sed 's/&//g')"
		if [[ $DO_REDIRECT == "true" ]]; then
			( $NOBGCMD >>$CMDLOG 2>&1 </dev/null  ) &
		else
			( $NOBGCMD >>/dev/null 2>&1 </dev/null ) &
		fi
		CMD_PID=$!
		echo $CMD_PID >> $CMD_PIDFILE
	else
		if [[ $DO_REDIRECT == "true" ]]; then
			timeout $TIMEOUT $CMD >>$CMDLOG 2>&1
		else
			timeout $TIMEOUT $CMD
		fi
	fi
}

test_setup_local()
{
	CMD=$1
	TIMEOUT=$2

	set +e
	$BYSYSCALL_PROG stop 2>/dev/null
	set -e
	if [[ -f "$AUDIT_CMD" ]]; then
		$AUDIT_CMD -e 0 >/dev/null 2>&1
	fi
	test_run_cmd_local "$CMD" true
}

test_cleanup_local()
{
	EXIT=$1

	unset LD_PRELOAD
	sleep 0.2
	if [ -f "$CMD_PIDFILE" ]; then
		CMD_PIDS=`cat $CMD_PIDFILE`
		for CMD_PID in $CMD_PIDS ; do
			kill -TERM $CMD_PID >/dev/null 2>&1 || true
		done
		rm -f $CMD_PIDFILE
	fi

	set +e
	pkill -TERM bysyscall
	$BYSYSCALL_PROG stop 2>/dev/null
	set -e

	if [[ $EXIT -ne 0 ]]; then
		if [[ -f $TESTLOG_LAST ]]; then
			echo "Output of last command:"
			cat $TESTLOG_LAST
		fi
	else
		# Clear log for next test
		echo "" > $TESTLOG_LAST
	fi
}

test_log_result()
{
	if [ $EXITCODE -ne 0 ]; then
		RESULT="FAIL; error $EXITCODE|"
	else
		RESULT="PASS($PASSED)"
	fi
	NUM_TESTS=`expr $NUM_TESTS + 1`

	bold "$TEST_INFO|$RESULT"
	bold "$TEST_INFO|$RESULT" >> $TESTLOG
}

test_exit()
{
	exit $EXITCODE
}

test_cleanup()
{
	trap - EXIT

	test_cleanup_local $EXITCODE
	if [ $EXITCODE -ne 0 ]; then
		test_log_result
		exit 1
	fi
}

test_cleanup_exit()
{
	BC=${BASH_COMMAND}
        if [[ -n "$BC" ]]; then
                echo "Last command executed: '$BC'"
        fi
	if [[ $SKIP_CLEANUP -ne 0 ]]; then
		echo "skipping cleanup as requested"
		if [ $EXITCODE -ne 0 ]; then
			test_log_result
		fi
	else
		test_cleanup
	fi
	test_exit
}

test_setup()
{
	CMD="$1"

	if [ "$(id -u)" != "0" ]; then
		echo "Sorry, tests must run as root"
		exit 1
	fi
	mkdir -p $TESTDIR

	trap test_cleanup_exit EXIT

	test_setup_local "$CMD" $TIMEOUT
}

test_start()
{
	TEST_INFO=$1

	bold "$TEST_INFO|START"
	bold "$TEST_INFO|START" >> $TESTLOG
	# Tests fail by default; need explicit test_pass
	EXITCODE=1
}

test_log_info()
{
	INFO=$1

	echo $1
	echo $1 >> $TESTLOG
}

test_pass()
{
	EXITCODE=0
	PASSED=$(expr $PASSED + 1)
	if [[ -n "$TEST_ID" ]]; then
		echo $PASSED > $TESTLOG_COUNT
	fi
	test_log_result
}

test_end()
{
	if [ $EXITCODE -ne 0 ]; then
		test_cleanup_exit
	fi
}

roundup()
{
	echo $1 | awk -F '.' '$2 >= 5 { print $1 + 1} $2 < 5 { print $1}'
}

test_init
