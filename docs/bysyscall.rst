====================
BYSYSCALL,LIBBYSCALL
====================
-------------------------------------------------------------------------------
Bypass system calls with BPF
-------------------------------------------------------------------------------

:Manual section: 8

SYNOPSIS
========

	**bysyscall** [*OPTIONS*]

	*OPTIONS* := { { **start** | **stop** } }

DESCRIPTION
===========
	*bysyscall* loads, attaches and pins a set of BPF programs
        to support system call bypass.  Users can then
        LD_PRELOAD=libbysyscall.so <cmd> to override libc wrappers
        for libbysyscall versions which make use of shared data
        BPF collects to avoid having to make a system call.

        **bysyscall** requires *CAP_BPF* and *CAP_TRACING* capabilities,
        or *CAP_SYS_ADMIN* on older systemes.  It can be run via a systemd
        service, but can also be run standalone if required.  Running
        **bysyscall** will load, attach and pin the required programs
        and maps and exit.  It is run via the **bysysall** service.

        When a program runs with libbysyscall.so LD_PRELOADed the
        associated library init function is traced such that the
        required data is mmap()ed into the process.

        **bysyscall stop** will remove pinned programs/maps.

OPTIONS
=======
        start      
                  Start, attach and pin programs.
        stop
                  Unpin, detach programs.
