# bysyscall - using BPF to bypass system calls

In a post-SPECTRE/Meltdown world, the cost of system calls is high.
We have techniques like vDSO/vsyscall to mitigate system call overheads -
these operate on the basis that the cheapest system call is the one you do
not have to make. However there are limitations with vDSO and caching
techniques - one instructive example is `getpid()`.

`getpid()` support is complex because the value must be right, but a cached
value can be invalidated by events such as `fork()`ing a new process.

As a result glibc caching support for `getpid()` was removed [1], but it is
wanted - see [2].

It seems timely to ask - can BPF help here? It can do many of the things
vDSO does.

- BPF programs can run in the kernel and populate memory-mapped maps with
kernel data such that userspace can read those values (like pid in the
case of getpid()) without making a system call.
- BPF programs can trigger on specific events in kernel such as `fork()`ing
a new process, starting a new pthread or entering a pid namespace, and
update cache values in response to such events.

# bysyscall design

With this approach in mind, we can create

- an LD_PRELOAD libbysyscall shared library with its own versions of libc
functions which consult these memory-mapped values, falling back to the
libc functions if this fails.

- a user-space service and associated program (bysyscall), responsible
for launching BPF programs to help populate cache values and update them
in response to events.

The bysyscall service runs the bysyscall program, which loads and attaches
the set of BPF programs needed to update the shared memory map values
from the BPF side.  These are then pinned and the program exits. As a
result there is nothing running in userspace aside from the `LD_PRELOAD`ed
library to support syscall bypass.

On the BPF side, a hash map is used to map from a thread tid to an index in
the memory-mapped array of per-task data.  When the user loads the
libbysyscall library, the init function finds and `mmap()`s the pinned
array map of per-task data.  It then calls `__bysyscall_init()` with
a pointer to a per-thread integer index into the array map.

The BPF program instrumenting that function calls bpf_probe_write_user()
to write the relevant index and from then on callers of system call
wrappers can use that index to retrieve per-task data from the
memory-mapped array.

When a process that is using bysyscall calls `fork()`, we instrument
the `fork()` return for the child process (where the return value is 0).
In this case, we check if the parent process is indeed using bysyscall
(it has an index map entry), and if it does we populate the newly-created
process array map values and update the index to point at that task.

`pthread_create()` is similar.  We instrument libpthread's
`start_thread()` function and dynamically compute the offset of
the per-thread variable holding the array map index; it is
found relative to the `pthread_t` argument to `start_thread()`.
Once we have the address of the per-thread index variable and
the task struct, we can initialize the per-thread data and
set the index in the per-thread variable before the user method
runs.  This means the cached values can always be used in the
thread context.

In the fork() case the same address is used but in different address
spaces, so copy-on-write assures that we have the appropriate values.

```
Userspace		    				Kernel
		     	  	+-----------+	
				|           |
				|           |
syscall wrappers read <=======  |shared map | <== BPF programs update per-task
per-task data from		|           |	  data (pid, uid)
shared map using		|           |
perthread array index		+-----------+

perthread array index <========================== BPF programs write per-thread
						  index value for newly-created
						  tasks using libbysyscall,
						  or tasks fork()ed from
						  such tasks
```

# Why is this needed?

With the approach of using an `LD_PRELOAD` library, a reasonable question
is why use BPF at all? We could just cache the relevant values like
pid, uid etc.

This is where BPF comes in - by attaching BPF programs to the
right places, we can update our cached values when things change
(e.g. a `setuid()` call changing the uid, a process fork etc).

In addition some system calls like `getrusage()` are not amenable to
caching as their values keep changing.

Finally we see in the `pthread_create()` case that BPF instrumentation
allows us to catch thread creation and prepare our cached data
ahead of thread execution.

# Getting started

If building the repository manually, simply run

```
$ make ; sudo make install
```

To build, the following packages are needed (names may vary by distro);

- libbpf, libbpf-devel >= 1
- bpftool >= 4.18
- clang >= 11
- llvm >= 11
- python3-docutils

From the kernel side, BPF trampoline (fentry/fexit) needs to be
supported along with kernel BTF; check for presence of
`/sys/kernel/btf/vmlinux`.

# bysyscall usage

To use bysyscall it will then be a matter of using the LD_PRELOAD approach
to launch your program (once the bysyscall service has been started)


```
$ service bysyscall start

$ LD_PRELOAD=/usr/lib64/libbysyscall.so myprogram
```

When a program is launched this way, libbysyscall's replacement library
wrapper functions will be run, avoiding system calls where possible.

Alternatively, you can build your program linking -lbysyscall.  If doing
so, it is necessary to add `--wrap` [3] options for each library function
you wish to override.

For example, to compile a program with -lbysyscall to override `getpid()`:

```
$ cc -o myprog myprog.c -lbysyscall -Wl,--wrap=getpid
```

Additional ovverrides should be added with more `-Wl,--wrap=<function>'
options.

# Supported syscall wrapper functions

Per-task bysyscall wrappers are provided for

- `getpid()`
- `getuid()`
- `getgid()`
- `getrusage()`

# Example usage

`getpid` is a simple program that calls getpid the specified number of times,
then compares the result to the raw syscall to ensure it was right each time.

Running this with baseline (no bysyscall in the picture for 10000000 calls to
`getpid()` we see:

```
$ time ./getpid 10000000
10000000 pid from getpid() (423483) matches pid from syscall (423483)

real	0m0.989s
user	0m0.321s
sys	0m0.667s
```

So this takes ~1 second.  Now with bysyscall, and our LD_PRELOAD library:

```
$ sudo service bysyscall start
# loads/attaches syscall bypass progs and pins them to
# /sys/fs/bpf/bysyscall , then exits.
$ time LD_PRELOAD=/usr/lib64/libbysyscall.so ./getpid 10000000
10000000 pid from getpid() (423444) matches pid from syscall (423444)

real	0m0.083s
user	0m0.082s
sys	0m0.001s

```

It took less than 1/10 of a second this time.  Note the `sys` time;
for the baseline case it was 0.667 seconds, for the test case it was
0.001 seconds, indicating much less time in-kernel.

Investigating with DTrace, let's compare running a version of
getpid linked with libbyscall (`getpid_linked`) versus a version using
libc only.  Baseline first:

```
# dtrace -n 'syscall:::entry /pid ==$target/{@c[probefunc] = count(); }' -c './getpid 1000'
dtrace: description 'syscall:::entry ' matched 343 probes
1000 pid from getpid() (2063846) matches pid from syscall (2063846)

  exit_group                                                        1
  getrandom                                                         1
  newfstat                                                          1
  write                                                             1
  brk                                                               3
  getpid                                                         1001
```

So, as expected we see ~1000 `getpid()` system calls.  Now with the
libbysyscall-linked version:

```
# dtrace -n 'syscall:::entry /pid ==$target/{@c[probefunc] = count(); }' -c './getpid_linked 1000'
dtrace: description 'syscall:::entry ' matched 343 probes
1000 pid from getpid() (2063997) matches pid from syscall (2063997)

  exit_group                                                        1
  getpid                                                            1
  getrandom                                                         1
  newfstat                                                          1
  write                                                             1
  brk                                                               3
```

Only 1 getpid() system call is done!  (This is done deliberately bypassing
the getpid() wrapper to check that the values we retrieve are correct).
So we can see the difference in terms of syscall overhead can be significant.

We can try using `LD_PRELOAD=/usr/lib64/libbysyscall.so` with other programs.
If we set `BYSYSCALL_LOG=info`, libbysyscall will log additional info on
how many times bypass occurred:

```
$ BYSYSCALL_LOG=info LD_PRELOAD=/usr/lib64/libbysyscall.so /usr/bin/python3
Python 3.6.8 (default, May 24 2024, 06:39:46) 
[GCC 8.5.0 20210514 (Red Hat 8.5.0-21.0.1)] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> exit()
getpid: bypassed 2 times
getuid: bypassed 1 times
getgid: bypassed 1 times
$
```

# Testing

Tests can be run via

```
# sudo make test
```

...either at the toplevel, or in the `test/` subdirectory.

# Security

Please consult the [security guide](./SECURITY.md) for our responsible security vulnerability disclosure process

# License

Copyright (c) 2024 Oracle and/or its affiliates.

This software is available to you under

SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note

Being under the terms of the GNU General Public License version 2.

SPDX-URL: https://spdx.org/licenses/GPL-2.0.html

See [the license file](./LICENSE.txt) for more details.

# References

- [1] https://bugzilla.redhat.com/show_bug.cgi?id=1443976
- [2] https://bugzilla.redhat.com/show_bug.cgi?id=1469670
- [3] https://sourceware.org/binutils/docs-2.23.1/ld/Options.html#index-g_t_002d_002dwrap_003d_0040var_007bsymbol_007d-263
