# bysyscall - using BPF to bypass system calls

In a post-SPECTRE/Meltdown world, the cost of system calls is high.
We have techniques like vDSO/vsyscall to mitigate system call overheads -
these operate on the basis that the cheapest system call is the one you do
not have to make. However there are limitations with vDSO techniques -
one instructive example is `getpid()`.

`getpid()` support is complex because the value must be right but a cached
value can be invalidated by events such as `fork()`ing a new process,
or entering a pid namespace.

As a result support for `getpid()` was removed from vDSO [1], but it is
wanted - see [2].

It seems timely to ask - can BPF help here? It can do many of the things
vDSO does.

- BPF programs can run in the kernel and populate memory-mapped maps with
kernel data such that userspace can read those values (like pid in the
case of getpid()) without making a system call.
- BPF programs can trigger on specific events in kernel such as entering
a pid namespace and update cache values in response to such events.

# bysyscall design

With this approach in mind, we can create

- an LD_PRELOAD libbysyscall shared library with its own versions of libc
functions which consult these memory-mapped values, falling back to the
libc functions if this fails.

- a user-space service and associated program (bysyscall) is responsible
for launching BPF programs to help populate cache values and update them
in response to events.

The bysyscall service runs the bysyscall program, which loads and attaches
the set of BPF programs needed to update the shared memory map values
from the BPF side.  These are then pinned and the program exits. As a
result there is nothing running in userspace aside from the `LD_PRELOAD`ed
library to support syscall bypass.

# bysyscall usage

To use bysyscall it will then be a matter of using the LD_PRELOAD approach
to launch your program (once the bysyscall service has been started)


```
$ service bysyscall start

$ LD_PRELOAD=/usr/lib64/libbsyscall.so myprogram
```

When a program is launched this way, libybsyscall's replacement library
wrapper functions will be run, avoiding system calls where possible.

# Supported syscall wrapper functions

Per-task bysyscall wrappers are provided for

- `getpid()`
- `getuid()`
- `getgid()`

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

It took less than 1/10 of a second this time.

We can try the same with other programs.  If we set BYSYSCALL_LOG=info,
libbysyscall will log additional info about how many times bypass occurred:

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

[1] https://bugzilla.redhat.com/show_bug.cgi?id=1443976
[2] https://bugzilla.redhat.com/show_bug.cgi?id=1469670
