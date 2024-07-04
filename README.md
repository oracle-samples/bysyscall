# bysyscall - using BPF to bypass system calls

In a post-SPECTRE/Meltdown world, the cost of system calls is high.
We have techniques like vDSO/vsyscall to mitigate system call overheads -
these operate on the basis that the cheapest system call is the one you do
not have to make. However there are limitations with vDSO techniques -
one instructive example is `getpid()`.

`getpid()` support is complex because the value must be right but a cached
value can be invalidated by events such as `fork()`ing a new process,
creating a new thread via pthread_create() or entering a pid namespace.
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

With this approach in mind, we can createan LD_PRELOAD library with its

- an LD_PRELOAD libbysyscall shared library with its own versions of libc
functions which consult these memory-mapped values, falling back to the
libc functions if this fails.

- a daemon (bysyscalld) is responsible for launching BPF programs to handle
populating values and updating them in response to events

# bysyscall usage

To use bysyscall it will then be a matter of using the LD_PRELOAD approach
to launch your program e.g.

LD_PRELOAD=/usr/lib64/libbsyscall.so myprogram

When a program is launched this way, libybsyscall's functions

# Supported libc syscall wrapper functions

Per-task bysyscall wrappers are provided for

- getpid()
- getppid()
- getuid()
- geteuid()

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
$ bysyscall # loads/attaches syscall bypass progs and pins them to
	    # /sys/fs/bpf/bysyscall , then exits.
$ time LD_PRELOAD=/usr/lib64/libbysyscall.so ./getpid 10000000
10000000 pid from getpid() (423444) matches pid from syscall (423444)

real	0m0.083s
user	0m0.082s
sys	0m0.001s
$ 
```

[1] https://bugzilla.redhat.com/show_bug.cgi?id=1443976
[2] https://bugzilla.redhat.com/show_bug.cgi?id=1469670
