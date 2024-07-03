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

[1] https://bugzilla.redhat.com/show_bug.cgi?id=1443976
[2] https://bugzilla.redhat.com/show_bug.cgi?id=1469670
