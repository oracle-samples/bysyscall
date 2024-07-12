# Contributing to bpftune

We welcome your contributions! There are multiple ways to contribute.

## Opening issues

For bugs or enhancement requests, please file a GitHub issue unless it is security related. When filing a bug remember that the better written the bug is, the more likely it is to be fixed. If you think you have found a security vulnerability, do not raise a GitHub issue and follow the instructions in our security policy documented in SECURITY.md.

## Contributing code

We welcome your code contributions. Before submitting code via a pull request, you will need to have signed the Oracle Contributor Agreement (OCA) at

https://oca.opensource.oracle.com/

...and your commits need to include the following line using the name and e-mail address you used to sign the OCA:

Signed-off-by: Your Name <you@example.org>

This can be automatically added to pull requests by committing with --sign-off or -s, e.g.

git commit --signoff

Only pull requests from committers that can be verified as having signed the OCA can be accepted.

## Pull request process

-   Ensure there is an issue created to track and discuss the fix or enhancement you intend to submit.
-    Fork this repository.
-    Create a branch in your fork to implement the changes. We recommend using the issue number as part of your branch name, e.g. 1234-fixes.
-    Ensure that any documentation is updated with the changes that are required by your change.
-    Ensure that any samples are updated if the base image has been changed.
-    Ensure that all changes comply to project coding conventions as documented here
-    Ensure that there is at least one test that would fail without the fix and passes post fix.
-    Submit the pull request. Do not leave the pull request blank. Explain exactly what your changes are meant to do and provide simple steps on how to validate your changes. Ensure that you reference the issue you created as well.
-    We will assign the pull request for review before it is submitted internally and the PR is closed.

## Code of conduct

Follow the Golden Rule. If you would like more specific guidelines, see the Contributor Covenant Code of Conduct at

https://www.contributor-covenant.org/version/1/4/code-of-conduct/

## Technical guide to contribution

The architecture used is

- a core program, src/bysyscall.c that loads src/bysyscall.bpf.c
  BPF programs and pins them to /sys/fs/bpf/bysyscall.
- a library, libbysyscall which provides override functions for system
  call wrappers like getpid etc.

Adding a new wrapper involves adding it to `FNS()` list in src/libbysyscall.c
and adding the function itself to src/libbysyscall.c.  As well as adding
the `function()`, add `__wrap_function()` since the latter is needed
for dynamic linking; `__wrap_function()` should simply call `function()`.

Also add tests to tests/ to check your syscall wrapper override works and
matches the results from the syscall itself.
