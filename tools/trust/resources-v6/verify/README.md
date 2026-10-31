# Observe one command

```sh
sh /path/to/installed-package/verify/pure.sh -- /absolute/COMMAND ARGS
```

Dependencies: Linux, Python 3, `unshare` and `strace`. The command runs once
inside a new network namespace under a complete syscall trace. Namespace and
tracer setup are outside the target trace. Exit 0 means all advertised checks
completed and no policy violation was observed. Exit 1 means a violation or
unsuccessful target; exit 3 means INCOMPLETE, never PASS.

The policy denies attempted network calls, extra execs, separate process
creation and filesystem mutation. Threads with CLONE_THREAD are allowed.
Reads and private writable mappings are allowed; shared writable file mappings,
file write opens and writes through other descriptors are denied. File-backed read-only
shared mappings return INCOMPLETE because a later mprotect could make them writable;
private and anonymous mappings remain permitted. mmap flags are parsed only from
their positional fields. ioctl/fcntl must be traced as raw numeric arguments; unknown
operations or annotated/ambiguous argument fields return INCOMPLETE. stdout/stderr
are isolated pipes forwarded by the untraced parent; writes through fd1/2 rebound
to regular files are denied. /dev/null is allowed. Every trace/TID must end with
an explicit normal terminal exit. Unknown/incomplete/truncated trace records or
unsupported side-effect interfaces cannot pass. Receipts and complete
traces remain in the printed temporary directory for inspection.
Environment values in execve are left abbreviated; traces can still contain
input/output fragments and arguments. Keep user-run receipts private unless
their contents have been reviewed for publication.

This is a diagnostic observation, not enforcement of filesystem purity, a
malware scanner or a proof of behavior on other inputs. A negative control that
writes a file must use a disposable working directory. The namespace blocks
external networking; a detected filesystem operation may already have occurred.

The result applies to the supplied command, arguments, inputs and environment.
It does **not** assert that the entire upstream package never uses files,
processes or networking: saving a model or user-requested upstream I/O correctly
fails this policy. Python bytecode generation and user caches are not hidden or
filtered. Use `python -B` when testing a Python call without bytecode writes,
and record that setting with the result. Loading existing code/data is permitted.

Signatures, artifact hashes and provenance establish different facts about
identity and integrity. None establishes absence of malicious behavior.

## Optional enforced descriptor boundary

`sh pure.sh --safe-fds -- COMMAND ARGS` supplies read-only `/dev/null` as fd0,
closes all other inherited descriptors, and isolates fd1/2 as output pipes.
The target cannot consume caller stdin in this mode. Do not use this mode for a
command whose inputs require stdin. Named input files are still read normally.

Only this enforced mode permits read-only shared file mappings: all new writable
file opens globally fail; FD-transfer interfaces are rejected or incomplete.
A shared mapping from an O_RDONLY descriptor lacks VM_MAYWRITE, so Linux rejects
mprotect enabling write (EACCES). Mutable private/anonymous mappings stay allowed.
This is a descriptor invariant, not an exception for named system files. Default
mode inherits stdin and keeps read-only shared mappings INCOMPLETE. All other
unknown-side-effect and trace-completeness checks remain fail-closed. The tool
still observes a concrete run and is not a general malware proof/sandbox.

Clone policy uses only the decoded flags field (anchored Linux x86-64 clone/clone3
forms), split into exact `|` tokens. CLONE_THREAD in cgroup/FD annotations does not
permit a separate process. Missing, duplicate or unsupported flags fields are
INCOMPLETE. A decoded field without CLONE_THREAD is FAIL.
Only the ordinary pthread flag family is supported: VM/FS/FILES/SIGHAND/THREAD/
SYSVSEM/SETTLS/PARENT_SETTID/CHILD_SETTID/CHILD_CLEARTID. THREAD with any other
flag, including CLONE_UNTRACED, is INCOMPLETE: descendant trace completeness
cannot be assumed. A decoded call without THREAD remains a process violation.
