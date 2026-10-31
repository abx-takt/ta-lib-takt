# SPDX-License-Identifier: MIT
"""Conservative policy for complete strace -ff -yy logs of one command.

This observes syscalls; it is not an absence-of-malware proof or a sandbox.
Unknown or incomplete records never produce PASS.
"""

from pathlib import Path
import re

READ_ONLY = set("""
read readv pread64 preadv preadv2 lseek close close_range brk munmap mprotect
mremap madvise mincore mlock munlock mlockall munlockall futex futex_waitv
rseq set_robust_list get_robust_list rt_sigaction rt_sigprocmask rt_sigreturn
sigaltstack restart_syscall arch_prctl set_tid_address getpid gettid getppid
getuid geteuid getgid getegid getresuid getresgid getgroups getpgrp getpgid
getsid uname sysinfo prlimit64 getrlimit ugetrlimit getrusage times
clock_gettime clock_getres gettimeofday time nanosleep clock_nanosleep
sched_yield sched_getaffinity sched_getparam sched_getscheduler
sched_get_priority_max sched_get_priority_min getrandom stat lstat fstat
newfstatat statx access faccessat faccessat2 readlink readlinkat getcwd
getdents getdents64 statfs fstatfs statfs64 fstatfs64 fadvise64 fadvise64_64
mbind get_mempolicy set_mempolicy
poll ppoll select pselect6 epoll_create epoll_create1 epoll_ctl epoll_wait
epoll_pwait epoll_pwait2 eventfd eventfd2 pipe pipe2 dup dup2 dup3 umask
chdir fchdir wait4 waitid getcpu exit exit_group
""".split())
NETWORK = set("""
socket socketpair connect bind listen accept accept4 sendto sendmsg sendmmsg
recvfrom recvmsg recvmmsg shutdown getsockname getpeername setsockopt getsockopt
""".split())
MUTATE = set("""
creat unlink unlinkat rename renameat renameat2 mkdir mkdirat rmdir link linkat
symlink symlinkat truncate ftruncate truncate64 ftruncate64 chmod fchmod
fchmodat fchmodat2 chown fchown lchown fchownat utime utimes futimesat utimensat
setxattr lsetxattr fsetxattr removexattr lremovexattr fremovexattr mknod mknodat
mount umount umount2 pivot_root chroot fallocate fanotify_init fanotify_mark
io_uring_setup io_uring_enter io_uring_register ptrace process_vm_writev
pidfd_getfd open_tree move_mount fsopen fsconfig fsmount mount_setattr
sendfile sendfile64 splice tee vmsplice copy_file_range sync syncfs fsync fdatasync
""".split())
OPEN = {"open", "openat", "openat2", "open_by_handle_at"}
WRITE = {"write", "writev", "pwrite64", "pwritev", "pwritev2"}
CALL = re.compile(r"^([a-zA-Z_][a-zA-Z_0-9]*)\((.*)\)\s+=\s+(.+)$")
# raw=ioctl,fcntl is mandatory: numeric argument fields cannot contain FD names.
RAW_NUMBER = re.compile(r"(?:0x[0-9a-f]+|[0-9]+|-[0-9]+)")
FCNTL_ALLOWED = {0, 1, 2, 3, 4, 5, 6, 7, 1030}
IOCTL_ALLOWED = {0x5401, 0x802c542a, 0x5413, 0x541b, 0x5451, 0x5450}
THREAD_FLAGS = {"CLONE_VM", "CLONE_FS", "CLONE_FILES", "CLONE_SIGHAND", "CLONE_THREAD",
                "CLONE_SYSVSEM", "CLONE_SETTLS", "CLONE_PARENT_SETTID",
                "CLONE_CHILD_SETTID", "CLONE_CHILD_CLEARTID"}
MMAP_PROT = {"PROT_NONE", "PROT_READ", "PROT_WRITE", "PROT_EXEC", "PROT_GROWSDOWN", "PROT_GROWSUP"}
MMAP_FLAGS = set("""MAP_SHARED MAP_SHARED_VALIDATE MAP_PRIVATE MAP_FIXED MAP_ANONYMOUS
MAP_32BIT MAP_GROWSDOWN MAP_DENYWRITE MAP_EXECUTABLE MAP_LOCKED MAP_NORESERVE
MAP_POPULATE MAP_NONBLOCK MAP_STACK MAP_HUGETLB MAP_SYNC MAP_FIXED_NOREPLACE
MAP_HUGE_2MB MAP_HUGE_1GB""".split())


def raw_command(args):
    parts = [field.strip() for field in args.split(",")]
    if len(parts) != 3 or any(not RAW_NUMBER.fullmatch(field) for field in parts):
        raise ValueError("Expected raw numeric ioctl/fcntl fields; annotations or ambiguous args rejected")
    return int(parts[1], 16 if parts[1].startswith("0x") else 10)


def clone_flags(name, args):
    # Linux x86-64 decoded forms only. Neither the flags value nor any
    # prefix before it may be obtained from a later FD/path annotation.
    # Extra occurrences are ambiguous (including in a filename): fail closed.
    if args.count("flags=") != 1:
        raise ValueError("Missing or ambiguous clone flags field")
    prefix = r"^\{flags=" if name == "clone3" else r"^(?:child_stack=(?:NULL|0x[0-9a-f]+),\s*)?flags="
    match = re.match(prefix + r"([A-Z0-9_|]+)(?=,|\}|$)", args)
    if not match:
        raise ValueError("Unsupported decoded clone flags position/value")
    tokens = match[1].split("|")
    if any(not re.fullmatch(r"CLONE_[A-Z0-9_]+|SIG[A-Z0-9_]+|0", token) for token in tokens) or len(set(tokens)) != len(tokens):
        raise ValueError("Unsupported or ambiguous clone flag tokens")
    return set(tokens)


def mapping_policy(args, safe_fds=False):
    # Only the first FOUR comma-delimited fields are used. A later FD annotation
    # may contain arbitrary filename text including commas, flags or angle brackets.
    fields = args.split(",", 4)
    if len(fields) != 5:
        raise ValueError("Incomplete mmap fields")
    protection = set(fields[2].strip().split("|"))
    flags = set(fields[3].strip().split("|"))
    if not protection or not protection <= MMAP_PROT or not flags or not flags <= MMAP_FLAGS:
        raise ValueError("Unsupported positional mmap protection/flags")
    bases = flags & {"MAP_PRIVATE", "MAP_SHARED", "MAP_SHARED_VALIDATE"}
    if len(bases) != 1:
        raise ValueError("Ambiguous mmap sharing flags")
    if "MAP_ANONYMOUS" not in flags and bases != {"MAP_PRIVATE"}:
        if "PROT_WRITE" in protection:
            return "writable shared file mapping"
        # In safe-fds mode the runner closes inherited descriptors, supplies
        # read-only stdin and pipe outputs. Every new writable file open is a
        # global violation; unknown FD-transfer interfaces are never PASS.
        # Thus an otherwise passing file-backed shared map uses O_RDONLY,
        # which lacks VM_MAYWRITE: Linux rejects a later writable mprotect.
        if not safe_fds:
            raise ValueError("File-backed shared mapping requires VMA tracking or enforced safe-fds; INCOMPLETE")
    return None


WRITE_FLAGS = re.compile(r"\bO_(?:WRONLY|RDWR|CREAT|TRUNC|APPEND|TMPFILE)\b")


def records(path):
    pending = None
    terminal = False
    for number, raw in enumerate(path.read_text(errors="replace").splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if terminal:
            raise ValueError(f"Record after terminal exit {path.name}:{number}")
        if re.fullmatch(r"\+\+\+ exited with \d+ \+\+\+", line):
            if pending:
                raise ValueError(f"Terminal exit with incomplete syscall {path.name}:{number}")
            terminal = True
            continue
        if line.startswith("--- SIG"):
            continue
        if line.endswith("<unfinished ...>"):
            if pending:
                raise ValueError(f"Overlapping incomplete record {path.name}:{number}")
            pending = line.removesuffix("<unfinished ...>")
            continue
        if line.startswith("<... ") and " resumed>" in line:
            if not pending:
                raise ValueError(f"Unmatched resumed record {path.name}:{number}")
            name, tail = line[5:].split(" resumed>", 1)
            if not pending.startswith(name + "("):
                raise ValueError(f"Resumed syscall mismatch {path.name}:{number}")
            line, pending = pending + tail, None
        match = CALL.match(line)
        if not match:
            raise ValueError(f"Unparsed trace record {path.name}:{number}")
        yield match.groups()
    if pending:
        raise ValueError(f"Unfinished syscall at end of {path.name}")
    if not terminal:
        raise ValueError(f"Missing normal terminal exit in {path.name}; truncated/detached trace")


def inspect(paths, safe_fds=False):
    violations, incomplete = [], []
    initial_execs = 0
    calls = 0
    for path in sorted(paths):
        try:
            for name, args, result in records(path):
                calls += 1
                reason = None
                if name in {"execve", "execveat"}:
                    initial_execs += 1
                    if initial_execs > 1 or not result.startswith("0"):
                        reason = "extra or failed exec attempt"
                elif name in NETWORK:
                    reason = "network syscall attempt"
                elif name in {"fork", "vfork"}:
                    reason = "new process attempt"
                elif name in {"clone", "clone3"}:
                    try:
                        flags = clone_flags(name, args)
                        if "CLONE_THREAD" not in flags:
                            reason = "non-thread clone attempt"
                        elif not flags <= THREAD_FLAGS:
                            incomplete.append(f"{path.name}: unsupported thread flags; untraced/new clone semantics cannot PASS")
                    except ValueError as error:
                        incomplete.append(f"{path.name}: {error}")
                elif name in MUTATE:
                    reason = "filesystem/process mutation or opaque side-effect interface"
                elif name in OPEN:
                    if WRITE_FLAGS.search(args) and not (
                            re.search(r'"/dev/null"', args)
                            and re.fullmatch(r"\d+</dev/null<char 1:3>>", result)):
                        reason = "file opened for writing"
                    elif re.search(r"(?:flags=|,\s*)0x[0-9a-f]+", args):
                        incomplete.append(f"{path.name}: unknown open flags")
                elif name in WRITE:
                    fd = args.split(",", 1)[0].strip()
                    if not re.fullmatch(r"[12]<pipe:\[\d+\]>", fd) and not re.fullmatch(r"\d+</dev/null<char 1:3>>", fd):
                        reason = "write outside declared stdout/stderr or /dev/null"
                elif name in {"mmap", "mmap2"}:
                    try:
                        reason = mapping_policy(args, safe_fds)
                    except ValueError as error:
                        incomplete.append(f"{path.name}: {error}")
                elif name == "fcntl":
                    try:
                        if raw_command(args) not in FCNTL_ALLOWED:
                            incomplete.append(f"{path.name}: unsupported raw fcntl command")
                    except ValueError as error:
                        incomplete.append(f"{path.name}: {error}")
                elif name == "ioctl":
                    try:
                        if raw_command(args) not in IOCTL_ALLOWED:
                            incomplete.append(f"{path.name}: unsupported raw ioctl command")
                    except ValueError as error:
                        incomplete.append(f"{path.name}: {error}")
                elif name not in READ_ONLY:
                    incomplete.append(f"{path.name}: unsupported syscall {name}")
                if reason:
                    violations.append({"trace": path.name, "syscall": name, "reason": reason})
        except (OSError, ValueError) as error:
            incomplete.append(str(error))
    if calls == 0 or initial_execs != 1:
        incomplete.append("Expected one successful initial exec and a nonempty complete trace")
    return {"syscalls": calls, "initial_exec_records": initial_execs,
            "violations": violations, "incomplete": incomplete,
            "status": "FAIL" if violations else "INCOMPLETE" if incomplete else "PASS"}


if __name__ == "__main__":
    import argparse
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", nargs="+", type=Path)
    result = inspect(parser.parse_args().trace)
    print(json.dumps(result, indent=2))
    raise SystemExit({"PASS": 0, "FAIL": 1, "INCOMPLETE": 3}[result["status"]])
