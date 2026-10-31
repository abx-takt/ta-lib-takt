#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real DTrace collector around a user-owned stopped pre-exec launcher.

Diagnostic only: unknown calls, Mach IPC, drops and missing probes never PASS.
No system-protection setting changes, no client execution as root, no path capture.
"""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import subprocess
import tempfile
import time


NETWORK = {"socket", "socketpair", "connect", "connectx", "bind", "listen", "accept", "accept_nocancel", "sendto", "sendmsg", "recvfrom", "recvmsg", "sendmsg_x", "recvmsg_x", "setsockopt"}
PROCESS = {"fork", "vfork", "posix_spawn", "__mac_execve"}
MUTATION = {"unlink", "unlinkat", "rename", "renameat", "renameatx_np", "mkdir", "mkdirat", "rmdir", "link", "linkat", "symlink", "symlinkat", "truncate", "ftruncate", "chmod", "fchmod", "fchmodat", "chown", "fchown", "lchown", "utimes", "futimes", "setxattr", "fsetxattr", "removexattr", "fremovexattr", "exchangedata", "clonefileat", "fclonefileat"}


class CollectorUnavailable(RuntimeError):
    def __init__(self, code, diagnostic):
        super().__init__(code)
        self.code = code
        self.diagnostic_sha256 = hashlib.sha256(diagnostic.encode()).hexdigest()


def diagnostic_code(stderr):
    lower = stderr.lower()
    if any(item in lower for item in ("operation not permitted", "permission denied", "requires additional privileges", "password is required", "not allowed to execute")):
        return "TRACER_PRIVILEGE_OR_SIP_UNAVAILABLE"
    if any(item in lower for item in ("does not match any probes", "failed to match", "probe description")):
        return "REQUIRED_PROVIDER_UNAVAILABLE"
    return "TRACER_NOT_READY"


def begin_matches(data, target_pid):
    # A pipe read may legally coalesce BEGIN with the first target records.
    first_line, separator, _suffix = data.partition(b"\n")
    return bool(separator) and first_line == f"B|{target_pid}".encode()


def cleanup_tracer(tracer):
    """Stop only the observer session/group created by this Popen, even under sudo."""
    if tracer.poll() is not None:
        return
    for signum, signame in ((signal.SIGINT, "INT"), (signal.SIGKILL, "KILL")):
        try:
            os.killpg(tracer.pid, signum)
        except ProcessLookupError:
            pass
        except PermissionError:
            # start_new_session=True guarantees this PGID is observer-only, not target/driver.
            stopped = subprocess.run(["sudo", "-n", "/bin/kill", "-" + signame, "-" + str(tracer.pid)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False)
            if stopped.returncode and tracer.poll() is None:
                raise RuntimeError("OBSERVER_CLEANUP_PRIVILEGE_UNAVAILABLE")
        try:
            tracer.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            continue
    raise RuntimeError("OBSERVER_CLEANUP_INCOMPLETE")


def classify(provider, name, args):
    """Conservative positive detections; absence of a hit is not a proof."""
    if provider == "M":
        return None, "MACH_TRAP_ARGUMENTS_UNDECODED"
    if name in NETWORK:
        return "NETWORK_ATTEMPT", None
    if name in PROCESS:
        return "PROCESS_CREATION_OR_UNADMITTED_EXEC", None
    if name in MUTATION:
        return "FILE_MUTATION_ATTEMPT", None
    if name in {"write", "write_nocancel", "writev", "writev_nocancel", "pwrite", "pwrite_nocancel", "pwritev"}:
        return ("FILE_WRITE_ATTEMPT", None) if args[0] > 2 else (None, "STDIO_DESCRIPTOR_POLICY_UNPROVEN")
    if name in {"open", "open_nocancel", "open_extended", "open_dprotected_np", "__open_extended"}:
        flags = args[1]
    elif name in {"openat", "openat_nocancel", "openat_dprotected_np"}:
        flags = args[2]
    else:
        flags = None
    if flags is not None:
        # Darwin O_ACCMODE=3; O_CREAT=0x200; O_TRUNC=0x400; O_APPEND=8.
        if flags & (3 | 0x200 | 0x400 | 8):
            return "WRITABLE_OPEN_ATTEMPT", None
        return None, "READ_OPEN_PATH_POLICY_UNPROVEN"
    if name == "mmap" and args[2] & 2 and args[3] & 1:
        return "SHARED_WRITABLE_MAPPING_ATTEMPT", None
    return None, "SYSCALL_ARGUMENT_POLICY_UNPROVEN:" + name


def parse_trace(raw, stderr, expected_pid, tracer_rc):
    counts = collections.Counter()
    violations, gaps = set(), set()
    began = terminal = ended = False
    exec_count = 0
    for line in raw.splitlines():
        cells = line.split("|")
        if cells == ["B", str(expected_pid)] and not began and not ended:
            began = True
        elif len(cells) == 9 and cells[0] in {"S", "M"} and began and not ended:
            if not re.fullmatch(r"[0-9]+", cells[1]) or not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", cells[2]):
                gaps.add("MALFORMED_EVENT"); continue
            try:
                if not all(re.fullmatch(r"[0-9a-f]{1,16}", item) for item in cells[3:]): raise ValueError()
                args = [int(item, 16) for item in cells[3:]]
            except ValueError:
                gaps.add("MALFORMED_ARGUMENT"); continue
            counts[cells[0] + ":" + cells[2]] += 1
            if cells[0] == "S" and cells[2] in {"execve", "execve_nocancel"}:
                exec_count += 1
                if exec_count > 1: violations.add("PROCESS_REPLACEMENT_AFTER_INITIAL_EXEC")
            hit, gap = classify(cells[0], cells[2], args)
            if hit: violations.add(hit)
            if gap: gaps.add(gap)
        elif len(cells) == 2 and cells[0] == "T" and cells[1].isdigit() and began and not terminal:
            terminal = True
        elif cells == ["E"] and began and terminal and not ended:
            ended = True
        else:
            gaps.add("UNKNOWN_OR_OUT_OF_ORDER_RECORD")
    if not began or not terminal or not ended: gaps.add("INCOMPLETE_BOUNDARY")
    if not counts: gaps.add("NO_TARGET_EVENTS")
    if tracer_rc: gaps.add("TRACER_NONZERO")
    # Even an apparently harmless SIP warning is preserved as incomplete until native calibration.
    if stderr.strip(): gaps.add("TRACER_DIAGNOSTIC_OR_DROP")
    gaps.add("NATIVE_CALIBRATION_AND_FULL_POLICY_NOT_YET_CLOSED")
    return {"schema": "takt-native-purity-dtrace-diagnostic-v1", "status": "VIOLATION_OBSERVED" if violations else "INCOMPLETE", "purity_pass": False, "release_ready": False,
            "violations": sorted(violations), "coverage_gaps": sorted(gaps), "event_counts": dict(sorted(counts.items())), "begin_seen": began, "terminal_seen": terminal, "end_seen": ended,
            "tracer_rc": tracer_rc, "trace_sha256": hashlib.sha256(raw.encode()).hexdigest(), "diagnostic_sha256": hashlib.sha256(stderr.encode()).hexdigest()}


def collect(launcher, command, script, timeout):
    if platform.system() != "Darwin": raise RuntimeError("NATIVE_DARWIN_REQUIRED")
    for path in (launcher, script, Path(command[0])):
        if not path.is_file() or path.is_symlink(): raise ValueError("Regular input files required")
    child = tracer = None
    raw, diagnostic = "", ""
    gate_read, gate_write = os.pipe()
    with tempfile.TemporaryFile() as target_out, tempfile.TemporaryFile() as target_err, tempfile.TemporaryFile() as trace_err:
        try:
            # Only 0..2 are inherited. Target cannot inherit or forge the tracer's pipe.
            child = subprocess.Popen([str(launcher), "--gate-fd", str(gate_read), *command], stdin=subprocess.DEVNULL, stdout=target_out, stderr=target_err, close_fds=True, pass_fds=(gate_read,))
            os.close(gate_read); gate_read = -1
            stopped, status = os.waitpid(child.pid, os.WUNTRACED)
            if stopped != child.pid or not os.WIFSTOPPED(status): raise RuntimeError("PRE_EXEC_STOP_MISSING")
            # sudo is tracer-only. The target retains the caller's uid, SIP untouched.
            tracer = subprocess.Popen(["sudo", "-n", "/usr/sbin/dtrace", "-q", "-s", str(script), "-p", str(child.pid)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=trace_err, close_fds=True, start_new_session=True)
            if tracer.stdout is None: raise RuntimeError("TRACER_PIPE_MISSING")
            selector = selectors.DefaultSelector(); selector.register(tracer.stdout, selectors.EVENT_READ)
            first = b""; deadline = time.monotonic() + timeout
            while b"\n" not in first and time.monotonic() < deadline:
                if selector.select(0.1):
                    chunk = os.read(tracer.stdout.fileno(), 65536)
                    if not chunk: break
                    first += chunk
                elif tracer.poll() is not None: break
            selector.close()
            # No target code runs until the kernel tracer emits BEGIN for this PID.
            if not begin_matches(first, child.pid):
                trace_err.seek(0)
                diagnostic = trace_err.read().decode("utf-8", errors="replace")
                raise CollectorUnavailable(diagnostic_code(diagnostic), diagnostic)
            os.write(gate_write, b"G")
            os.close(gate_write); gate_write = -1
            os.kill(child.pid, signal.SIGCONT)
            more, _ = tracer.communicate(timeout=timeout)
            raw = (first + more).decode("utf-8", errors="strict")
            child.wait(timeout=5)
            trace_err.seek(0); diagnostic = trace_err.read().decode("utf-8", errors="replace")
            receipt = parse_trace(raw, diagnostic, child.pid, tracer.returncode)
            receipt.update(target_rc=child.returncode, target_uid=os.getuid(), scope="cold-target-exec-after-trusted-launcher-stop", target_stdout_bytes=target_out.tell(), target_stderr_bytes=target_err.tell())
            return receipt
        finally:
            for fd in (gate_read, gate_write):
                if fd >= 0: os.close(fd)
            if child is not None and child.poll() is None:
                child.kill(); child.wait()
            if tracer is not None:
                cleanup_tracer(tracer)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--launcher", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("command", nargs=argparse.REMAINDER)
    ns = ap.parse_args()
    command = ns.command[1:] if ns.command[:1] == ["--"] else ns.command
    if not command or ns.out.exists(): ap.error("New output and explicit target command required")
    try:
        receipt = collect(ns.launcher.resolve(), command, Path(__file__).with_name("macos.d"), ns.timeout)
    except Exception as error:
        receipt = {"schema": "takt-native-purity-dtrace-diagnostic-v1", "status": "INCOMPLETE", "purity_pass": False, "release_ready": False, "reason": "NATIVE_COLLECTOR_UNAVAILABLE_OR_FAILED", "exception_type": type(error).__name__}
        if isinstance(error, CollectorUnavailable):
            receipt.update(reason=error.code, diagnostic_sha256=error.diagnostic_sha256)
    ns.out.parent.mkdir(parents=True, exist_ok=True)
    ns.out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return 1 if receipt["status"] == "VIOLATION_OBSERVED" else 3


if __name__ == "__main__": raise SystemExit(main())
