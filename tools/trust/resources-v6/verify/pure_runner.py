# SPDX-License-Identifier: MIT
"""Run namespace and trace checks together, retaining a concrete-run receipt."""

import json
import contextlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from trace_check import inspect


def main():
    command = sys.argv[1:]
    safe_fds = command[:1] == ["--safe-fds"]
    if safe_fds:
        command = command[1:]
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        return 2
    missing = [name for name in ("unshare", "strace") if not shutil.which(name)]
    if missing:
        print("INCOMPLETE: missing " + ", ".join(missing))
        return 3
    command[0] = shutil.which(command[0]) or command[0]
    report = Path(tempfile.mkdtemp(prefix="takt-pure-"))
    probe = subprocess.run(["unshare", "-rn", "--", "true"], capture_output=True)
    if probe.returncode:
        (report / "namespace.stderr").write_bytes(probe.stderr)
        (report / "RESULT.json").write_text(json.dumps({"status": "INCOMPLETE", "target_ran": False,
            "reason": "unshare -rn unavailable", "target_command": command}, indent=2) + "\n")
        print(f"INCOMPLETE: unshare -rn unavailable; target was not run; receipt {report}")
        return 3
    argv = ["unshare", "-rn", "--", "strace", "-ff", "-q", "-yy", "-s", "256",
            "-e", "raw=ioctl,fcntl", "-o", str(report / "trace"), "--", *command]
    # Do not use subprocess.DEVNULL here: Python opens it O_RDWR. Explicit rb
    # makes fd0 read-only. close_fds=True also closes unrelated inherited FDs.
    with open("/dev/null", "rb") if safe_fds else contextlib.nullcontext(None) as input_stream:
        completed = subprocess.run(argv, stdin=input_stream, close_fds=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    sys.stdout.buffer.write(completed.stdout)
    sys.stderr.buffer.write(completed.stderr)
    sys.stdout.buffer.flush()
    sys.stderr.buffer.flush()
    result = inspect(list(report.glob("trace.*")), safe_fds=safe_fds)
    result.update(target_command=command, target_returncode=completed.returncode,
                  safe_fds_enforced=safe_fds, stdin_policy="read-only /dev/null" if safe_fds else "inherited stdin; conservative shared-file policy",
                  other_inherited_fds="closed explicitly", network_namespace=True, scope="observations for this complete command and inputs only",
                  stdout_stderr="declared output streams", threads="CLONE_THREAD allowed; separate processes denied")
    if completed.returncode != 0 and result["initial_exec_records"] > 0:
        result["status"] = "FAIL"
        result["violations"].append({"reason": "target/tracer did not complete with exit 0"})
    (report / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"{result['status']}: {result['syscalls']} syscalls; receipt {report}")
    if result["violations"]:
        print(json.dumps(result["violations"][:5]))
    if result["incomplete"]:
        print(json.dumps(result["incomplete"][:5]))
    return {"PASS": 0, "FAIL": 1, "INCOMPLETE": 3}[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
