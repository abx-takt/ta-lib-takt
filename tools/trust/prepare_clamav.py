# SPDX-License-Identifier: MIT
"""Create and verify a fresh scanner directory before invoking freshclam."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re


def prepare(root, owner):
    root = root.absolute()
    if any(c.isspace() for c in str(root)) or any(c in str(root) for c in '\\"\x00'):
        raise ValueError("Scanner workspace must be a simple absolute path")
    if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_-]*\$?", owner):
        raise ValueError("Invalid scanner database owner")
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    database = root / "db"
    database.mkdir(mode=0o700)
    config = root / "freshclam.conf"
    content = ("DatabaseMirror database.clamav.net\n"
               "DatabaseDirectory " + str(database) + "\n"
               "DatabaseOwner " + owner + "\n").encode("ascii")
    with os.fdopen(os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as target:
        target.write(content)
    os.chmod(config, 0o600)
    actual = config.read_bytes()
    if actual != content or len(actual.splitlines()) != 3 or b"\\n" in actual:
        raise ValueError("Scanner configuration bytes differ from expected LF directives")
    if not database.is_dir() or not os.access(database, os.R_OK | os.W_OK | os.X_OK):
        raise ValueError("Scanner database directory is not accessible")
    if config.is_symlink() or (config.stat().st_mode & 0o777) != 0o600:
        raise ValueError("Scanner configuration permissions are unsafe")
    return {"config": str(config), "database": str(database), "owner": owner,
            "config_sha256": hashlib.sha256(actual).hexdigest(), "config_bytes": len(actual),
            "config_lines": 3, "config_mode": "0600", "database_mode": "0700",
            "network_requests": 0, "scanner_execution": False}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--metadata", type=Path, required=True)
    p.add_argument("--owner", help="Explicit updater account when preparing standard paths with sudo")
    args = p.parse_args()
    result = prepare(args.root, args.owner or pwd.getpwuid(os.getuid()).pw_name)
    args.metadata.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))
