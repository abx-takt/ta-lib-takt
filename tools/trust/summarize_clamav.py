# SPDX-License-Identifier: MIT
"""Summarize successful ClamAV logs without replacing scanner exit-code gates."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re


def summary(scan, definitions, update):
    log = scan.read_text()
    infected = re.findall(r"^Infected files:\s*(\d+)\s*$", log, re.MULTILINE)
    engines = re.findall(r"^Engine version:\s*(\S+)\s*$", log, re.MULTILINE)
    versions = re.findall(r"^ClamAV ([^/\s]+)/([0-9]+)/([^\r\n]+)$", definitions.read_text(), re.MULTILINE)
    if infected != ["0"] or len(engines) != 1 or len(versions) != 1:
        raise ValueError("Need an unambiguous zero-infected scan and dated database version")
    engine, database_version, database_date = versions[0]
    if engines[0] != engine:
        raise ValueError("Scanner/updater engine versions differ")
    if not update.read_bytes():
        raise ValueError("Mandatory freshclam stdout/stderr log is missing")
    return {"observed_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "engine_version": engine, "daily_database_version": int(database_version),
            "daily_database_build_date_as_reported": database_date,
            "infected_files": 0, "scanner_exit_gate": "separate mandatory shell pipefail",
            "logs_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                            for p in [scan, definitions, update]},
            "signal": "dated scanner observation; not a safety certificate"}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--scan", type=Path, required=True)
    p.add_argument("--definitions", type=Path, required=True)
    p.add_argument("--update", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    result = summary(a.scan, a.definitions, a.update)
    a.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))
