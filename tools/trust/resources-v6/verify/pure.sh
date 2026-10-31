#!/bin/sh
# SPDX-License-Identifier: MIT
# Observe one complete command in an isolated network namespace and full strace.
set -eu
case "${1:-}" in --) shift ;; esac
[ "$#" -gt 0 ] || { echo "usage: pure.sh [--safe-fds] -- COMMAND [ARGS...]" >&2; exit 2; }
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 -B "$script_dir/pure_runner.py" "$@"
