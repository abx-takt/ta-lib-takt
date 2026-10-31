#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
output=pure-result.json
if [ "${1-}" = --output ]; then
    [ "$#" -ge 2 ] || exit 2
    output=$2
    shift 2
fi
if [ "${1-}" = -- ]; then shift; fi
case "$(uname -m)" in
    arm64|aarch64) target=macos_arm64 ;;
    *) target=macos_x86_64 ;;
esac
# Collector MISSING: helper returns 3 and does not execute these arguments.
exec python3 "$root/desktop_bootstrap.py" --target "$target" --output "$output" --pure -- "$@"
