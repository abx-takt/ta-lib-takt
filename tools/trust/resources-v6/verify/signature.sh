#!/bin/sh
# SPDX-License-Identifier: MIT
# Verify final bytes against an explicitly expected GitHub workflow identity.
set -eu
[ "$#" -eq 3 ] || { echo 'usage: signature.sh ARTIFACT BUNDLE EXPECTED_WORKFLOW_IDENTITY' >&2; exit 2; }
exec cosign verify-blob "$1" --bundle "$2" --certificate-identity "$3" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
