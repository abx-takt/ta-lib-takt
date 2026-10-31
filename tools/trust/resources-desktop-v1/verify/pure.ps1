# SPDX-License-Identifier: MIT
param(
    [string]$Output = "pure-result.json",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Command
)
# No command execution until a native collector has passed completeness controls.
& python "$PSScriptRoot/desktop_bootstrap.py" --target windows_x86_64 --output $Output --pure -- @Command
exit $LASTEXITCODE
