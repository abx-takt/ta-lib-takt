/* SPDX-License-Identifier: MIT. $target is the stopped trusted launcher PID. */
#pragma D option quiet
#pragma D option bufsize=16m
#pragma D option switchrate=10hz
dtrace:::BEGIN { printf("B|%d\n", $target); }
syscall:::entry /pid == $target/ {
    printf("S|%d|%s|%x|%x|%x|%x|%x|%x\n", tid, probefunc, arg0, arg1, arg2, arg3, arg4, arg5);
}
mach_trap:::entry /pid == $target/ {
    printf("M|%d|%s|%x|%x|%x|%x|%x|%x\n", tid, probefunc, arg0, arg1, arg2, arg3, arg4, arg5);
}
proc:::exit /pid == $target/ { printf("T|%d\n", args[0]); exit(0); }
dtrace:::END { printf("E\n"); }
