/* SPDX-License-Identifier: MIT -- trusted Unix pre-exec boundary, no target code yet. */
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc < 4 || strcmp(argv[1], "--gate-fd")) return 64;
    char *end = NULL;
    long gate_number = strtol(argv[2], &end, 10);
    if (!end || *end || gate_number < 3 || gate_number > 1048575) return 64;
    int gate = (int)gate_number;
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit)) return 65;
    rlim_t bound = limit.rlim_cur;
    /* Driver explicitly passes close_fds=True; still close all finite open FDs. */
    if (bound == RLIM_INFINITY || bound > 1048576) bound = 1048576;
    for (int fd = 3; (rlim_t)fd < bound; fd++) if (fd != gate) close(fd);
    if (raise(SIGSTOP)) return 66;
    /* Even if attach resumes SIGSTOP, only the parent-held pipe can release exec. */
    char token;
    if (read(gate, &token, 1) != 1 || token != 'G') return 68;
    close(gate);
    execv(argv[3], argv + 3);
    return 67;
}
