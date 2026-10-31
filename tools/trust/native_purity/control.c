/* SPDX-License-Identifier: MIT -- public diagnostic, never a SKU. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

int main(int argc, char **argv) {
    if (argc != 3) return 64;
    const char *mode = argv[1], *path = argv[2];
    if (!strcmp(mode, "clean") || !strcmp(mode, "child")) {
        volatile unsigned long total = 0;
        for (unsigned long i = 0; i < 100000; i++) total += i;
        return total == 0;
    }
    if (!strcmp(mode, "network")) {
#ifdef _WIN32
        WSADATA state; if (WSAStartup(MAKEWORD(2, 2), &state)) return 65;
        SOCKET fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd == INVALID_SOCKET) return 66;
#else
        int fd = socket(AF_INET, SOCK_DGRAM, 0); if (fd < 0) return 66;
#endif
        struct sockaddr_in dst; memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET; dst.sin_port = htons(9);
        dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        int result = (int)sendto(fd, "P", 1, 0, (struct sockaddr *)&dst, (int)sizeof(dst));
#ifdef _WIN32
        closesocket(fd); WSACleanup();
#else
        close(fd);
#endif
        return result == 1 ? 0 : 67;
    }
    if (!strcmp(mode, "process")) {
#ifdef _WIN32
        char exe[MAX_PATH], command[2 * MAX_PATH + 80];
        if (!GetModuleFileNameA(NULL, exe, MAX_PATH)) return 68;
        if (snprintf(command, sizeof(command), "\"%s\" child \"%s\"", exe, path) >= (int)sizeof(command)) return 69;
        STARTUPINFOA si; PROCESS_INFORMATION pi;
        memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
        memset(&pi, 0, sizeof(pi));
        if (!CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) return 70;
        WaitForSingleObject(pi.hProcess, 10000); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
#else
        pid_t pid = fork(); if (pid < 0) return 70;
        if (!pid) { execl(argv[0], argv[0], "child", path, (char *)NULL); _exit(71); }
        int status; if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status)) return 72;
#endif
        return 0;
    }
    int write_mode = !strcmp(mode, "write"), open_mode = !strcmp(mode, "openwrite");
    int map_mode = !strcmp(mode, "mapwrite");
    if (!write_mode && !open_mode && !map_mode) return 64;
#ifdef _WIN32
    HANDLE fd = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fd == INVALID_HANDLE_VALUE) return 73;
    int result = 0;
    if (write_mode) { DWORD n; if (!WriteFile(fd, "X", 1, &n, NULL) || n != 1) result = 74; }
    if (map_mode) {
        HANDLE section = CreateFileMappingA(fd, NULL, PAGE_READWRITE, 0, 0, NULL);
        if (!section) result = 75;
        else {
            char *p = MapViewOfFile(section, FILE_MAP_WRITE, 0, 0, 0);
            if (!p) result = 76; else { p[0] = 'M'; FlushViewOfFile(p, 1); UnmapViewOfFile(p); }
            CloseHandle(section);
        }
    }
    CloseHandle(fd); return result;
#else
    int fd = open(path, O_RDWR); if (fd < 0) return 73;
    int result = 0;
    if (write_mode && write(fd, "X", 1) != 1) result = 74;
    if (map_mode) {
        char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (p == MAP_FAILED) result = 75;
        else { p[0] = 'M'; if (msync(p, 4096, MS_SYNC)) result = 76; munmap(p, 4096); }
    }
    close(fd); return result;
#endif
}
