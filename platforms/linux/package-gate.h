/* Stable root-owned lease, acquired before reading replaceable package code.
 * The descriptor deliberately survives exec; never replace/unlink its inode.
 * Header shared by the desktop/runtime/setup launcher and CUPS backend. */
#ifndef FIN3000_PACKAGE_GATE_H
#define FIN3000_PACKAGE_GATE_H
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

static int package_root_child(int parent, const char *name, int directory) {
    int fd = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK |
                    (directory ? O_DIRECTORY | O_CLOEXEC : 0));
    struct stat info;
    if (fd < 0) return -1;
    if (fstat(fd, &info) || info.st_uid != 0 || (info.st_mode & 022) ||
        (directory ? !S_ISDIR(info.st_mode) : (!S_ISREG(info.st_mode) || info.st_nlink != 1))) {
        close(fd); return -1;
    }
    return fd;
}

static int package_lease(void) {
    int parent = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (parent < 0) return -1;
    const char *parts[] = {"var", "lib", "fin3000-printer", "lifecycle"};
    for (unsigned int i = 0; i < sizeof(parts) / sizeof(parts[0]); i++) {
        int next = package_root_child(parent, parts[i], 1);
        close(parent); if (next < 0) return -1; parent = next;
    }
    int lease = package_root_child(parent, "lease", 0);
    if (lease < 0 || flock(lease, LOCK_SH | LOCK_NB)) {
        if (lease >= 0) close(lease);
        close(parent); return -1;
    }
    int ready = package_root_child(parent, "ready", 0);
    close(parent);
    char bytes[3];
    ssize_t count = ready < 0 ? -1 : read(ready, bytes, sizeof(bytes));
    if (ready >= 0) close(ready);
    if (count != 2 || memcmp(bytes, "1\n", 2)) { close(lease); return -1; }
    return lease;
}
#endif
