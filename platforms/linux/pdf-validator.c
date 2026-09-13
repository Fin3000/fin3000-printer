/* Unprivileged fixed parser launcher. Its enforcing profile allows stdin only. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1 || getuid() == 0 || geteuid() != getuid()) return 1;
    int descriptor = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) return 1;
    char profile[128] = {0};
    ssize_t size = read(descriptor, profile, sizeof(profile) - 1); close(descriptor);
    if (size < 1 || strcmp(profile, "fin3000-printer-pdf-validator (enforce)\n")) return 1;
    struct rlimit cpu = {10, 10}, memory = {512u * 1024u * 1024u, 512u * 1024u * 1024u}, files = {0, 0}, descriptors = {32, 32};
    if (setrlimit(RLIMIT_CPU, &cpu) || setrlimit(RLIMIT_AS, &memory) || setrlimit(RLIMIT_FSIZE, &files) ||
        setrlimit(RLIMIT_CORE, &files) || setrlimit(RLIMIT_NOFILE, &descriptors)) return 1;
    /* Check the fixed library before consuming stdin. The private ingress
       parent holds the package lease, keeping these bytes stable through exec.
       The constructor runs again inside pdfinfo, after exec reset dumpability. */
    if (!dlopen("/usr/lib/fin3000-printer/bin/no-core.so", RTLD_NOW | RTLD_LOCAL)) return 1;
    char *const arguments[] = {"/usr/bin/pdfinfo", "-", NULL};
    char *const environment[] = {"PATH=/usr/bin:/bin", "LANG=C.UTF-8",
        "LD_PRELOAD=/usr/lib/fin3000-printer/bin/no-core.so", NULL};
    execve(arguments[0], arguments, environment);
    return 1;
}
