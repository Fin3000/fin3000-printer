/* Loaded by fixed private-process launchers after exec, before application code.
 * RLIMIT_CORE alone does not block pipe handlers such as Ubuntu's Apport.
 * PR_SET_DUMPABLE in the launcher would be reset by exec, so set it here.
 * No GLib callback, signal handler, credentials or configurable library path. */
#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>

__attribute__((constructor)) static void protect_private_memory(void) {
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) ||
        prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0 ||
        unsetenv("LD_PRELOAD") || setenv("FIN3000_CORE_GUARD", "1", 1)) {
        _exit(70);
    }
}
