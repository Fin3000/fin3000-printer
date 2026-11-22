/* Non-elevated desktop launcher; remove runtime injection before GJS/Node. */
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <stdio.h>
#include <sys/resource.h>
#include "package-gate.h"

int main(int argc, char **argv) {
    uid_t uid = getuid();
    int setup = argc == 3 && !strcmp(argv[1], "--setup") &&
                (!strcmp(argv[2], "configure") || !strcmp(argv[2], "remove"));
    int runtime_mode = argc == 2 && !strcmp(argv[1], "--runtime");
    int ingress_mode = argc == 2 && !strcmp(argv[1], "--ingress");
    int secrets_mode = argc == 2 && !strcmp(argv[1], "--secrets");
    if (setup) {
        const char *caller = getenv("PKEXEC_UID");
        if (uid != 0 || geteuid() != 0 || !caller || strlen(caller) < 4 || strlen(caller) > 5 ||
            strspn(caller, "0123456789") != strlen(caller) || atoi(caller) < 1000 || atoi(caller) > 60000) return 1;
        char calling_uid[6]; strcpy(calling_uid, caller);
        if (package_lease() < 0) return 75;
        clearenv();
        if (setenv("PKEXEC_UID", calling_uid, 1) || setenv("PATH", "/usr/bin:/bin", 1) || setenv("LANG", "C.UTF-8", 1)) return 1;
        char *args[] = {"/usr/bin/python3", "-I", "/usr/lib/fin3000-printer/platforms/linux/setup.py", argv[2], NULL};
        execv(args[0], args); return 1;
    }
    if (uid < 1000 || uid > 60000 || geteuid() != uid || argc > 2 ||
        (argc == 2 && !runtime_mode && !ingress_mode && !secrets_mode && strcmp(argv[1], "--background"))) return 1;
    if (package_lease() < 0) return 75;
    struct passwd *account = getpwuid(uid);
    if (!account || !account->pw_dir || account->pw_dir[0] != '/') return 1;
    char *home = strdup(account->pw_dir);
    const char *names[] = {"LANG", "LANGUAGE", "LC_ALL", "XDG_SESSION_ID", "XDG_SESSION_TYPE", "XDG_CURRENT_DESKTOP", "WAYLAND_DISPLAY", "DISPLAY"};
    char *values[sizeof(names) / sizeof(names[0])] = {0};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        const char *value = getenv(names[i]);
        if (value && strlen(value) <= 128 && strspn(value, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:@/-") == strlen(value)) values[i] = strdup(value);
    }
    clearenv();
    if (!home || setenv("HOME", home, 1) || setenv("PATH", "/usr/bin:/bin", 1) || setenv("LANG", "C.UTF-8", 1)) return 1;
    /* Ubuntu's default browser is a Snap desktop entry. Retain its fixed
       system lookup path, never an inherited executable/plugin search path. */
    if (setenv("XDG_DATA_DIRS", "/usr/share/ubuntu:/usr/share/gnome:/usr/local/share:/usr/share:/var/lib/snapd/desktop", 1)) return 1;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) if (values[i] && setenv(names[i], values[i], 1)) return 1;
    char runtime[80], bus[100];
    snprintf(runtime, sizeof(runtime), "/run/user/%u", uid);
    snprintf(bus, sizeof(bus), "unix:path=/run/user/%u/bus", uid);
    if (setenv("XDG_RUNTIME_DIR", runtime, 1) || setenv("DBUS_SESSION_BUS_ADDRESS", bus, 1)) return 1;
    struct rlimit core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core)) return 1;
    /* Every private interpreter may hold credentials or PDF bytes. The fixed
       constructor reapplies non-dumpability after exec; it removes itself from
       the environment. Each entrypoint consumes its guard marker before I/O. */
    if (setenv("LD_PRELOAD", "/usr/lib/fin3000-printer/bin/no-core.so", 1)) return 1;
    if (runtime_mode) {
        char *args[] = {"/usr/lib/fin3000-printer/runtime/bin/node", "--experimental-strip-types",
                        "/usr/lib/fin3000-printer/platforms/linux/runtime.ts", NULL};
        execv(args[0], args); return 1;
    }
    if (ingress_mode) {
        char *args[] = {"/usr/bin/python3", "-I", "/usr/lib/fin3000-printer/platforms/linux/ingress.py", NULL};
        execv(args[0], args); return 1;
    }
    if (secrets_mode) {
        char *args[] = {"/usr/bin/gjs-console", "-m", "/usr/lib/fin3000-printer/platforms/linux/secret-store.js", "--stdio", NULL};
        execv(args[0], args); return 1;
    }
    /* GJS can refuse a callback during GC with a native critical. Continuing
       silently loses the read/session/watchdog chain. Fail-stop in native
       GLib instead; systemd restarts the group and retained operation state is
       recovered without resending print jobs. Core dumps stay disabled.
       Apply only to the GTK owner, never the runtime or secret-store helper. */
    if (setenv("G_DEBUG", "fatal-criticals", 1)) return 1;
    char *args[] = {"/usr/bin/gjs-console", "-m", "/usr/lib/fin3000-printer/platforms/linux/app.js", argc == 2 ? "--background" : NULL, NULL};
    execv(args[0], args);
    return 1;
}
