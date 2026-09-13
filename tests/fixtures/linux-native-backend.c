/* Synthetic native G0 fixture, not a production CUPS backend. No cloud access. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef PROBE_UID
#error Compile with the explicitly authorized desktop UID
#endif
#ifndef PROBE_USER
#error Compile with the explicitly authorized desktop username
#endif
#define LIMIT (1024 * 1024)
#define SOCK_PATH "/run/fin3000-native-probe/ingest.sock"
static unsigned char pdf[LIMIT + 1];

static int fail(const char *stage) {
    fprintf(stderr, "ERROR: Fin3000 synthetic probe: %s (%d)\n", stage, errno);
    return 1;
}

static bool spool_path(const char *p) {
    const char *prefix = "/var/spool/cups/d";
    if (strncmp(p, prefix, strlen(prefix))) return false;
    p += strlen(prefix);
    if (*p < '0' || *p > '9') return false;
    while (*p >= '0' && *p <= '9') p++;
    if (*p++ != '-') return false;
    if (*p < '0' || *p > '9') return false;
    while (*p >= '0' && *p <= '9') p++;
    return *p == 0;
}

int main(int argc, char **argv) {
    if (argc == 1) return 0; /* Not discoverable: explicit test queue only. */
    const char *uri = getenv("DEVICE_URI");
    /* CUPS supplies an empty AUTH_PASSWORD even for passwordless PeerCred. */
    const char *password = getenv("AUTH_PASSWORD");
    if (getuid() != 0 || (argc != 6 && argc != 7) || strcmp(argv[2], PROBE_USER) ||
        !uri || strcmp(uri, "fin3000nativeprobe:/local") || (password && *password))
        return fail("identity or invocation");
    alarm(15);
    char label[256] = {0};
    int label_fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    if (label_fd < 0) return fail("read confinement");
    ssize_t label_len = read(label_fd, label, sizeof(label) - 1);
    close(label_fd);
    if (label_len < 1 || strcmp(label, "fin3000-native-probe (enforce)\n"))
        return fail("confinement not enforcing");
    /* Negative controls: no IP socket and no privileged credential read. */
    int forbidden = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (forbidden >= 0) { close(forbidden); return fail("IP unexpectedly allowed"); }
    if (errno != EACCES && errno != EPERM) return fail("IP negative control");
    forbidden = open("/etc/shadow", O_RDONLY | O_CLOEXEC);
    if (forbidden >= 0) { close(forbidden); return fail("credential access unexpectedly allowed"); }
    if (errno != EACCES && errno != EPERM) return fail("file negative control");
    int input = STDIN_FILENO;
    if (argc == 7) {
        if (!spool_path(argv[6])) return fail("non-spool input rejected");
        input = open(argv[6], O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        struct stat st;
        if (input < 0 || fstat(input, &st) || !S_ISREG(st.st_mode)) return fail("spool input");
    }
    size_t size = 0;
    while (size < sizeof(pdf)) {
        ssize_t count = read(input, pdf + size, sizeof(pdf) - size);
        if (count < 0) { if (errno == EINTR) continue; return fail("PDF read"); }
        if (!count) break;
        size += (size_t)count;
    }
    if (input != STDIN_FILENO) close(input);
    if (size < 5 || size > LIMIT || memcmp(pdf, "%PDF-", 5)) return fail("bounded PDF required");
    int client = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (client < 0) return fail("local socket");
    struct timeval timeout = {.tv_sec = 5};
    if (setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
        setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))) return fail("timeout");
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    strcpy(addr.sun_path, SOCK_PATH);
    if (connect(client, (struct sockaddr *)&addr, sizeof(addr))) return fail("agent unavailable");
    struct ucred peer;
    socklen_t peer_len = sizeof(peer);
    if (getsockopt(client, SOL_SOCKET, SO_PEERCRED, &peer, &peer_len) || peer.uid != PROBE_UID)
        return fail("agent identity");
    unsigned char header[8] = {'F', '3', 'P', '1'};
    uint32_t length = htonl((uint32_t)size);
    memcpy(header + 4, &length, 4);
    if (send(client, header, sizeof(header), MSG_NOSIGNAL) != sizeof(header)) return fail("header");
    for (size_t sent = 0; sent < size;) {
        size_t count = size - sent > 65536 ? 65536 : size - sent;
        if (send(client, pdf + sent, count, MSG_NOSIGNAL) != (ssize_t)count) return fail("transfer");
        sent += count;
    }
    char reply[32] = {0};
    ssize_t n = recv(client, reply, sizeof(reply), 0);
    close(client);
    if (n != 8 || memcmp(reply, "ACCEPTED", 8)) return fail("synthetic custody rejected");
    fprintf(stderr, "INFO: Fin3000 synthetic PDF received locally; no upload.\n");
    return 0;
}
