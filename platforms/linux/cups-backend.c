/* Package-owned CUPS backend. Root only, enforcing profile, local handoff only. */
#define _GNU_SOURCE
#include <cups/cups.h>
#include <cups/backend.h>
#include <json-c/json.h>
#include <openssl/evp.h>
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#include <wchar.h>
#include <wctype.h>
#include "package-gate.h"

#define PDF_LIMIT (20u * 1024u * 1024u)
#define PROFILE "fin3000-printer-backend (enforce)\n"
struct installation { uid_t uid; char username[33], generation[37], queue[64], socket_path[108]; };

static int fail(const char *code) {
    /* Only hard-coded codes: no job title, user path, token or provider text. */
    fprintf(stderr, "ERROR: Fin3000: %s. Open Fin3000 Printer for details.\n", code);
    return CUPS_BACKEND_FAILED;
}

static bool uuid_valid(const char *value) {
    if (!value || strlen(value) != 36) return false;
    for (size_t i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) { if (value[i] != '-') return false; }
        else if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f'))) return false;
    }
    return true;
}

static bool username_valid(const char *value) {
    size_t size = value ? strlen(value) : 0;
    if (!size || size > 32 || !((value[0] >= 'a' && value[0] <= 'z') || value[0] == '_')) return false;
    for (size_t i = 1; i < size; i++) if (!((value[i] >= 'a' && value[i] <= 'z') || (value[i] >= '0' && value[i] <= '9') || value[i] == '_' || value[i] == '-')) return false;
    return true;
}

static bool enforcing(void) {
    char value[128] = {0};
    int fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    ssize_t size = read(fd, value, sizeof(value) - 1); close(fd);
    return size > 0 && !strcmp(value, PROFILE);
}

static int root_child(int parent, const char *name, bool directory) {
    int fd = openat(parent, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | (directory ? O_DIRECTORY : 0));
    struct stat info;
    if (fd < 0) return -1;
    if (fstat(fd, &info) || info.st_uid != 0 || (info.st_mode & 0022) ||
        (directory ? !S_ISDIR(info.st_mode) : !S_ISREG(info.st_mode)) || (!directory && info.st_nlink != 1)) { close(fd); return -1; }
    return fd;
}

static const char *json_string(struct json_object *root, const char *key) {
    struct json_object *value = NULL;
    if (!json_object_object_get_ex(root, key, &value) || !json_object_is_type(value, json_type_string)) return NULL;
    const char *text = json_object_get_string(value);
    return text && strlen(text) == (size_t)json_object_get_string_len(value) ? text : NULL;
}

static bool json_integer(struct json_object *root, const char *key, int64_t expected) {
    struct json_object *value = NULL;
    return json_object_object_get_ex(root, key, &value) && json_object_is_type(value, json_type_int) && json_object_get_int64(value) == expected;
}

static bool mapping(struct installation *result, struct passwd *user) {
    int parent = open("/", O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    if (parent < 0) return false;
    const char *dirs[] = {"etc", "fin3000-printer", "installations"};
    for (size_t i = 0; i < 3; i++) { int next = root_child(parent, dirs[i], true); close(parent); if (next < 0) return false; parent = next; }
    char name[32]; snprintf(name, sizeof(name), "%u.json", user->pw_uid);
    int fd = root_child(parent, name, false); close(parent);
    if (fd < 0) return false;
    char raw[4097] = {0}; size_t length = 0;
    while (length < sizeof(raw) - 1) {
        ssize_t count = read(fd, raw + length, sizeof(raw) - 1 - length);
        if (count < 0) { if (errno == EINTR) continue; close(fd); return false; }
        if (!count) break;
        length += (size_t)count;
    }
    close(fd);
    if (!length || length >= sizeof(raw) - 1) return false;
    if (raw[length - 1] == '\n') raw[--length] = 0;
    struct json_tokener *parser = json_tokener_new_ex(4);
    if (!parser) return false;
    json_tokener_set_flags(parser, JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    struct json_object *object = json_tokener_parse_ex(parser, raw, (int)length);
    bool valid = json_tokener_get_error(parser) == json_tokener_success && json_tokener_get_parse_end(parser) == length;
    json_tokener_free(parser);
    if (!valid || !object || !json_object_is_type(object, json_type_object)) { if (object) json_object_put(object); return false; }
    /* Canonical compact JSON rejects duplicate keys, alternate escapes and junk. */
    valid = json_object_object_length(object) == 8 && !strcmp(raw, json_object_to_json_string_ext(object, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE));
    const char *username = json_string(object, "username"), *generation = json_string(object, "generation");
    const char *queue = json_string(object, "queue"), *path = json_string(object, "socketPath");
    char expected_queue[64], expected_path[108];
    snprintf(expected_queue, sizeof(expected_queue), "Fin3000-%u", user->pw_uid);
    snprintf(expected_path, sizeof(expected_path), "/run/user/%u/fin3000-printer/ingest.sock", user->pw_uid);
    struct stat home;
    valid = valid && !lstat(user->pw_dir, &home) && S_ISDIR(home.st_mode) && home.st_uid == user->pw_uid &&
        json_integer(object, "version", 1) && json_integer(object, "uid", user->pw_uid) &&
        json_integer(object, "homeDevice", (int64_t)home.st_dev) && json_integer(object, "homeInode", (int64_t)home.st_ino) &&
        username && !strcmp(username, user->pw_name) && uuid_valid(generation) && queue && !strcmp(queue, expected_queue) && path && !strcmp(path, expected_path);
    if (valid) {
        result->uid = user->pw_uid; strcpy(result->username, username); strcpy(result->generation, generation);
        strcpy(result->queue, queue); strcpy(result->socket_path, path);
    }
    json_object_put(object); return valid;
}

static const char *attribute(ipp_t *response, const char *name, ipp_tag_t type) {
    ipp_attribute_t *attr = ippFindAttribute(response, name, type);
    return attr && ippGetCount(attr) == 1 ? ippGetString(attr, 0, NULL) : NULL;
}

static const char *no_password(const char *prompt, http_t *http, const char *method, const char *resource, void *context) {
    (void)prompt; (void)http; (void)method; (void)resource; (void)context;
    return NULL; /* Never prompt/read an OS password from a print backend. */
}

static bool native_identity(const struct installation *installation, int job_id, char uuid[37]) {
    /* This is the existing local scheduler, not a network printer or discovery. */
    http_t *connection = httpConnect2("/run/cups/cups.sock", 0, NULL, AF_UNIX, HTTP_ENCRYPTION_NEVER, 1, 5000, NULL);
    if (!connection) return false;
    cupsSetUser(installation->username);
    cupsSetPasswordCB2(no_password, NULL);
    ipp_t *request = ippNewRequest(IPP_OP_GET_JOB_ATTRIBUTES);
    char uri[80]; snprintf(uri, sizeof(uri), "ipp://localhost/jobs/%d", job_id);
    ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI, "job-uri", NULL, uri);
    ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME, "requesting-user-name", NULL, installation->username);
    const char *wanted[] = {"job-uuid", "job-originating-user-name", "job-printer-uri"};
    ippAddStrings(request, IPP_TAG_OPERATION, IPP_TAG_KEYWORD, "requested-attributes", 3, NULL, wanted);
    ipp_t *response = cupsDoRequest(connection, request, "/jobs/");
    httpClose(connection);
    if (!response) return false;
    const char *job_uuid = attribute(response, "job-uuid", IPP_TAG_URI);
    const char *user = attribute(response, "job-originating-user-name", IPP_TAG_NAME);
    const char *printer = attribute(response, "job-printer-uri", IPP_TAG_URI);
    char scheme[32], username[64], host[256], resource[256], expected[100]; int port = 0;
    snprintf(expected, sizeof(expected), "/printers/%s", installation->queue);
    bool valid = ippGetStatusCode(response) <= IPP_STATUS_OK_EVENTS_COMPLETE && job_uuid &&
        !strncmp(job_uuid, "urn:uuid:", 9) && uuid_valid(job_uuid + 9) && user && !strcmp(user, installation->username) && printer &&
        httpSeparateURI(HTTP_URI_CODING_ALL, printer, scheme, sizeof(scheme), username, sizeof(username), host, sizeof(host), &port, resource, sizeof(resource)) == HTTP_URI_STATUS_OK &&
        !strcmp(scheme, "ipp") && !*username && !strcmp(resource, expected);
    if (valid) strcpy(uuid, job_uuid + 9);
    ippDelete(response); return valid;
}

static bool spool_path(const char *path, int job_id) {
    /* CUPS uses d%05d-%03d. Bind the file to the already verified job,
       not merely to the scheduler's spool directory. Widths are minimums. */
    char expected[64];
    if (!path || job_id < 1 || strnlen(path, sizeof(expected)) == sizeof(expected)) return false;
    int prefix_size = snprintf(expected, sizeof(expected), "/var/spool/cups/d%05d-", job_id);
    if (prefix_size < 0 || (size_t)prefix_size >= sizeof(expected) || strncmp(path, expected, (size_t)prefix_size)) return false;
    const char *document = path + prefix_size;
    uint32_t document_id = 0;
    for (const char *digit = document; *digit; digit++) {
        if (*digit < '0' || *digit > '9' || document_id > (INT32_MAX - (uint32_t)(*digit - '0')) / 10) return false;
        document_id = document_id * 10 + (uint32_t)(*digit - '0');
    }
    if (!document_id) return false;
    int size = snprintf(expected, sizeof(expected), "/var/spool/cups/d%05d-%03d", job_id, (int)document_id);
    return size > 0 && (size_t)size < sizeof(expected) && !strcmp(path, expected);
}

static void safe_title(const char *source, char destination[721]) {
    mbstate_t state = {0}; size_t consumed = 0, written = 0, characters = 0;
    size_t available = strnlen(source, 4096);
    while (consumed < available && characters < 180) {
        wchar_t point;
        size_t count = mbrtowc(&point, source + consumed, available - consumed, &state);
        if (!count || count == (size_t)-1 || count == (size_t)-2) break;
        if (iswprint(point) && !iswcntrl(point) && !(point >= 0x200b && point <= 0x200f) &&
            !(point >= 0x202a && point <= 0x202e) && !(point >= 0x2060 && point <= 0x206f) && point != 0xfeff && written + count <= 720) {
            memcpy(destination + written, source + consumed, count); written += count; characters++;
        }
        consumed += count;
    }
    destination[written] = 0;
}

int main(int argc, char **argv) {
    if (argc == 1) return 0; /* Explicit setup only; never broadcast discovery. */
    if (getuid() != 0 || geteuid() != 0 || (argc != 6 && argc != 7) || !enforcing() || !username_valid(argv[2])) return fail("INVOCATION_DENIED");
    if (package_lease() < 0) return fail("PACKAGE_UNAVAILABLE");
    struct rlimit no_core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &no_core) || prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)) return fail("CONFINEMENT_INVALID");
    const char *environment_uri = getenv("DEVICE_URI"), *password = getenv("AUTH_PASSWORD");
    char device_uri[128] = {0};
    if (!environment_uri || strlen(environment_uri) >= sizeof(device_uri) || (password && *password)) return fail("INVOCATION_DENIED");
    strcpy(device_uri, environment_uri);
    clearenv(); setenv("PATH", "/usr/bin:/bin", 1); setenv("LANG", "C.UTF-8", 1); setlocale(LC_CTYPE, "C.UTF-8");
    alarm(60);
    char *end = NULL; errno = 0; long job_id = strtol(argv[1], &end, 10);
    if (errno || !end || *end || job_id < 1 || job_id > INT32_MAX || argv[1][0] == '+' || argv[1][0] == '0') return fail("JOB_ID_INVALID");
    struct passwd *user = getpwnam(argv[2]); struct installation installation;
    if (!user || user->pw_uid < 1000 || user->pw_uid > 60000 || !mapping(&installation, user)) return fail("INSTALLATION_DRIFT");
    char expected_uri[128]; snprintf(expected_uri, sizeof(expected_uri), "fin3000:/%u/%s", installation.uid, installation.generation);
    if (strcmp(device_uri, expected_uri)) return fail("INSTALLATION_DRIFT");
    char job_uuid[37];
    if (!native_identity(&installation, (int)job_id, job_uuid)) return fail("JOB_IDENTITY_INVALID");
    int input = STDIN_FILENO;
    if (argc == 7) {
        if (!spool_path(argv[6], (int)job_id)) return fail("INPUT_INVALID");
        input = open(argv[6], O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        struct stat info;
        if (input < 0 || fstat(input, &info) || !S_ISREG(info.st_mode) || info.st_size > PDF_LIMIT || info.st_uid != 0) return fail("INPUT_INVALID");
    }
    unsigned char *pdf = malloc(PDF_LIMIT + 1);
    if (!pdf) return fail("MEMORY_LIMIT");
    size_t size = 0;
    while (size <= PDF_LIMIT) {
        ssize_t count = read(input, pdf + size, PDF_LIMIT + 1 - size);
        if (count < 0) { if (errno == EINTR) continue; free(pdf); return fail("INPUT_FAILED"); }
        if (!count) break;
        size += (size_t)count;
    }
    if (input != STDIN_FILENO) close(input);
    /* No PDF parser in root context. The unprivileged confined worker validates. */
    if (size < 5 || size > PDF_LIMIT) { free(pdf); return fail("PDF_SIZE_INVALID"); }
    unsigned char hash[EVP_MAX_MD_SIZE]; unsigned int hash_size = 0;
    if (!EVP_Digest(pdf, size, hash, &hash_size, EVP_sha256(), NULL) || hash_size != 32) { free(pdf); return fail("DIGEST_FAILED"); }
    char digest[65], title[721];
    for (unsigned int i = 0; i < 32; i++) snprintf(digest + i * 2, 3, "%02x", hash[i]);
    safe_title(argv[3], title);
    struct json_object *header = json_object_new_object();
    json_object_object_add(header, "version", json_object_new_int(2));
    json_object_object_add(header, "generation", json_object_new_string(installation.generation));
    json_object_object_add(header, "nativeJobUuid", json_object_new_string(job_uuid));
    json_object_object_add(header, "jobId", json_object_new_int((int)job_id));
    json_object_object_add(header, "title", json_object_new_string(title));
    json_object_object_add(header, "size", json_object_new_int64((int64_t)size));
    json_object_object_add(header, "sha256", json_object_new_string(digest));
    const char *wire = json_object_to_json_string_ext(header, JSON_C_TO_STRING_PLAIN);
    int client = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (client < 0) { json_object_put(header); free(pdf); return fail("AGENT_UNAVAILABLE"); }
    struct timeval timeout = {.tv_sec = 30};
    bool timed = !setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) &&
        !setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_un address = {.sun_family = AF_UNIX}; strcpy(address.sun_path, installation.socket_path);
    struct ucred peer; socklen_t peer_size = sizeof(peer);
    bool accepted = timed && !connect(client, (struct sockaddr *)&address, sizeof(address)) &&
        !getsockopt(client, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) && peer.uid == installation.uid &&
        strlen(wire) <= 4096 && send(client, wire, strlen(wire), MSG_NOSIGNAL) == (ssize_t)strlen(wire);
    for (size_t sent = 0; accepted && sent < size;) {
        size_t count = size - sent > 65536 ? 65536 : size - sent;
        accepted = send(client, pdf + sent, count, MSG_NOSIGNAL) == (ssize_t)count; sent += count;
    }
    explicit_bzero(pdf, size); free(pdf); json_object_put(header);
    char reply[80] = {0};
    ssize_t count = accepted ? recv(client, reply, sizeof(reply) - 1, 0) : -1; close(client);
    if (count != 50 || strncmp(reply, "LOCAL_HANDOFF ", 14) || !uuid_valid(reply + 14)) return fail("HANDOFF_NOT_CONFIRMED");
    fprintf(stderr, "INFO: Handed to the local Fin3000 app. Cloud delivery is shown in the app.\n");
    return CUPS_BACKEND_OK;
}
