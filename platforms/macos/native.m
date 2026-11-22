#import "native.h"
#import <Security/Security.h>
#include <fcntl.h>
#include <grp.h>
#include <cups/cups.h>
#include <mach/message.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

NSString *F3Queue(uid_t uid) { return [NSString stringWithFormat:@"%@-%u", F3_QUEUE, uid]; }

NSString *F3SocketPath(uid_t uid) {
    return [NSString stringWithFormat:@"/private/var/tmp/%@/%u/agent.sock", F3_SERVICE, uid];
}

NSString *F3Generation(uid_t uid) {
    NSString *path = [F3_VENDOR stringByAppendingFormat:@"/users/%u", uid];
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return nil;
    struct stat st;
    char buffer[37] = {0};
    BOOL ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == 0 &&
        !(st.st_mode & 022) && st.st_nlink == 1 && st.st_size == 37 &&
        F3Read(fd, buffer, 36);
    close(fd);
    if (!ok) return nil;
    NSString *value = [NSString stringWithUTF8String:buffer];
    NSUUID *uuid = value ? [[NSUUID alloc] initWithUUIDString:value] : nil;
    return uuid.UUIDString.lowercaseString;
}

// A socket name or PID alone does not identify the executable at its other end.
BOOL F3Peer(int fd, uid_t uid, NSString *executable) {
    uid_t peer; gid_t group;
    audit_token_t token;
    socklen_t length = sizeof(token);
    if (getpeereid(fd, &peer, &group) || peer != uid ||
        getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &length) || length != sizeof(token)) {
#ifdef FIN3000_QA
        fputs("DEBUG: FIN3000_QA_PEER_CREDENTIALS\n", stderr);
#endif
        return NO;
    }
    NSDictionary *attrs = @{(__bridge NSString *)kSecGuestAttributeAudit: [NSData dataWithBytes:&token length:length]};
    SecCodeRef live = NULL;
    SecStaticCodeRef running = NULL, installed = NULL;
    CFDictionaryRef a = NULL, b = NULL;
    OSStatus status = SecCodeCopyGuestWithAttributes(NULL, (__bridge CFDictionaryRef)attrs, 0, &live);
    if (!status) status = SecCodeCheckValidity(live, 0, NULL);
    if (!status) status = SecCodeCopyStaticCode(live, 0, &running);
    if (!status) status = SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:executable], 0, &installed);
    if (!status) status = SecCodeCopySigningInformation(running, kSecCSSigningInformation, &a);
    if (!status) status = SecCodeCopySigningInformation(installed, kSecCSSigningInformation, &b);
    CFTypeRef one = a ? CFDictionaryGetValue(a, kSecCodeInfoUnique) : NULL;
    CFTypeRef two = b ? CFDictionaryGetValue(b, kSecCodeInfoUnique) : NULL;
    BOOL ok = !status && one && two && CFEqual(one, two);
#ifdef FIN3000_QA
    if (!ok) fprintf(stderr, "DEBUG: FIN3000_QA_PEER_CODE status=%d live=%d static=%d installed=%d info=%d,%d\n",
        (int)status, live != NULL, running != NULL, installed != NULL, a != NULL, b != NULL);
#endif
    if (a) CFRelease(a);
    if (b) CFRelease(b);
    if (live) CFRelease(live);
    if (running) CFRelease(running);
    if (installed) CFRelease(installed);
    return ok;
}

BOOL F3Read(int fd, void *data, size_t size) {
    while (size) {
        ssize_t n = read(fd, data, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return NO;
        data = (char *)data + n; size -= n;
    }
    return YES;
}
BOOL F3Write(int fd, const void *data, size_t size) {
    while (size) {
        ssize_t n = write(fd, data, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return NO;
        data = (const char *)data + n; size -= n;
    }
    return YES;
}
void F3Timeout(int fd, int seconds) {
    struct timeval timeout = {.tv_sec = seconds};
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

int F3Listen(uid_t uid) {
    if (!F3Generation(uid)) return -1;
    NSString *path = F3SocketPath(uid);
    struct stat st;
    struct group *lp = getgrnam("_lp");
    if (!lp || lstat(path.stringByDeletingLastPathComponent.fileSystemRepresentation, &st) ||
        !S_ISDIR(st.st_mode) || st.st_uid != uid || st.st_gid != lp->gr_gid || (st.st_mode & 027)) return -1;
    const char *name = path.fileSystemRepresentation;
    if (!lstat(name, &st) && (!S_ISSOCK(st.st_mode) || st.st_uid != uid || unlink(name))) return -1;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    if (strlcpy(address.sun_path, name, sizeof(address.sun_path)) >= sizeof(address.sun_path)) return -1;
    address.sun_len = SUN_LEN(&address);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (bind(fd, (struct sockaddr *)&address, address.sun_len) || chmod(name, 0660) ||
        lstat(name, &st) || st.st_gid != lp->gr_gid || listen(fd, 3)) { close(fd); return -1; }
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    return fd;
}

// Hold the opened private directory for the entire GUI / coordinator lifetime.
int F3OpenState(void) {
    NSURL *parent = [[NSFileManager defaultManager] URLForDirectory:NSApplicationSupportDirectory
        inDomain:NSUserDomainMask appropriateForURL:nil create:YES error:nil];
    if (!parent) return -1;
    int base = open(parent.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (base < 0) return -1;
    const char *name = F3_SERVICE.UTF8String;
    if (mkdirat(base, name, 0700) && errno != EEXIST) { close(base); return -1; }
    int dir = openat(base, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(base);
    struct stat st;
    if (dir < 0) return -1;
    if (fstat(dir, &st) || st.st_uid != getuid() || (st.st_mode & 077) || flock(dir, LOCK_EX | LOCK_NB)) { close(dir); return -1; }
    return dir;
}
NSData *F3LoadState(int dir, NSError **error) {
    int fd = openat(dir, "state.json", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0 && errno == ENOENT) return nil;
    struct stat st;
    NSMutableData *data = nil;
    if (fd >= 0 && !fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_uid == getuid() &&
        !(st.st_mode & 077) && st.st_nlink == 1 && st.st_size > 0 && st.st_size <= 8*1024*1024) {
        data = [NSMutableData dataWithLength:(NSUInteger)st.st_size];
        if (!F3Read(fd, data.mutableBytes, data.length)) data = nil;
    }
    if (fd >= 0) close(fd);
    if (!data && error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain code:EIO userInfo:nil];
    return data;
}
BOOL F3SaveState(int dir, NSData *data) {
    if (!data || !data.length || data.length > 8*1024*1024) return NO;
    NSString *name = [@".new-" stringByAppendingString:NSUUID.UUID.UUIDString];
    int fd = openat(dir, name.UTF8String, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return NO;
    BOOL ok = F3Write(fd, data.bytes, data.length) && fcntl(fd, F_FULLFSYNC) == 0;
    if (close(fd)) ok = NO;
    if (ok) ok = renameat(dir, name.UTF8String, dir, "state.json") == 0 && fsync(dir) == 0;
    if (!ok) unlinkat(dir, name.UTF8String, 0);
    return ok;
}

static NSString *attribute(ipp_t *reply, const char *name, ipp_tag_t tag) {
    ipp_attribute_t *field = ippFindAttribute(reply, name, tag);
    const char *value = field ? ippGetString(field, 0, NULL) : NULL;
    return value ? [NSString stringWithUTF8String:value] : nil;
}

NSString *F3JobUUID(int jobID, NSString *queue, NSString *user) {
    NSString *uri = [NSString stringWithFormat:@"ipp://localhost/jobs/%d", jobID];
    http_t *server = httpConnect2("/private/var/run/cupsd", 0, NULL, AF_UNIX, HTTP_ENCRYPTION_NEVER, 1, 5000, NULL);
    if (!server) return nil;
    ipp_t *req = ippNewRequest(IPP_OP_GET_JOB_ATTRIBUTES);
    ippAddString(req, IPP_TAG_OPERATION, IPP_TAG_URI, "job-uri", NULL, uri.UTF8String);
    ippAddString(req, IPP_TAG_OPERATION, IPP_TAG_NAME, "requesting-user-name", NULL, user.UTF8String);
    const char *fields[] = {"job-uuid", "job-printer-uri", "job-originating-user-name"};
    ippAddStrings(req, IPP_TAG_OPERATION, IPP_TAG_KEYWORD, "requested-attributes", 3, NULL, fields);
    ipp_t *reply = cupsDoRequest(server, req, "/");
    httpClose(server);
    if (!reply) return nil;
    NSString *uuid = attribute(reply, "job-uuid", IPP_TAG_URI);
    NSString *printerURI = attribute(reply, "job-printer-uri", IPP_TAG_URI);
    NSString *origin = attribute(reply, "job-originating-user-name", IPP_TAG_NAME);
    ipp_status_t status = ippGetStatusCode(reply);
    ippDelete(reply);
    if (status >= IPP_STATUS_ERROR_BAD_REQUEST || ![uuid hasPrefix:@"urn:uuid:"] ||
        !printerURI || ![[NSURL URLWithString:printerURI].path isEqualToString:[@"/printers/" stringByAppendingString:queue]] ||
        ![origin isEqualToString:user]) return nil;
    return [[[NSUUID alloc] initWithUUIDString:[uuid substringFromIndex:9]] UUIDString].lowercaseString;
}


BOOL F3CancelJob(int jobID, NSString *queue, NSString *user, NSString *identity) {
    // Only the already authenticated, registered job may be removed from CUPS.
    if (!identity || ![F3JobUUID(jobID, queue, user) isEqual:identity]) return NO;
    http_t *server = httpConnect2("/private/var/run/cupsd", 0, NULL, AF_UNIX, HTTP_ENCRYPTION_NEVER, 1, 5000, NULL);
    if (!server) return NO;
    ipp_t *req = ippNewRequest(IPP_OP_CANCEL_JOB);
    NSString *uri = [NSString stringWithFormat:@"ipp://localhost/jobs/%d", jobID];
    ippAddString(req, IPP_TAG_OPERATION, IPP_TAG_URI, "job-uri", NULL, uri.UTF8String);
    ippAddString(req, IPP_TAG_OPERATION, IPP_TAG_NAME, "requesting-user-name", NULL, user.UTF8String);
    ipp_t *result = cupsDoRequest(server, req, "/jobs/");
    BOOL ok = result && ippGetStatusCode(result) < IPP_STATUS_ERROR_BAD_REQUEST;
    if (result) ippDelete(result);
    httpClose(server);
    return ok;
}
