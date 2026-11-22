// CUPS invokes this PDF filter for the single user's unshared queue.
#import "native.h"
#import <CoreGraphics/CoreGraphics.h>
#include <cups/cups.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static int perform(int argc, char **argv) {
    if (argc != 6 && argc != 7) return 1;
    char *end = NULL;
    long jobID = strtol(argv[1], &end, 10);
    struct passwd *owner = getpwnam(argv[2]);
    if (!end || *end || jobID <= 0 || jobID > INT32_MAX || !owner || owner->pw_uid < 501) return 1;
    uid_t uid = owner->pw_uid;
    NSString *queue = F3Queue(uid);
    const char *name = getenv("PRINTER");
    NSString *generation = F3Generation(uid);
    if (!name || ![queue isEqualToString:[NSString stringWithUTF8String:name]] || !generation) return 1;
    cups_option_t *options = NULL;
    int optionCount = cupsParseOptions(argv[5], 0, &options);
    const char *rawUUID = cupsGetOption("job-uuid", optionCount, options);
    NSString *value = rawUUID ? [NSString stringWithUTF8String:rawUUID] : nil;
    cupsFreeOptions(optionCount, options);
    NSString *identity = [value hasPrefix:@"urn:uuid:"] ?
        [[[NSUUID alloc] initWithUUIDString:[value substringFromIndex:9]] UUIDString].lowercaseString : nil;
    if (!identity) { fputs("ERROR: FIN3000_JOB_IDENTITY_UNAVAILABLE\n", stderr); return 1; }
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    NSString *parent = [@"/private/var/tmp" stringByAppendingPathComponent:F3_SERVICE];
    NSString *endpoint = [parent stringByAppendingFormat:@"/cups-%u.sock", uid];
    struct stat st;
    if (lstat(parent.fileSystemRepresentation, &st) || !S_ISDIR(st.st_mode) || st.st_uid || (st.st_mode & 022) ||
        lstat(endpoint.fileSystemRepresentation, &st) || !S_ISSOCK(st.st_mode) || st.st_uid != 0) return 1;
    if (strlcpy(address.sun_path, endpoint.fileSystemRepresentation, sizeof(address.sun_path)) >= sizeof(address.sun_path)) return 1;
    address.sun_len = SUN_LEN(&address);
    int socketFD = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socketFD < 0) return 1;
    F3Timeout(socketFD, 330);
    if (connect(socketFD, (struct sockaddr *)&address, address.sun_len)) {
        perror("ERROR: FIN3000_SOCKET_UNAVAILABLE"); return 1;
    }
    // launchd bound this inode inside the non-writable root directory. Only
    // the root-installed per-user job can claim the listening file descriptor.
    uid_t peer; gid_t group;
    if (getpeereid(socketFD, &peer, &group) || (peer != 0 && peer != uid)) {
        fputs("ERROR: FIN3000_AGENT_UNAVAILABLE – Fin3000 Drucker öffnen und den Auftrag prüfen.\n", stderr);
        return 1;
    }
    // Identify the CUPS job before sending any document content. The relay
    // can retire a refused job even when the GUI is absent or the seat locked.
    uint32_t jobNumber = htonl((uint32_t)jobID);
    if (!F3Write(socketFD, &jobNumber, sizeof(jobNumber)) || !F3Write(socketFD, identity.UTF8String, 36)) return 1;
    char ready = 0;
    if (!F3Read(socketFD, &ready, 1) || ready != 'R') {
        fputs(ready == 'L' ? "ERROR: FIN3000_SESSION_LOCKED – Sitzung entsperren und erneut drucken.\n" :
            "ERROR: FIN3000_CONNECT_AND_REPRINT – Fin3000 Drucker öffnen und Konto verbinden.\n", stderr);
        return 1;
    }
    int input = argc == 7 ? open(argv[6], O_RDONLY | O_NOFOLLOW) : STDIN_FILENO;
    if (input < 0) return 1;
    NSMutableData *pdf = [NSMutableData data];
    char block[32768]; ssize_t count;
    while ((count = read(input, block, sizeof(block))) > 0) {
        if (pdf.length + (NSUInteger)count > 20 * 1024 * 1024) { fputs("ERROR: FIN3000_PDF_TOO_LARGE\n", stderr); return 1; }
        [pdf appendBytes:block length:(NSUInteger)count];
    }
    if (count < 0 || pdf.length < 5 || memcmp(pdf.bytes, "%PDF-", 5)) return 1;
    CGDataProviderRef provider = CGDataProviderCreateWithCFData((__bridge CFDataRef)pdf);
    CGPDFDocumentRef doc = provider ? CGPDFDocumentCreateWithProvider(provider) : NULL;
    BOOL valid = doc && CGPDFDocumentIsUnlocked(doc) && CGPDFDocumentGetNumberOfPages(doc) > 0;
    if (doc) CGPDFDocumentRelease(doc);
    if (provider) CGDataProviderRelease(provider);
    if (!valid) return 1;
    NSString *title = [NSString stringWithUTF8String:argv[3]] ?: @"";
    if (title.length > 250) title = [title substringToIndex:250];
    NSDictionary *header = @{@"generation":generation, @"jobId":@(jobID), @"nativeJobUuid":identity, @"title": title, @"size":@(pdf.length)};
    NSData *encoded = [NSJSONSerialization dataWithJSONObject:header options:0 error:nil];
    uint32_t length = htonl((uint32_t)encoded.length);
    char ack = 0;
    if (!encoded || !F3Write(socketFD, &length, 4) || !F3Write(socketFD, encoded.bytes, encoded.length) ||
        !F3Write(socketFD, pdf.bytes, pdf.length) || !F3Read(socketFD, &ack, 1) || ack != 'A') {
        fputs("ERROR: FIN3000_PRINT_NOT_CONFIRMED – Status in Fin3000 Drucker prüfen.\n", stderr);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    @autoreleasepool { return perform(argc, argv); }
}
