// launchd owns the CUPS listening socket in a root-controlled directory.
// This on-demand bridge runs as the registered user, outside the CUPS filter sandbox.
#import "native.h"
#include <arpa/inet.h>
#include <launch.h>
#include <poll.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void forwardJob(int client) {
    struct passwd *lp = getpwnam("_lp");
    if (!lp || !F3Peer(client, lp->pw_uid, [F3_VENDOR stringByAppendingString:@"/pdf-filter"])) return;
    uint32_t number = 0; char rawIdentity[37] = {0};
    F3Timeout(client, 12);
    if (!F3Read(client, &number, 4) || !F3Read(client, rawIdentity, 36)) return;
    int jobID = (int)ntohl(number);
    NSString *identity = [NSString stringWithUTF8String:rawIdentity], *queue = F3Queue(getuid()), *user = NSUserName();
    if (jobID <= 0 || !identity || ![F3JobUUID(jobID, queue, user) isEqual:identity]) return;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    if (strlcpy(address.sun_path, F3SocketPath(getuid()).fileSystemRepresentation, sizeof(address.sun_path)) >= sizeof(address.sun_path)) return;
    address.sun_len = SUN_LEN(&address);
    int agent = socket(AF_UNIX, SOCK_STREAM, 0); if (agent < 0) return;
    F3Timeout(agent, 330); F3Timeout(client, 30);
    @try {
        char ready = 'N';
        if (connect(agent, (struct sockaddr *)&address, address.sun_len) ||
            !F3Peer(agent, getuid(), [F3_APP stringByAppendingString:@"/Contents/MacOS/Fin3000"])) {
            F3Write(client, &ready, 1); F3CancelJob(jobID, queue, user, identity); return;
        }
        if (!F3Read(agent, &ready, 1)) ready = 'N';
        if (!F3Write(client, &ready, 1)) return;
        if (ready != 'R') { F3CancelJob(jobID, queue, user, identity); return; }
        uint32_t raw;
        if (!F3Read(client, &raw, 4) || ntohl(raw) == 0 || ntohl(raw) > 4096) return;
        NSMutableData *head = [NSMutableData dataWithLength:ntohl(raw)];
        if (!F3Read(client, head.mutableBytes, head.length)) return;
        id header = [NSJSONSerialization JSONObjectWithData:head options:0 error:nil];
        if (![header isKindOfClass:NSDictionary.class] || ![header[@"size"] isKindOfClass:NSNumber.class] ||
            ![header[@"nativeJobUuid"] isEqual:identity] || ![header[@"jobId"] isEqual:@(jobID)]) return;
        NSInteger remain = [header[@"size"] integerValue];
        if (remain < 5 || remain > 20*1024*1024 || !F3Write(agent, &raw, 4) || !F3Write(agent, head.bytes, head.length)) return;
        char buffer[32768];
        while (remain > 0) {
            size_t take = MIN((size_t)remain, sizeof(buffer));
            if (!F3Read(client, buffer, take) || !F3Write(agent, buffer, take)) return;
            remain -= take;
        }
        char reply;
        if (!F3Read(agent, &reply, 1)) reply = 'N';
        F3Write(client, &reply, 1);
        if (reply != 'A') F3CancelJob(jobID, queue, user, identity);
    } @finally { close(agent); }
}

int main(void) {
    @autoreleasepool {
        int *listeners = NULL; size_t count = 0;
        if (getuid() < 501 || launch_activate_socket("Cups", &listeners, &count) != 0 || count != 1) return 1;
        struct pollfd interest = {.fd=listeners[0], .events=POLLIN};
        while (poll(&interest, 1, 15000) > 0) {
            @autoreleasepool {
                int client = accept(interest.fd, NULL, NULL);
                if (client < 0) break;
                forwardJob(client); close(client);
            }
        }
        close(interest.fd); free(listeners);
    }
    return 0;
}
