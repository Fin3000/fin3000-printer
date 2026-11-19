#import <Foundation/Foundation.h>
#include <sys/types.h>
#ifdef FIN3000_QA
#define F3_VENDOR @"/Library/Printers/Fin3000QA"
#define F3_APP @"/Applications/Fin3000 Drucker QA.app"
#define F3_QUEUE @"Fin3000QA"
#define F3_SERVICE @"com.fin3000.printer.qa"
#else
#define F3_VENDOR @"/Library/Printers/Fin3000"
#define F3_APP @"/Applications/Fin3000 Drucker.app"
#define F3_QUEUE @"Fin3000"
#define F3_SERVICE @"com.fin3000.printer"
#endif
NSString *F3JobUUID(int jobID, NSString *queue, NSString *user);
BOOL F3CancelJob(int jobID, NSString *queue, NSString *user, NSString *identity);
NSString *F3Queue(uid_t uid);
NSString *F3Generation(uid_t uid);
NSString *F3SocketPath(uid_t uid);
BOOL F3Peer(int fd, uid_t uid, NSString *executable);
BOOL F3Read(int fd, void *data, size_t size);
BOOL F3Write(int fd, const void *data, size_t size);
void F3Timeout(int fd, int seconds);
int F3Listen(uid_t uid);
int F3OpenState(void);
NSData *F3LoadState(int dir, NSError **error);
BOOL F3SaveState(int dir, NSData *bytes);
