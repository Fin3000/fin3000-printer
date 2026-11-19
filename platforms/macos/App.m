#import <AppKit/AppKit.h>
#import <CoreGraphics/CoreGraphics.h>
#import <Security/Security.h>
#import "native.h"
#include <arpa/inet.h>

#include <poll.h>
#include <pwd.h>
#include <sys/socket.h>
#include <unistd.h>

static BOOL sessionLocked(void) {
    NSDictionary *session = CFBridgingRelease(CGSessionCopyCurrentDictionary());
    return ![session[@"kCGSSessionOnConsoleKey"] boolValue] ||
        [session[@"kCGSSessionUserIDKey"] unsignedIntValue] != getuid() ||
        [session[@"CGSSessionScreenIsLocked"] boolValue];
}
static NSData *json(id obj) {
    return [NSJSONSerialization dataWithJSONObject:obj options:0 error:nil];
}
static NSDictionary *object(NSData *bytes) {
    if (!bytes) return nil;
    id value = [NSJSONSerialization JSONObjectWithData:bytes options:0 error:nil];
    return [value isKindOfClass:NSDictionary.class] ? value : nil;
}
static NSString *resource(NSString *name) { return [NSBundle.mainBundle.resourcePath stringByAppendingPathComponent:name]; }

@interface PrinterApp : NSObject <NSApplicationDelegate, NSWindowDelegate, NSTableViewDataSource, NSTableViewDelegate>
@end
@implementation PrinterApp {
    NSWindow *_window;
    NSTextField *_status;
    NSButton *_connect, *_history, *_reconcile, *_remove;
    NSTableView *_table;
    NSArray *_jobs;
    NSDictionary *_catalog, *_state, *_config;
    NSTask *_runtime;
    NSPipe *_input;
    NSMutableData *_output;
    NSMutableDictionary<NSString *, void (^)(BOOL)> *_jobsPending;
    dispatch_queue_t _writeQueue;
    dispatch_source_t _listener;
    int _directory;
    BOOL _locked, _stopping, _removing, _runtimeReady;
#ifdef FIN3000_QA
    BOOL _qaConnectRequested;
#endif
    NSTimer *_sessionTimer;
}
- (NSString *)t:(NSString *)key { return _catalog[key] ?: key; }
- (void)write:(NSDictionary *)message {
    if (_stopping || !_runtime.running) return;
    dispatch_async(_writeQueue, ^{
        @autoreleasepool {
            NSMutableData *line = [json(message) mutableCopy]; if (!line) return;
            [line appendBytes:"\n" length:1];
            @try { [self->_input.fileHandleForWriting writeData:line]; }
            @catch (NSException *exception) { /* Runtime exit is reported on the main queue. */ }
        }
    });
}
- (void)receiveBytes:(NSData *)bytes {
    [_output appendData:bytes];
    if (_output.length > 12*1024*1024) { [_runtime terminate]; return; }
    while (_output.length) {
        const void *eol = memchr(_output.bytes, '\n', _output.length);
        if (!eol) return;
        NSUInteger len = (const char *)eol - (const char *)_output.bytes;
        NSDictionary *msg = object([_output subdataWithRange:NSMakeRange(0, len)]);
        [_output replaceBytesInRange:NSMakeRange(0, len+1) withBytes:NULL length:0];
        if (!msg) { [_runtime terminate]; return; }
        [self message:msg];
    }
}
- (void)startRuntime {
    _input = [NSPipe pipe]; NSPipe *out = [NSPipe pipe];
    _runtime = [NSTask new];
    _runtime.executableURL = [NSURL fileURLWithPath:resource(@"node")];
    _runtime.arguments = @[resource(@"platforms/macos/adapter.js")];
    NSMutableDictionary *env = [@{@"PATH":@"/usr/bin:/bin", @"HOME":NSHomeDirectory(), @"LANG":@"en_US.UTF-8"} mutableCopy];
#ifdef FIN3000_QA
    if ([NSFileManager.defaultManager fileExistsAtPath:resource(@"qa-ca.crt")]) env[@"NODE_EXTRA_CA_CERTS"] = resource(@"qa-ca.crt");
#endif
    _runtime.environment = env; _runtime.standardInput = _input; _runtime.standardOutput = out;
    _runtime.standardError = NSFileHandle.fileHandleWithNullDevice;
    __weak PrinterApp *weak = self;
    out.fileHandleForReading.readabilityHandler = ^(NSFileHandle *handle) {
        NSData *data = handle.availableData;
        if (!data.length) { handle.readabilityHandler = nil; return; }
        dispatch_async(dispatch_get_main_queue(), ^{ [weak receiveBytes:data]; });
    };
    _runtime.terminationHandler = ^(NSTask *task) {
        dispatch_async(dispatch_get_main_queue(), ^{
            PrinterApp *app = weak;
            if (app && !app->_stopping) {
                app->_runtimeReady = NO;
                for (void (^reply)(BOOL) in app->_jobsPending.allValues) reply(NO);
                [app->_jobsPending removeAllObjects];
                app->_state = @{}; [app refresh];
                app->_status.stringValue = [app t:@"actionFailed"];
            }
        });
    };
    if (![_runtime launchAndReturnError:nil]) { _status.stringValue = [self t:@"actionFailed"]; return; }
    _locked = sessionLocked();
    [self write:@{@"type":@"start", @"generation":F3Generation(getuid()) ?: NSNull.null, @"locked":@(_locked)}];
}
- (void)checkSession {
    BOOL locked = sessionLocked();
    if (locked != _locked) {
        _locked = locked; [self write:@{@"type":@"control", @"action":@"session", @"locked":@(locked)}]; [self refresh];
    }
}
- (void)forceLock:(NSNotification *)note {
    _locked = YES;
    [self write:@{@"type":@"control", @"action":@"session", @"locked":@YES}];
    [self refresh];
}
- (void)sessionChanged:(NSNotification *)note { [self checkSession]; }

- (BOOL)startListener {
    if (_listener) return YES;
    int fd = F3Listen(getuid()); if (fd < 0) return NO;
    dispatch_queue_t queue = dispatch_queue_create("com.fin3000.cups", DISPATCH_QUEUE_SERIAL);
    _listener = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, fd, 0, queue);
    // Only one CUPS job from this queue can be in flight at a time.
    dispatch_source_set_event_handler(_listener, ^{
        @autoreleasepool {
            int peer = accept(fd, NULL, NULL); if (peer < 0) return;
            [self handleFilter:peer]; close(peer);
        }
    });
    dispatch_source_set_cancel_handler(_listener, ^{ close(fd); });
    dispatch_resume(_listener);
    return YES;
}
- (void)stopListener {
    if (_listener) {
        dispatch_source_cancel(_listener); _listener = nil;
        unlink(F3SocketPath(getuid()).fileSystemRepresentation);
    }
}
- (void)handleFilter:(int)fd {
    F3Timeout(fd, 12);
    if (!F3Peer(fd, getuid(), [F3_VENDOR stringByAppendingString:@"/relay"])) return;
    __block char ready = 'N';
    dispatch_sync(dispatch_get_main_queue(), ^{
        [self checkSession];
        if (self->_locked) ready = 'L';
        else if (self->_runtimeReady && !self->_removing && [self->_state[@"connected"] boolValue]) ready = 'R';
    });
    if (!F3Write(fd, &ready, 1) || ready != 'R') return;
    uint32_t raw;
    if (!F3Read(fd, &raw, 4) || ntohl(raw) < 2 || ntohl(raw) > 4096) return;
    NSMutableData *head = [NSMutableData dataWithLength:ntohl(raw)];
    if (!F3Read(fd, head.mutableBytes, head.length)) return;
    NSDictionary *h = object(head);
    if (![h[@"generation"] isEqual:F3Generation(getuid())] || ![h[@"size"] isKindOfClass:NSNumber.class] ||
        ![h[@"title"] isKindOfClass:NSString.class] || ![h[@"nativeJobUuid"] isKindOfClass:NSString.class]) return;
    NSNumber *jobID = h[@"jobId"];
    if (![jobID isKindOfClass:NSNumber.class] || jobID.longLongValue <= 0 || jobID.longLongValue > INT_MAX) return;
    NSString *identity = F3JobUUID(jobID.intValue, F3Queue(getuid()), NSUserName());
    if (!identity || ![identity isEqual:h[@"nativeJobUuid"]]) return;
    NSInteger size = [h[@"size"] integerValue];
    if (size < 5 || size > 20*1024*1024) return;
    NSMutableData *data = [NSMutableData dataWithLength:size];
    if (!F3Read(fd, data.mutableBytes, data.length) || memcmp(data.bytes, "%PDF-", 5) || sessionLocked()) return;
    struct pollfd pollFD = {.fd = fd, .events = POLLIN};
    if (poll(&pollFD, 1, 0) > 0 && (pollFD.revents & (POLLHUP|POLLERR|POLLIN))) return;
    NSString *identifier = NSUUID.UUID.UUIDString;
    NSString *pdf = [data base64EncodedStringWithOptions:0]; [data resetBytesInRange:NSMakeRange(0, data.length)];
    dispatch_semaphore_t done = dispatch_semaphore_create(0); __block BOOL accepted = NO;
    dispatch_async(dispatch_get_main_queue(), ^{
        [self checkSession];
        if (self->_locked || !self->_runtimeReady || self->_removing || ![self->_state[@"connected"] boolValue]) {
            self->_status.stringValue = [self t:@"reprint"];
            dispatch_semaphore_signal(done); return;
        }
        self->_jobsPending[identifier] = ^(BOOL ok) { accepted = ok; dispatch_semaphore_signal(done); };
        [self write:@{@"type":@"job", @"id":identifier, @"generation":h[@"generation"], @"nativeJobUuid":h[@"nativeJobUuid"],
            @"title":h[@"title"], @"pdf":pdf}];
    });
    if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 320LL*NSEC_PER_SEC))) {
        dispatch_async(dispatch_get_main_queue(), ^{ [self->_jobsPending removeObjectForKey:identifier]; }); return;
    }
    char reply = accepted ? 'A' : 'N'; F3Write(fd, &reply, 1);
}

- (id)secret:(NSString *)action value:(id)value error:(BOOL *)failed {
    NSMutableDictionary *q = [@{(__bridge id)kSecClass:(__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService:F3_SERVICE, (__bridge id)kSecAttrAccount:@"oauth-v2",
        (__bridge id)kSecUseAuthenticationUI:(__bridge id)kSecUseAuthenticationUIFail} mutableCopy];
    OSStatus rc;
    if ([action isEqual:@"secretLoad"]) {
        q[(__bridge id)kSecReturnData] = @YES;
        CFTypeRef result = NULL;
        rc = SecItemCopyMatching((__bridge CFDictionaryRef)q, &result);
        if (rc == errSecItemNotFound) return nil;
        NSData *data = CFBridgingRelease(result);
        if (rc != errSecSuccess || ![data isKindOfClass:NSData.class]) { *failed = YES; return nil; }
        NSString *text = data.length <= 32768 ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : nil;
        *failed = rc != errSecSuccess || !text; return text;
    }
    if ([action isEqual:@"secretClear"]) {
        rc = SecItemDelete((__bridge CFDictionaryRef)q);
        *failed = rc != errSecSuccess && rc != errSecItemNotFound; return nil;
    }
    if (![value isKindOfClass:NSString.class] || [value length] > 32768) { *failed = YES; return nil; }
    NSDictionary *attr = @{(__bridge id)kSecValueData:[value dataUsingEncoding:NSUTF8StringEncoding]};
    rc = SecItemUpdate((__bridge CFDictionaryRef)q, (__bridge CFDictionaryRef)attr);
    if (rc == errSecItemNotFound) {
        [q removeObjectForKey:(__bridge id)kSecUseAuthenticationUI];
        [q addEntriesFromDictionary:attr]; rc = SecItemAdd((__bridge CFDictionaryRef)q, NULL);
    }
    *failed = rc != errSecSuccess; return nil;
}
- (NSURL *)loginItem {
    NSURL *home = [NSURL fileURLWithPath:NSHomeDirectory() isDirectory:YES];
    return [[home URLByAppendingPathComponent:@"Library/LaunchAgents"] URLByAppendingPathComponent:[F3_SERVICE stringByAppendingString:@".plist"]];
}
- (BOOL)loginItemEnabled:(BOOL)enabled {
    NSURL *path = [self loginItem]; NSFileManager *files = NSFileManager.defaultManager;
    NSDictionary *plist = @{@"Label":F3_SERVICE, @"RunAtLoad":@YES, @"LimitLoadToSessionType":@"Aqua",
        @"ProgramArguments":@[[F3_APP stringByAppendingString:@"/Contents/MacOS/Fin3000"], @"--background"]};
    if ([files fileExistsAtPath:path.path]) {
        if (![[NSDictionary dictionaryWithContentsOfURL:path] isEqual:plist]) return NO;
        return enabled || [files removeItemAtURL:path error:nil];
    }
    if (!enabled) return YES;
    return [files createDirectoryAtURL:path.URLByDeletingLastPathComponent withIntermediateDirectories:YES attributes:nil error:nil] &&
        [plist writeToURL:path error:nil];
}
- (void)setup:(NSString *)action request:(NSString *)identifier {
    BOOL removing = [action isEqual:@"remove"];
    if (removing) { _removing = YES; [self stopListener]; }
    // All interpolated values are fixed installation constants, an enum and the current numeric uid.
    NSString *script = [NSString stringWithFormat:@"do shell script \"'/Library/Printers/%@/setup.sh' %@ %u\" with administrator privileges",
        F3_QUEUE, action, getuid()];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSTask *task = [NSTask new]; task.executableURL = [NSURL fileURLWithPath:@"/usr/bin/osascript"];
        task.arguments = @[@"-e", script]; task.standardOutput = task.standardError = NSFileHandle.fileHandleWithNullDevice;
        BOOL ok = [task launchAndReturnError:nil]; if (ok) { [task waitUntilExit]; ok = task.terminationStatus == 0; }
        dispatch_async(dispatch_get_main_queue(), ^{
            BOOL ready = ok && [self loginItemEnabled:!removing];
            if (!removing || !ok) ready = [self startListener] && ready;
            self->_removing = NO;
            [self reply:identifier ok:ready value:removing ? nil : F3Generation(getuid()) code:@"SETUP_REQUIRED"];
        });
    });
}
- (void)reply:(NSString *)key ok:(BOOL)ok value:(id)value code:(NSString *)code {
    [self write:@{@"type":@"reply", @"id":key, @"ok":@(ok), @"value":value ?: NSNull.null, @"code":code}];
}
- (void)message:(NSDictionary *)msg {
    NSString *type = msg[@"type"];
    if ([type isEqual:@"state"]) {
        _runtimeReady = YES; _state = msg; [self refresh];
#ifdef FIN3000_QA
        if (!_qaConnectRequested && [NSProcessInfo.processInfo.arguments containsObject:@"--qa-connect"] &&
            _connect.enabled && ![_state[@"connected"] boolValue] && ![_state[@"busy"] boolValue]) {
            _qaConnectRequested = YES; [_connect performClick:nil];
        }
#endif
        return;
    }
    if ([type isEqual:@"removed"]) { [NSApp terminate:nil]; return; }
    if ([type isEqual:@"fatal"]) { _status.stringValue = [self t:@"actionFailed"]; return; }
    NSString *key = msg[@"id"]; if (![key isKindOfClass:NSString.class]) return;
    if ([type isEqual:@"jobResult"]) {
        void (^reply)(BOOL) = _jobsPending[key];
        if (reply) { [_jobsPending removeObjectForKey:key]; reply([msg[@"ok"] boolValue]); }
        return;
    }
    if (![type isEqual:@"request"]) return;
    NSString *action = msg[@"action"]; id value = msg[@"value"], result = nil;
    BOOL failed = NO; NSString *code = @"NATIVE_UNAVAILABLE";
    if ([action isEqual:@"stateLoad"]) {
        NSError *error = nil; NSData *data = F3LoadState(_directory, &error);
        if (data) result = object(data);
        failed = error != nil || (data && !result);
    } else if ([action isEqual:@"stateSave"]) failed = !F3SaveState(_directory, json(value));
    else if ([@[@"secretLoad", @"secretSave", @"secretClear"] containsObject:action]) {
        code = @"SECRET_UNAVAILABLE";
        if (sessionLocked()) failed = YES;
        else result = [self secret:action value:value error:&failed];
    } else if ([action isEqual:@"browser"]) {
        NSString *origin = _config[@"appOrigin"];
        NSURL *url = [value isKindOfClass:NSString.class] ? [NSURL URLWithString:value] : nil;
        NSURL *allowed = [NSURL URLWithString:origin];
        BOOL valid = url && !url.user && !url.password && !url.fragment && [url.scheme isEqual:allowed.scheme] &&
            [url.host isEqual:allowed.host] && ((url.port == nil && allowed.port == nil) || [url.port isEqual:allowed.port]) &&
            [@[@"/oauth/authorize", @"/accounting/incoming-invoices/print-operations"] containsObject:url.path];
        failed = sessionLocked() || !valid || ![NSWorkspace.sharedWorkspace openURL:url]; code = @"BROWSER_UNAVAILABLE";
    } else if ([@[@"configure",@"remove"] containsObject:action] && !sessionLocked()) {
        [self setup:action request:key]; return;
    } else failed = YES;
    [self reply:key ok:!failed value:result code:code];
}
- (void)clicked:(NSButton *)sender {
    NSString *action = sender.identifier;
    if ([action isEqual:@"remove"]) {
        NSAlert *alert = [NSAlert new]; alert.messageText = [self t:@"remove"]; alert.informativeText = [self t:@"drainExplanation"];
        [alert addButtonWithTitle:[self t:@"remove"]]; [alert addButtonWithTitle:[self t:@"cancel"]];
        if ([alert runModal] != NSAlertFirstButtonReturn) return;
    }
    NSMutableDictionary *msg = [@{@"type":@"control", @"action":action} mutableCopy];
    if ([action isEqual:@"reconcile"] && _table.selectedRow >= 0) msg[@"operationId"] = _jobs[_table.selectedRow][@"operationId"];
    [self checkSession]; [self write:msg];
}
- (NSButton *)button:(NSString *)title action:(NSString *)action {
    NSButton *button = [NSButton buttonWithTitle:[self t:title] target:self action:@selector(clicked:)];
    button.identifier = action; return button;
}
- (void)buildWindow {
    _window = [[NSWindow alloc] initWithContentRect:NSMakeRect(0,0,640,400)
        styleMask:NSWindowStyleMaskTitled|NSWindowStyleMaskClosable|NSWindowStyleMaskResizable
        backing:NSBackingStoreBuffered defer:NO];
    _window.title = NSBundle.mainBundle.infoDictionary[@"CFBundleDisplayName"]; _window.delegate = self; _window.releasedWhenClosed = NO;
    _status = [NSTextField wrappingLabelWithString:[self t:@"starting"]]; _status.font = [NSFont systemFontOfSize:15 weight:NSFontWeightMedium];
    _connect = [self button:@"connect" action:@"connect"]; _history = [self button:@"recovery" action:@"history"];
    _reconcile = [self button:@"reconcile" action:@"reconcile"]; _remove = [self button:@"remove" action:@"remove"];
    NSStackView *buttons = [NSStackView stackViewWithViews:@[_connect,_history,_reconcile]];
    NSTextField *heading = [NSTextField labelWithString:[self t:@"jobs"]]; heading.font = [NSFont boldSystemFontOfSize:14];
    _table = [NSTableView new]; _table.dataSource = self; _table.delegate = self;
    for (NSString *key in @[@"name", @"outcome"]) {
        NSTableColumn *col = [[NSTableColumn alloc] initWithIdentifier:key]; col.title = [self t:[key isEqual:@"name"] ? @"jobs" : @"helpTroubleshooting"];
        col.width = [key isEqual:@"name"] ? 266 : 290; [_table addTableColumn:col];
    }
    [_table setAccessibilityLabel:[self t:@"jobs"]];
    NSScrollView *scroll = [NSScrollView new]; scroll.documentView = _table; scroll.hasVerticalScroller = YES; scroll.borderType = NSBezelBorder;
    NSStackView *stack = [NSStackView stackViewWithViews:@[_status,buttons,heading,scroll,_remove]];
    stack.orientation = NSUserInterfaceLayoutOrientationVertical; stack.alignment = NSLayoutAttributeLeading; stack.spacing = 12;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    NSView *content = _window.contentView; [content addSubview:stack];
    [NSLayoutConstraint activateConstraints:@[[stack.leadingAnchor constraintEqualToAnchor:content.leadingAnchor constant:18],
      [stack.trailingAnchor constraintEqualToAnchor:content.trailingAnchor constant:-18], [stack.topAnchor constraintEqualToAnchor:content.topAnchor constant:18],
      [stack.bottomAnchor constraintEqualToAnchor:content.bottomAnchor constant:-18], [scroll.widthAnchor constraintEqualToAnchor:stack.widthAnchor],
      [_status.widthAnchor constraintEqualToAnchor:stack.widthAnchor], [scroll.heightAnchor constraintGreaterThanOrEqualToConstant:100]]];
    [_window center];
}
- (NSInteger)numberOfRowsInTableView:(NSTableView *)table { return _jobs.count; }
- (id)tableView:(NSTableView *)table objectValueForTableColumn:(NSTableColumn *)column row:(NSInteger)row {
    NSDictionary *job = _jobs[row];
    if ([column.identifier isEqual:@"outcome"]) return [self t:job[@"outcome"]];
    NSDate *date = [NSDate dateWithTimeIntervalSince1970:[job[@"receivedAt"] doubleValue]/1000.0];
    return [NSString stringWithFormat:@"%@ · %@", [NSDateFormatter localizedStringFromDate:date dateStyle:NSDateFormatterShortStyle timeStyle:NSDateFormatterShortStyle], job[@"name"]];
}
- (void)tableViewSelectionDidChange:(NSNotification *)notification { [self updateSelection]; }
- (void)updateSelection {
    NSInteger i = _table.selectedRow;
    _reconcile.enabled = !_locked && ![_state[@"busy"] boolValue] && i >= 0 && i < (NSInteger)_jobs.count && [_jobs[i][@"outcome"] isEqual:@"uncertain"];
}
- (void)refresh {
    NSString *selected = _table.selectedRow >= 0 && _table.selectedRow < (NSInteger)_jobs.count ? _jobs[_table.selectedRow][@"operationId"] : nil;
    NSArray *rows = _locked ? @[] : (_state[@"jobs"] ?: @[]);
    if (![_jobs isEqual:rows]) {
        _jobs = rows; [_table reloadData];
        NSUInteger index = selected ? [[rows valueForKey:@"operationId"] indexOfObject:selected] : NSNotFound;
        if (index != NSNotFound) [_table selectRowIndexes:[NSIndexSet indexSetWithIndex:index] byExtendingSelection:NO];
    }
    BOOL busy = [_state[@"busy"] boolValue], connected = [_state[@"connected"] boolValue];
    NSString *code = _state[@"code"]; NSString *text;
    if (_locked) text = [self t:@"locked"];
    else if (busy) text = [self t:@"working"];
    else if ([code isEqual:@"RECONCILE_REQUIRED"]) text = [self t:@"uncertain"];
    else if ([code isEqual:@"JOBS_IN_PROGRESS"]) text = [self t:@"pendingJobs"];
    else if ([code length] && ![code isEqual:@"LOGIN_REQUIRED"]) text = [NSString stringWithFormat:@"%@ (%@)", [self t:[code isEqual:@"CONNECT_AND_REPRINT"] ? @"reprint" : @"actionFailed"], code];
    else if (connected) text = [NSString stringWithFormat:@"%@ · %@", _state[@"account"] ?: @"Fin3000", _state[@"target"] ?: [self t:@"unassigned"]];
    else text = [self t:@"connectExplanation"];
    _status.stringValue = text; _connect.hidden = connected; _connect.enabled = _runtimeReady && !busy && !_locked;
    _history.enabled = !_locked && !busy && connected; _remove.hidden = ![_state[@"queue"] boolValue]; _remove.enabled = !_locked && !busy;
    [self updateSelection];
}
- (void)show {
    [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular]; [_window makeKeyAndOrderFront:nil]; [NSApp activateIgnoringOtherApps:YES];
}
- (BOOL)applicationShouldHandleReopen:(NSApplication *)app hasVisibleWindows:(BOOL)visible { [self show]; return NO; }
- (void)windowWillClose:(NSNotification *)note { [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory]; }
- (void)applicationDidFinishLaunching:(NSNotification *)note {
    _directory = F3OpenState();
    if (_directory < 0) { [NSApp terminate:nil]; return; }
    _writeQueue = dispatch_queue_create("com.fin3000.coordinator", DISPATCH_QUEUE_SERIAL);
    _jobsPending = [NSMutableDictionary dictionary]; _output = [NSMutableData data]; _jobs = @[];
    for (NSString *lang in NSLocale.preferredLanguages) {
        NSString *base = [[lang componentsSeparatedByCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"-_"]] firstObject];
        _catalog = object([NSData dataWithContentsOfFile:resource([NSString stringWithFormat:@"locales/%@.json",base])]); if (_catalog) break;
    }
    if (!_catalog) _catalog = object([NSData dataWithContentsOfFile:resource(@"locales/en.json")]);
    _config = object([NSData dataWithContentsOfFile:resource(@"config.json")]);
    [self buildWindow]; [self startListener]; [self startRuntime];
    NSDistributedNotificationCenter *center = NSDistributedNotificationCenter.defaultCenter;
    [center addObserver:self selector:@selector(forceLock:) name:@"com.apple.screenIsLocked" object:nil];
    [center addObserver:self selector:@selector(sessionChanged:) name:@"com.apple.screenIsUnlocked" object:nil];
    NSNotificationCenter *ws = NSWorkspace.sharedWorkspace.notificationCenter;
    for (NSString *name in @[NSWorkspaceSessionDidResignActiveNotification, NSWorkspaceWillSleepNotification])
        [ws addObserver:self selector:@selector(forceLock:) name:name object:nil];
    for (NSString *name in @[NSWorkspaceSessionDidBecomeActiveNotification, NSWorkspaceDidWakeNotification])
        [ws addObserver:self selector:@selector(sessionChanged:) name:name object:nil];
    _sessionTimer = [NSTimer scheduledTimerWithTimeInterval:1 repeats:YES block:^(NSTimer *timer){ [self checkSession]; }];
    if (![NSProcessInfo.processInfo.arguments containsObject:@"--background"]) [self show];
}
- (void)applicationWillTerminate:(NSNotification *)note {
    _stopping = YES; [_sessionTimer invalidate]; [self stopListener];
    [_input.fileHandleForWriting closeFile]; if (_directory >= 0) close(_directory);
}
@end

int main(void) {
    @autoreleasepool {
        NSApplication *app = NSApplication.sharedApplication;
        PrinterApp *delegate = [PrinterApp new]; app.delegate = delegate;
        [app setActivationPolicy:NSApplicationActivationPolicyAccessory];
        [app run];
    }
    return 0;
}
