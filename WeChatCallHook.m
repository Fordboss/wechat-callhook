// WeChatCallHook —— 对标官方 TrollRecorder 的 TRWeChatBridgeClient tweak
// 自包含 dylib：用 Objective-C runtime method_exchangeImplementations hook 微信通话方法，
// 检测来电/接通/挂断，通过 Darwin 通知触发自建录音 App 自动开始/停止。
// 用 TrollFools 注入到微信进程即可生效，不依赖 Theos/Substrate/ellekit。
//
// hook 点（来自官方 dylib 逆向）：
//   MMServiceCenter:
//     openAudioWindowWithContact:msgWrap:monoMsg:isCaller:from:startInApp:completion:  (语音)
//     openVideoWindowWithContact:...  (视频)
//     openWindowWithContact:...isEarMode:isAudioMode:completion:  (通用)
//   结束：OnHangup: / setM_currentStartTalkTime: / VoIP talk ended

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <CoreFoundation/CoreFoundation.h>

// 与自建 App 约定的 Darwin 通知名（只能传通知名，payload 走 App Group 文件）
static CFStringRef const kNotifyCallStart = CFSTR("com.wb.callrecorder.wxc.start");
static CFStringRef const kNotifyCallEnd   = CFSTR("com.wb.callrecorder.wxc.end");
static CFStringRef const kNotifyCallRing  = CFSTR("com.wb.callrecorder.wxc.ring");

// App Group 共享容器（微信 tweak 写 payload，自建 App 读）—— 需要两边都是巨魔签名同 group
static NSString * const kAppGroup = @"group.com.wb.callrecorder.shared";
static NSString * const kPayloadFile = @"wxc_payload.plist";

static void WXPost(CFStringRef name) {
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                         name, NULL, NULL, true);
}

// 写通话事件到共享 plist（App 端据此判断来电/去电、是否视频）
static void WXWritePayload(BOOL incoming, BOOL video, NSString *event) {
    NSURL *container = [[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:kAppGroup];
    if (!container) return;
    NSURL *f = [container URLByAppendingPathComponent:kPayloadFile];
    NSMutableDictionary *d = [NSMutableDictionary dictionaryWithContentsOfURL:f] ?: [NSMutableDictionary dictionary];
    d[@"incoming"] = @(incoming);
    d[@"video"] = @(video);
    d[@"event"] = event;
    d[@"ts"] = @([[NSDate date] timeIntervalSince1970]);
    [d writeToURL:f atomically:YES];
}

#pragma mark - 语音/视频通话窗口打开 → 通话开始

typedef void (*OpenWindowIMP)(id, SEL, id, id, BOOL, BOOL, id, BOOL, BOOL, BOOL, id);

static void hooked_openAudioWindow(id self, SEL _cmd, id contact, id msgWrap,
                                   BOOL monoMsg, BOOL isCaller, id from,
                                   BOOL startInApp, id completion) {
    WXWritePayload(!isCaller, NO, @"start");
    WXPost(kNotifyCallStart);
    NSLog(@"[WXHook] audio call start isCaller=%d contact=%@", isCaller, contact);

    // 调原实现（exchange 后，原 IMP 在 WXOrig_ 前缀的 selector 上）
    SEL orig = sel_registerName("WXOrig_openAudioWindowWithContact:msgWrap:monoMsg:isCaller:from:startInApp:completion:");
    IMP imp = class_getMethodImplementation(object_getClass(self), orig);
    if (imp) ((void(*)(id,SEL,id,id,BOOL,BOOL,id,BOOL,id))imp)(self, orig, contact, msgWrap, monoMsg, isCaller, from, startInApp, completion);
}

static void hooked_openVideoWindow(id self, SEL _cmd, id contact, id msgWrap,
                                   BOOL monoMsg, BOOL isCaller, id from,
                                   BOOL startInApp, id completion) {
    WXWritePayload(!isCaller, YES, @"start");
    WXPost(kNotifyCallStart);
    NSLog(@"[WXHook] video call start isCaller=%d", isCaller);

    SEL orig = sel_registerName("WXOrig_openVideoWindowWithContact:msgWrap:monoMsg:isCaller:from:startInApp:completion:");
    IMP imp = class_getMethodImplementation(object_getClass(self), orig);
    if (imp) ((void(*)(id,SEL,id,id,BOOL,BOOL,id,BOOL,id))imp)(self, orig, contact, msgWrap, monoMsg, isCaller, from, startInApp, completion);
}

// 通用 openWindow:...isEarMode:isAudioMode: 作为兜底，只在上面两个没生效时补 hook
static void hooked_openWindow(id self, SEL _cmd, id contact, id msgWrap,
                              BOOL monoMsg, BOOL isCaller, id from,
                              BOOL startInApp, BOOL isEarMode, BOOL isAudioMode, id completion) {
    WXWritePayload(!isCaller, !isAudioMode, @"start");
    WXPost(kNotifyCallStart);
    NSLog(@"[WXHook] generic call start isCaller=%d isAudioMode=%d", isCaller, isAudioMode);

    SEL orig = sel_registerName("WXOrig_openWindowWithContact:msgWrap:monoMsg:isCaller:from:startInApp:isEarMode:isAudioMode:completion:");
    IMP imp = class_getMethodImplementation(object_getClass(self), orig);
    if (imp) ((OpenWindowIMP)imp)(self, orig, contact, msgWrap, monoMsg, isCaller, from, startInApp, isEarMode, isAudioMode, completion);
}

#pragma mark - 通话接听（音量/时间戳设置）与挂断

static void hooked_setStartTalkTime(id self, SEL _cmd, id arg) {
    WXWritePayload(NO, NO, @"answered");
    WXPost(kNotifyCallStart);  // 接听再补一次 start（确保录音从接通开始）
    NSLog(@"[WXHook] call answered");

    SEL orig = sel_registerName("WXOrig_setStartTalkTimestamp:");
    IMP imp = class_getMethodImplementation(object_getClass(self), orig);
    if (imp) ((void(*)(id,SEL,id))imp)(self, orig, arg);
}

static void hooked_hangup(id self, SEL _cmd) {
    WXWritePayload(NO, NO, @"end");
    WXPost(kNotifyCallEnd);
    NSLog(@"[WXHook] call hangup");
    SEL orig = sel_registerName("WXOrig_trwcbc_endTalk");
    IMP imp = class_getMethodImplementation(object_getClass(self), orig);
    if (imp) ((void(*)(id,SEL))imp)(self, orig);
}

// 微信真正的挂断方法：OnHangup: （参数是一个 reason）
static void hooked_OnHangup(id self, SEL _cmd, id reason) {
    WXWritePayload(NO, NO, @"end");
    WXPost(kNotifyCallEnd);
    NSLog(@"[WXHook] OnHangup reason=%@", reason);
    SEL orig = sel_registerName("WXOrig_OnHangup:");
    IMP imp = class_getMethodImplementation(object_getClass(self), orig);
    if (imp) ((void(*)(id,SEL,id))imp)(self, orig, reason);
}

#pragma mark - hook 安装

// 给 cls 的 sel 安装 hook：把原 IMP 存到 origSel，再用 newImp 替换
static BOOL InstallHook(Class cls, SEL sel, SEL origSel, IMP newImp) {
    if (!cls || !sel) return NO;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return NO;
    const char *types = method_getTypeEncoding(m);
    IMP origIMP = method_getImplementation(m);
    // 存原实现
    class_addMethod(cls, origSel, origIMP, types);
    // 替换
    method_setImplementation(m, newImp);
    NSLog(@"[WXHook] hooked %@ on %@", NSStringFromSelector(sel), NSStringFromClass(cls));
    return YES;
}

// 在运行时按类名字符串找类（微信混淆类名时容错）
static Class FindClass(NSArray<NSString *> *names) {
    for (NSString *n in names) {
        Class c = objc_getClass(n.UTF8String);
        if (c) return c;
    }
    return Nil;
}

__attribute__((constructor)) static void WXHookInit(void) {
    @autoreleasepool {
        NSLog(@"[WXHook] ===== WeChatCallHook injected =====");

        // MMServiceCenter —— 官方确认的类名
        Class mm = FindClass(@[@"MMServiceCenter", @"MMServiceCenterWrapper"]);
        if (mm) {
            InstallHook(mm,
                        sel_registerName("openAudioWindowWithContact:msgWrap:monoMsg:isCaller:from:startInApp:completion:"),
                        sel_registerName("WXOrig_openAudioWindowWithContact:msgWrap:monoMsg:isCaller:from:startInApp:completion:"),
                        (IMP)hooked_openAudioWindow);
            InstallHook(mm,
                        sel_registerName("openVideoWindowWithContact:msgWrap:monoMsg:isCaller:from:startInApp:completion:"),
                        sel_registerName("WXOrig_openVideoWindowWithContact:msgWrap:monoMsg:isCaller:from:startInApp:completion:"),
                        (IMP)hooked_openVideoWindow);
            InstallHook(mm,
                        sel_registerName("openWindowWithContact:msgWrap:monoMsg:isCaller:from:startInApp:isEarMode:isAudioMode:completion:"),
                        sel_registerName("WXOrig_openWindowWithContact:msgWrap:monoMsg:isCaller:from:startInApp:isEarMode:isAudioMode:completion:"),
                        (IMP)hooked_openWindow);
            NSLog(@"[WXHook] MMServiceCenter found, hooks installed");
        } else {
            NSLog(@"[WXHook] ★MMServiceCenter NOT FOUND —— 微信版本可能混淆了类名");
        }

        // 接听时间戳方法：官方符号 setStartTalkTimestamp: / setM_currentStartTalkTime:
        // 用遍历所有类的方式找（类名不确定）
        int clsCount = objc_getClassList(NULL, 0);
        Class *classes = (Class *)malloc(sizeof(Class) * clsCount);
        objc_getClassList(classes, clsCount);
        SEL setTalkSel = sel_registerName("setStartTalkTimestamp:");
        SEL hangSel = sel_registerName("OnHangup:");
        for (int i = 0; i < clsCount; i++) {
            Class c = classes[i];
            if (class_getInstanceMethod(c, setTalkSel)) {
                InstallHook(c, setTalkSel, sel_registerName("WXOrig_setStartTalkTimestamp:"), (IMP)hooked_setStartTalkTime);
            }
            if (class_getInstanceMethod(c, hangSel)) {
                InstallHook(c, hangSel, sel_registerName("WXOrig_OnHangup:"), (IMP)hooked_OnHangup);
            }
        }
        free(classes);
        NSLog(@"[WXHook] ===== init done =====");
    }
}
