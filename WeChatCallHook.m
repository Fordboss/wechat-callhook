// WeChatCallHook —— 对标官方 TrollRecorder 的 TRWeChatBridgeClient tweak
// 自包含 dylib：用 Objective-C runtime hook 微信通话方法，
// 检测来电/接通/挂断，通过 Darwin 通知触发自建录音 App 自动开始/停止。
// 用 TrollFools 注入到微信进程即可生效，不依赖 Theos/Substrate/ellekit。
//
// 关键事实（来自官方 dylib 逆向，已核实完整 selector）：
//   MMServiceCenter:
//     openAudioWindowWithContact:msgWrap:monoMsg:isCaller:from:startInApp:completion:
//     openVideoWindowWithContact:msgWrap:monoMsg:isCaller:from:startInApp:completion:
//     openWindowWithContact:msgWrap:monoMsg:isCaller:from:startInApp:isEarMode:isAudioMode:completion:
//   OnHangup: / setStartTalkTimestamp: / setM_currentStartTalkTime:
// 这些 selector 官方原样使用、无版本判断 —— 说明它们跨微信版本稳定。
//
// 跨进程通信只用 Darwin 通知（和通知名一个信号），payload 走全局日志文件，不依赖 App Group
// （微信是 App Store 正版签名，无法与自建 App 共享 App Group）。

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <CoreFoundation/CoreFoundation.h>

// 与自建 App 约定的 Darwin 通知名
static CFStringRef const kNotifyCallStart = CFSTR("com.wb.callrecorder.wxc.start");
static CFStringRef const kNotifyCallEnd   = CFSTR("com.wb.callrecorder.wxc.end");

// 全局诊断日志：微信与自建 App 都在巨魔环境，都能读写这个路径
static NSString * const kLogPath = @"/var/mobile/Library/wxcallhook.log";

static void WXLog(NSString *fmt, ...) {
    va_list args; va_start(args, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    NSDateFormatter *df = [NSDateFormatter new];
    df.dateFormat = @"HH:mm:ss";
    NSString *stamped = [NSString stringWithFormat:@"[%@] %@\n", [df stringFromDate:[NSDate date]], line];
    // 追加写，失败也不影响主流程
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:kLogPath];
    if (fh) { [fh seekToEndOfFile]; [fh writeData:[stamped dataUsingEncoding:NSUTF8StringEncoding]]; [fh closeFile]; }
    else { [stamped writeToFile:kLogPath atomically:NO encoding:NSUTF8StringEncoding error:nil]; }
    NSLog(@"[WXHook] %@", line);
}

static void WXPost(CFStringRef name) {
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                         name, NULL, NULL, true);
}

#pragma mark - 语音/视频通话窗口打开 → 通话开始

static void hooked_openAudioWindow(id self, SEL _cmd, id contact, id msgWrap,
                                   BOOL monoMsg, BOOL isCaller, id from,
                                   BOOL startInApp, id completion) {
    WXLog(@"audio call START isCaller=%d", isCaller);
    WXPost(kNotifyCallStart);
    SEL orig = sel_registerName("WXOrig_openAudioWindowWithContact:msgWrap:monoMsg:isCaller:from:startInApp:completion:");
    IMP imp = class_getMethodImplementation(object_getClass(self), orig);
    if (imp) ((void(*)(id,SEL,id,id,BOOL,BOOL,id,BOOL,id))imp)(self, orig, contact, msgWrap, monoMsg, isCaller, from, startInApp, completion);
}

static void hooked_openVideoWindow(id self, SEL _cmd, id contact, id msgWrap,
                                   BOOL monoMsg, BOOL isCaller, id from,
                                   BOOL startInApp, id completion) {
    WXLog(@"video call START isCaller=%d", isCaller);
    WXPost(kNotifyCallStart);
    SEL orig = sel_registerName("WXOrig_openVideoWindowWithContact:msgWrap:monoMsg:isCaller:from:startInApp:completion:");
    IMP imp = class_getMethodImplementation(object_getClass(self), orig);
    if (imp) ((void(*)(id,SEL,id,id,BOOL,BOOL,id,BOOL,id))imp)(self, orig, contact, msgWrap, monoMsg, isCaller, from, startInApp, completion);
}

static void hooked_openWindow(id self, SEL _cmd, id contact, id msgWrap,
                              BOOL monoMsg, BOOL isCaller, id from,
                              BOOL startInApp, BOOL isEarMode, BOOL isAudioMode, id completion) {
    WXLog(@"generic call START isCaller=%d isAudioMode=%d", isCaller, isAudioMode);
    WXPost(kNotifyCallStart);
    SEL orig = sel_registerName("WXOrig_openWindowWithContact:msgWrap:monoMsg:isCaller:from:startInApp:isEarMode:isAudioMode:completion:");
    IMP imp = class_getMethodImplementation(object_getClass(self), orig);
    if (imp) ((void(*)(id,SEL,id,id,BOOL,BOOL,id,BOOL,BOOL,BOOL,id))imp)(self, orig, contact, msgWrap, monoMsg, isCaller, from, startInApp, isEarMode, isAudioMode, completion);
}

#pragma mark - 通话接听与挂断

static void hooked_setStartTalkTime(id self, SEL _cmd, id arg) {
    WXLog(@"call ANSWERED");
    WXPost(kNotifyCallStart);  // 接听再补一次 start，确保从接通开始录
    SEL orig = sel_registerName("WXOrig_setStartTalkTimestamp:");
    IMP imp = class_getMethodImplementation(object_getClass(self), orig);
    if (imp) ((void(*)(id,SEL,id))imp)(self, orig, arg);
}

static void hooked_OnHangup(id self, SEL _cmd, id reason) {
    WXLog(@"call END (OnHangup) reason=%@", reason);
    WXPost(kNotifyCallEnd);
    SEL orig = sel_registerName("WXOrig_OnHangup:");
    IMP imp = class_getMethodImplementation(object_getClass(self), orig);
    if (imp) ((void(*)(id,SEL,id))imp)(self, orig, reason);
}

static void hooked_hangupNoArg(id self, SEL _cmd) {
    WXLog(@"call END (hangup)");
    WXPost(kNotifyCallEnd);
    SEL orig = sel_registerName("WXOrig_hangup");
    IMP imp = class_getMethodImplementation(object_getClass(self), orig);
    if (imp) ((void(*)(id,SEL))imp)(self, orig);
}

#pragma mark - hook 安装

static BOOL InstallHook(Class cls, SEL sel, SEL origSel, IMP newImp) {
    if (!cls || !sel) return NO;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return NO;
    const char *types = method_getTypeEncoding(m);
    IMP origIMP = method_getImplementation(m);
    class_addMethod(cls, origSel, origIMP, types);
    method_setImplementation(m, newImp);
    WXLog(@"hooked %@ on %@", NSStringFromSelector(sel), NSStringFromClass(cls));
    return YES;
}

__attribute__((constructor)) static void WXHookInit(void) {
    @autoreleasepool {
        [@"===== WeChatCallHook injected =====" writeToFile:kLogPath atomically:NO encoding:NSUTF8StringEncoding error:nil];
        WXLog(@"init begin");

        // 1) MMServiceCenter —— 官方确认的类名，语音/视频/通用窗口三个方法
        Class mm = objc_getClass("MMServiceCenter") ?: objc_getClass("MMServiceCenterWrapper");
        if (mm) {
            InstallHook(mm, sel_registerName("openAudioWindowWithContact:msgWrap:monoMsg:isCaller:from:startInApp:completion:"),
                        sel_registerName("WXOrig_openAudioWindowWithContact:msgWrap:monoMsg:isCaller:from:startInApp:completion:"), (IMP)hooked_openAudioWindow);
            InstallHook(mm, sel_registerName("openVideoWindowWithContact:msgWrap:monoMsg:isCaller:from:startInApp:completion:"),
                        sel_registerName("WXOrig_openVideoWindowWithContact:msgWrap:monoMsg:isCaller:from:startInApp:completion:"), (IMP)hooked_openVideoWindow);
            InstallHook(mm, sel_registerName("openWindowWithContact:msgWrap:monoMsg:isCaller:from:startInApp:isEarMode:isAudioMode:completion:"),
                        sel_registerName("WXOrig_openWindowWithContact:msgWrap:monoMsg:isCaller:from:startInApp:isEarMode:isAudioMode:completion:"), (IMP)hooked_openWindow);
        } else {
            WXLog(@"!! MMServiceCenter NOT FOUND");
        }

        // 2) 遍历所有类，装接听/挂断 hook（类名不确定，按 selector 找）
        int n = objc_getClassList(NULL, 0);
        Class *classes = (Class *)malloc(sizeof(Class) * n);
        objc_getClassList(classes, n);
        SEL sTalk = sel_registerName("setStartTalkTimestamp:");
        SEL sTalk2 = sel_registerName("setM_currentStartTalkTime:");
        SEL sHang = sel_registerName("OnHangup:");
        SEL sHang2 = sel_registerName("hangup");
        int cTalk = 0, cHang = 0;
        for (int i = 0; i < n; i++) {
            Class c = classes[i];
            if (class_getInstanceMethod(c, sTalk))  { InstallHook(c, sTalk,  sel_registerName("WXOrig_setStartTalkTimestamp:"), (IMP)hooked_setStartTalkTime); cTalk++; }
            if (class_getInstanceMethod(c, sTalk2)) { InstallHook(c, sTalk2, sel_registerName("WXOrig_setM_currentStartTalkTime:"), (IMP)hooked_setStartTalkTime); cTalk++; }
            if (class_getInstanceMethod(c, sHang))  { InstallHook(c, sHang,  sel_registerName("WXOrig_OnHangup:"), (IMP)hooked_OnHangup); cHang++; }
            if (class_getInstanceMethod(c, sHang2)) { InstallHook(c, sHang2, sel_registerName("WXOrig_hangup"), (IMP)hooked_hangupNoArg); cHang++; }
        }
        free(classes);
        WXLog(@"init done: talk_hooks=%d hangup_hooks=%d", cTalk, cHang);
    }
}
