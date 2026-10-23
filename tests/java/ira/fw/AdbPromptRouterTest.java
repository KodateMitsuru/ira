// SPDX-License-Identifier: AGPL-3.0-or-later
package ira.fw;
import android.os.Handler;
import android.os.Message;

public final class AdbPromptRouterTest {
    private static int checks;
    private static final StringBuilder events = new StringBuilder();
    private static final class PlatformHandler extends Handler {
        private static final int MESSAGE_ADB_CONFIRM = 71;
        private static final int MESSAGE_ADB_ALLOW = 72;
        private static final int MESSAGE_ADB_DENY = 73;
        PlatformHandler() { super(message -> { events.append("callback;"); return false; }); }
        @Override public void handleMessage(Message message) { events.append("system" + message.what + ";"); }
    }
    private static void expect(String expected) {
        if (!events.toString().equals(expected)) throw new AssertionError("expected " + expected + ", got " + events);
        events.setLength(0); ++checks;
    }
    public static void main(String[] args) throws Exception {
        PlatformHandler handler = new PlatformHandler();
        AdbPromptRouter router = new AdbPromptRouter(new Object(), handler);
        router.install();
        AdbPromptRouter.Route route = original -> {
            events.append("borrow;");
            try { original.run(); } finally { events.append("restore;"); }
        };
        router.request("ours", route, () -> events.append("NO;"));
        handler.drain();
        expect("callback;system71;"); // no reply slot borrowed while the dialog is visible
        handler.dispatchMessage(Message.obtain(handler, 72, "ours"));
        expect("borrow;callback;system72;restore;");
        if (handler.delayedCount() != 0) throw new AssertionError("answered prompt retained its timeout");
        ++checks;
        handler.expire(); expect("");
        handler.dispatchMessage(Message.obtain(handler, 72, "ours")); expect(""); // late duplicate
        router.request("timeout", route, () -> events.append("NO;")); handler.drain();
        expect("callback;system71;");
        handler.expire(); expect("NO;");
        handler.dispatchMessage(Message.obtain(handler, 72, "timeout")); expect("");
        router.request("platform-race", route, () -> events.append("NO;")); handler.drain();
        expect("callback;system71;");
        handler.dispatchMessage(Message.obtain(handler, 71, "platform"));
        expect("NO;callback;system71;");
        handler.dispatchMessage(Message.obtain(handler, 72, "platform"));
        expect("callback;system72;"); // never borrow the slot for the platform's answer
        router.request("cancel-before-dispatch", route, () -> events.append("NO;"));
        router.cancel(); handler.drain(); expect("NO;");
        if (handler.delayedCount() != 0) throw new AssertionError("cancelled prompt retained its timeout");
        ++checks;
        router.request("deny", route, () -> events.append("NO;")); handler.drain();
        expect("callback;system71;");
        handler.dispatchMessage(new Message(73)); expect("borrow;callback;system73;restore;");
        router.request("exception", original -> { throw new Exception("test"); }, () -> events.append("NO;"));
        handler.drain(); expect("callback;system71;");
        handler.dispatchMessage(Message.obtain(handler, 72, "exception")); expect("NO;");
        System.out.println("PASS: " + checks + " Handler-confined prompt routing checks");
    }
}
