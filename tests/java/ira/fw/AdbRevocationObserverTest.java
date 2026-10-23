// SPDX-License-Identifier: AGPL-3.0-or-later
package ira.fw;

import android.os.Handler;
import android.os.Message;

public final class AdbRevocationObserverTest {
    private static int checks;
    private static final StringBuilder events = new StringBuilder();
    private static class PlatformHandler extends Handler {
        private static final int MESSAGE_ADB_CLEAR = 83;
        PlatformHandler(Callback callback) { super(callback); }
        @Override public void handleMessage(Message message) { events.append("system;"); }
    }
    private static final class VendorHandler extends PlatformHandler {
        VendorHandler(Callback callback) { super(callback); }
    }
    private static void expect(String expected) {
        if (!events.toString().equals(expected)) throw new AssertionError(events.toString());
        events.setLength(0);
        ++checks;
    }
    public static void main(String[] args) throws Exception {
        Handler handler = new VendorHandler(message -> {
            events.append("previous;");
            return false;
        });
        AdbRevocationObserver.install(new Object(), handler, () -> events.append("revoke;"));
        handler.dispatchMessage(new Message(83));
        expect("previous;system;revoke;");
        handler.dispatchMessage(new Message(82));
        expect("previous;system;");
        handler = new VendorHandler(message -> {
            events.append("consumed;");
            return true;
        });
        AdbRevocationObserver.install(new Object(), handler, () -> events.append("revoke;"));
        handler.dispatchMessage(new Message(83));
        expect("consumed;revoke;");
        handler.dispatchMessage(new Message(82));
        expect("consumed;");
        handler = new VendorHandler(null);
        AdbRevocationObserver.install(new Object(), handler, () -> events.append("revoke;"));
        handler.dispatchMessage(new Message(83));
        expect("system;revoke;");
        Handler failing = new VendorHandler(message -> { throw new IllegalStateException("test"); });
        AdbRevocationObserver.install(new Object(), failing, () -> events.append("revoke;"));
        try {
            failing.dispatchMessage(new Message(83));
            throw new AssertionError("original exception swallowed");
        } catch (IllegalStateException expected) {
            expect("revoke;");
        }
        try {
            AdbRevocationObserver.install(new Object(), new Handler(), () -> {});
            throw new AssertionError("missing clear constant guessed");
        } catch (NoSuchFieldException expected) { ++checks; }
        System.out.println("PASS: " + checks + " framework revocation observer checks");
    }
}
