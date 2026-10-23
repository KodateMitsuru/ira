// SPDX-License-Identifier: AGPL-3.0-or-later
package ira.fw;

import android.os.Handler;
import android.os.Message;
import java.lang.reflect.Field;

/** Observes a framework message without skipping its handler or an existing callback. */
final class AdbRevocationObserver implements Handler.Callback {
    private final Handler handler;
    private final Handler.Callback previous;
    private final int clearMessage;
    private final Runnable revoked;

    private AdbRevocationObserver(Handler handler, Handler.Callback previous, int clearMessage,
                                  Runnable revoked) {
        this.handler = handler;
        this.previous = previous;
        this.clearMessage = clearMessage;
        this.revoked = revoked;
    }

    static void install(Object manager, Handler handler, Runnable revoked) throws Exception {
        int clear = AdbResponseThreadBinding.messageCode(manager, handler, "MESSAGE_ADB_CLEAR");
        Field callback = AdbResponseThreadBinding.findField(Handler.class, "mCallback");
        callback.setAccessible(true);
        // Install on the owning looper so dispatch never races a callback replacement.
        handler.post(() -> {
            try {
                Handler.Callback previous = (Handler.Callback) callback.get(handler);
                callback.set(handler, new AdbRevocationObserver(handler, previous, clear, revoked));
            } catch (IllegalAccessException e) {
                android.util.Log.e("ira-fw", "Cannot observe ADB revocation", e);
            }
        });
    }

    @Override
    public boolean handleMessage(Message message) {
        if (message.what != clearMessage) {
            return previous != null && previous.handleMessage(message);
        }
        try {
            if (previous == null || !previous.handleMessage(message)) {
                handler.handleMessage(message);
            }
        } finally {
            revoked.run();
        }
        return true;
    }
}
