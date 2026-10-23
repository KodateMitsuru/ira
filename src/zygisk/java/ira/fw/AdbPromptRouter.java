// SPDX-License-Identifier: AGPL-3.0-or-later
package ira.fw;

import android.os.Handler;
import android.os.Message;
import android.util.Log;
import java.lang.reflect.Field;

/** Only lends the reply slot while the handler synchronously processes this request's answer. */
final class AdbPromptRouter implements Handler.Callback {
    interface Route { void dispatch(Runnable original) throws Exception; }
    private static final class Pending {
        final String key;
        final Route route;
        final Runnable denied;
        Message confirm;
        Runnable timeout;
        boolean shown;
        final long received;
        Pending(String key, Route route, Runnable denied, long received) {
            this.key = key; this.route = route; this.denied = denied; this.received = received;
        }
    }
    private final Handler handler;
    private final int confirm, allow, deny;
    private Handler.Callback previous;
    private Pending active;
    private String retired;
    private boolean platformPrompt;

    AdbPromptRouter(Object manager, Handler handler) throws Exception {
        this.handler = handler;
        confirm = AdbResponseThreadBinding.messageCode(manager, handler, "MESSAGE_ADB_CONFIRM");
        allow = AdbResponseThreadBinding.messageCode(manager, handler, "MESSAGE_ADB_ALLOW");
        deny = AdbResponseThreadBinding.messageCode(manager, handler, "MESSAGE_ADB_DENY");
    }
    void install() throws Exception {
        Field callback = AdbResponseThreadBinding.findField(Handler.class, "mCallback");
        callback.setAccessible(true);
        handler.post(() -> {
            try {
                previous = (Handler.Callback) callback.get(handler);
                callback.set(handler, this);
            } catch (Exception e) { Log.e("ira-fw", "cannot install prompt router", e); }
        });
    }
    void request(String key, Route route, Runnable denied) {
        final long received = System.nanoTime();
        handler.post(() -> {
            if (platformPrompt) { denied.run(); return; }
            cancel();
            platformPrompt = false;
            retired = null;
            Pending request = new Pending(key, route, denied, received);
            active = request;
            request.confirm = Message.obtain(handler, confirm, key);
            request.confirm.sendToTarget();
            request.timeout = () -> { if (active == request) cancel(); };
            handler.postDelayed(request.timeout, 40000);
        });
    }
    // Called only on the handler's looper. A late answer must never borrow the platform slot.
    void cancel() {
        Pending request = active;
        active = null;
        if (request != null) {
            retired = request.key;
            handler.removeMessages(confirm, request.key);
            handler.removeCallbacks(request.timeout);
            request.denied.run();
        }
    }
    void channelClosed() { handler.post(this::cancel); }
    private void original(Message message) {
        if (previous == null || !previous.handleMessage(message)) handler.handleMessage(message);
    }
    @Override public boolean handleMessage(Message message) {
        if (message.what == confirm) {
            if (active != null && message == active.confirm) {
                Pending request = active;
                request.shown = true;
                long started = System.nanoTime();
                try { original(message); } catch (RuntimeException e) { cancel(); throw e; }
                finally {
                    Log.i("ira-fw", "auth prompt: queue=" + ((started - request.received) / 1000000)
                            + "ms, framework=" + ((System.nanoTime() - started) / 1000000) + "ms");
                }
                return true;
            }
            cancel();
            retired = null;
            platformPrompt = true;
        } else if (message.what == allow || message.what == deny) {
            Pending request = active;
            boolean ours = request != null && request.shown &&
                    (message.what == deny || request.key.equals(message.obj));
            if (ours) {
                active = null;
                retired = request.key;
                handler.removeCallbacks(request.timeout);
                long started = System.nanoTime();
                try { request.route.dispatch(() -> original(message)); }
                catch (Exception e) { Log.e("ira-fw", "cannot route auth answer", e); request.denied.run(); }
                finally {
                    Log.i("ira-fw", "auth answer: framework="
                            + ((System.nanoTime() - started) / 1000000) + "ms");
                }
                return true;
            }
            if (platformPrompt) {
                try { original(message); } finally { platformPrompt = false; }
                return true;
            }
            if (retired != null &&
                    (message.what == deny || retired.equals(message.obj))) return true;
        }
        return previous != null && previous.handleMessage(message);
    }
}
