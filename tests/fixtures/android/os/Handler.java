// SPDX-License-Identifier: AGPL-3.0-or-later
package android.os;
import java.util.ArrayDeque;
import java.util.ArrayList;

public class Handler {
    public interface Callback { boolean handleMessage(Message message); }
    private Callback mCallback;
    private final ArrayDeque<Message> messages = new ArrayDeque<>();
    private final ArrayList<Runnable> delayed = new ArrayList<>();
    public Handler() {}
    public Handler(Callback callback) { mCallback = callback; }
    public boolean post(Runnable task) { task.run(); return true; }
    public boolean postDelayed(Runnable task, long delay) { delayed.add(task); return true; }
    public void removeCallbacks(Runnable task) { delayed.removeIf(queued -> queued == task); }
    public int delayedCount() { return delayed.size(); }
    public void removeMessages(int what, Object object) {
        messages.removeIf(message -> message.what == what && message.obj == object);
    }
    void enqueue(Message message) { messages.add(message); }
    public void drain() { while (!messages.isEmpty()) dispatchMessage(messages.remove()); }
    public void expire() { var callbacks = new ArrayList<>(delayed); delayed.clear(); callbacks.forEach(Runnable::run); }
    public void handleMessage(Message message) {}
    public void dispatchMessage(Message message) {
        if (mCallback == null || !mCallback.handleMessage(message)) handleMessage(message);
    }
}
