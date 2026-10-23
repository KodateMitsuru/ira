// SPDX-License-Identifier: AGPL-3.0-or-later
package ira.fw;

import android.util.Log;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/** Retains revocations until the daemon acknowledges them, without socket I/O on the ADB Handler. */
final class AdbRevocationClient {
    interface Command { void send() throws Exception; }
    interface Queue { void post(Runnable task, long delayMillis); }
    private final Command command;
    private final Queue queue;
    private long requested;
    private boolean scheduled;
    private int failures;

    AdbRevocationClient(Command command) {
        this(command, backgroundQueue());
    }
    AdbRevocationClient(Command command, Queue queue) {
        this.command = command;
        this.queue = queue;
    }
    private static Queue backgroundQueue() {
        var worker = Executors.newSingleThreadScheduledExecutor(task -> {
            Thread thread = new Thread(task, "ira-revoke");
            thread.setDaemon(true);
            return thread;
        });
        return (task, delay) -> worker.schedule(task, delay, TimeUnit.MILLISECONDS);
    }
    synchronized void request() {
        ++requested;
        if (!scheduled) {
            scheduled = true;
            queue.post(this::deliver, 0);
        }
    }
    private void deliver() {
        final long generation;
        synchronized (this) { generation = requested; }
        try {
            command.send();
        } catch (Exception e) {
            // Keep retrying, but repeated failures must not flood logd with a stack every second.
            if (++failures == 1 || failures % 60 == 0)
                Log.w("ira-fw", "cannot revoke daemon ADB sessions; retrying (attempt " + failures + ")", e);
            queue.post(this::deliver, 1000);
            return;
        }
        failures = 0;
        Log.i("ira-fw", "daemon acknowledged ADB session revocation");
        synchronized (this) {
            if (generation != requested) queue.post(this::deliver, 0);
            else scheduled = false;
        }
    }
}
