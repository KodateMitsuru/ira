// SPDX-License-Identifier: AGPL-3.0-or-later
package ira.fw;

import java.util.ArrayDeque;

public final class AdbRevocationClientTest {
    private static int checks;
    private static void expect(boolean condition, String reason) {
        if (!condition) throw new AssertionError(reason);
        ++checks;
    }
    private static final class Queue implements AdbRevocationClient.Queue {
        final ArrayDeque<Runnable> tasks = new ArrayDeque<>();
        long delay;
        public void post(Runnable task, long delayMillis) { tasks.add(task); delay = delayMillis; }
        void run() { tasks.remove().run(); }
    }
    public static void main(String[] args) {
        Queue queue = new Queue();
        int[] sent = {0};
        AdbRevocationClient client = new AdbRevocationClient(() -> ++sent[0], queue);
        client.request();
        expect(sent[0] == 0, "request on ADB Handler performs no socket I/O");
        client.request();
        expect(queue.tasks.size() == 1, "duplicate pending requests share a worker task");
        queue.run();
        expect(sent[0] == 1 && queue.tasks.isEmpty(), "acknowledgement stops delivery");
        client.request();
        queue.run();
        expect(sent[0] == 2, "a later clear is delivered independently");

        Queue retry = new Queue();
        int[] attempts = {0};
        AdbRevocationClient reconnect = new AdbRevocationClient(() -> {
            if (++attempts[0] < 3) throw new java.io.IOException("daemon restarting or ACK lost");
        }, retry);
        reconnect.request();
        retry.run();
        expect(attempts[0] == 1 && retry.tasks.size() == 1 && retry.delay == 1000,
               "failed connection retains revocation with bounded retry frequency");
        reconnect.request();
        expect(retry.tasks.size() == 1, "new revoke while disconnected does not multiply retries");
        retry.run();
        retry.run();
        expect(attempts[0] == 3 && retry.tasks.isEmpty(), "reconnect completes and stops retries");

        Queue racing = new Queue();
        AdbRevocationClient[] duringSend = new AdbRevocationClient[1];
        int[] sends = {0};
        duringSend[0] = new AdbRevocationClient(() -> {
            if (++sends[0] == 1) duringSend[0].request();
        }, racing);
        duringSend[0].request();
        racing.run();
        expect(racing.tasks.size() == 1, "a clear during an in-flight command survives its old ACK");
        racing.run();
        expect(sends[0] == 2 && racing.tasks.isEmpty(), "in-flight newer request is delivered exactly once");
        System.out.println("PASS: " + checks + " asynchronous revocation delivery checks");
    }
}
