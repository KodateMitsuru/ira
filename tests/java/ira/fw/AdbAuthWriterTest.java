// SPDX-License-Identifier: AGPL-3.0-or-later
package ira.fw;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;

public final class AdbAuthWriterTest {
    private static int checks;
    private static void expect(boolean condition, String reason) {
        if (!condition) throw new AssertionError(reason);
        ++checks;
    }
    private static final class Queue implements Executor {
        final ArrayDeque<Runnable> tasks = new ArrayDeque<>();
        public void execute(Runnable task) { tasks.add(task); }
        void drain() { while (!tasks.isEmpty()) tasks.remove().run(); }
    }
    private static final class Packets extends OutputStream {
        final List<String> packets = new ArrayList<>();
        @Override public void write(int value) { throw new AssertionError("split auth packet"); }
        @Override public void write(byte[] bytes, int offset, int length) {
            packets.add(new String(bytes, offset, length, StandardCharsets.UTF_8));
        }
    }
    public static void main(String[] args) throws Exception {
        Queue queue = new Queue();
        Packets target = new Packets();
        AdbAuthWriter writer = new AdbAuthWriter(target, queue, error -> { throw new AssertionError(error); });
        byte[] reply = {'x', 'O', 'K', 'x'};
        writer.write(reply, 1, 2);
        reply[1] = 'N';
        writer.write(new byte[] {'N', 'O'});
        expect(target.packets.isEmpty(), "ADB Handler only queues replies and never calls socket write");
        queue.drain();
        expect(target.packets.equals(List.of("OK", "NO")), "immutable reply packets preserve order and boundaries");
        writer.write('N');
        queue.drain();
        expect(target.packets.get(2).equals("N"), "single-byte OutputStream API remains supported");
        writer.write(new byte[0]);
        expect(queue.tasks.isEmpty(), "empty writes do not create empty protocol packets");
        writer.write(new byte[] {'O', 'K'});
        writer.close();
        queue.drain();
        expect(target.packets.size() == 3, "queued replies for a closed connection are discarded");
        try {
            writer.write('N');
            throw new AssertionError("closed writer accepted reply");
        } catch (IOException expected) { ++checks; }

        int[] failures = {0};
        AdbAuthWriter failed = new AdbAuthWriter(new OutputStream() {
            @Override public void write(int value) throws IOException { throw new IOException("disconnected"); }
        }, queue, error -> ++failures[0]);
        failed.write(new byte[] {'O', 'K'});
        failed.write(new byte[] {'N', 'O'});
        Packets replacement = new Packets();
        AdbAuthWriter reconnected = new AdbAuthWriter(replacement, queue,
                error -> { throw new AssertionError(error); });
        reconnected.write(new byte[] {'O', 'K'});
        queue.drain();
        expect(failures[0] == 1, "failed connection is retired once");
        expect(replacement.packets.equals(List.of("OK")), "reconnection never receives an old connection's pending reply");
        reconnected.close();
        System.out.println("PASS: " + checks + " asynchronous auth reply checks");
    }
}
