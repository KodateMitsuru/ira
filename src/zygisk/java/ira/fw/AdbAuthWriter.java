// SPDX-License-Identifier: AGPL-3.0-or-later
package ira.fw;

import android.util.Log;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.concurrent.Executor;
import java.util.function.Consumer;

/** One connection's replies, copied and serialized off the ADB Handler. */
final class AdbAuthWriter extends OutputStream {
    private final OutputStream target;
    private final Executor queue;
    private final Consumer<IOException> failed;
    private volatile boolean closed;

    AdbAuthWriter(OutputStream target, Executor queue, Consumer<IOException> failed) {
        this.target = target;
        this.queue = queue;
        this.failed = failed;
    }
    @Override public void write(int value) throws IOException {
        write(new byte[] {(byte) value}, 0, 1);
    }
    @Override public void write(byte[] bytes, int offset, int length) throws IOException {
        if (closed) throw new IOException("Auth channel closed");
        if (offset < 0 || length < 0 || offset > bytes.length - length)
            throw new IndexOutOfBoundsException();
        if (length == 0) return;
        byte[] packet = Arrays.copyOfRange(bytes, offset, offset + length);
        long queued = System.nanoTime();
        queue.execute(() -> {
            if (closed) return;
            long started = System.nanoTime();
            try {
                target.write(packet);
                Log.i("ira-fw", "auth reply: queue=" + ((started - queued) / 1000000)
                        + "ms, write=" + ((System.nanoTime() - started) / 1000000) + "ms");
            } catch (IOException e) {
                closed = true;
                failed.accept(e);
            }
        });
    }
    // The socket owner closes the actual connection; discard work still queued for this one.
    @Override public void close() { closed = true; }
}
