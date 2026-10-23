// SPDX-License-Identifier: AGPL-3.0-or-later
package android.net;
import java.io.*;
import java.nio.charset.StandardCharsets;

/** Models Android's lazy native fd and one-byte reads to catch the failed device path. */
public final class LocalSocket implements AutoCloseable {
    public static final int SOCKET_STREAM = 2;
    public static String response = "ok\n";
    public static String name;
    public static boolean closed;
    public static boolean connected;
    public static boolean failConnect;
    public static int timeout;
    public static ByteArrayOutputStream request;
    private InputStream input;
    public LocalSocket(int type) {
        if (type != SOCKET_STREAM) throw new AssertionError("wrong control socket type");
        connected = false; closed = false; timeout = 0; request = new ByteArrayOutputStream();
    }
    public void connect(LocalSocketAddress address) throws IOException {
        if (failConnect) throw new IOException("daemon unavailable");
        if (address.namespace != LocalSocketAddress.Namespace.ABSTRACT) throw new AssertionError();
        name = address.name; connected = true;
    }
    public void setSoTimeout(int value) throws IOException {
        if (!connected) throw new IOException("socket not created");
        timeout = value;
    }
    public OutputStream getOutputStream() throws IOException {
        if (!connected || timeout != 1000) throw new IOException("socket not ready");
        return request;
    }
    public InputStream getInputStream() {
        if (input == null) input = new ByteArrayInputStream(response.getBytes(StandardCharsets.UTF_8)) {
            @Override public synchronized int read(byte[] bytes, int offset, int length) {
                return super.read(bytes, offset, Math.min(length, 1));
            }
        };
        return input;
    }
    public void close() { closed = true; }
}
