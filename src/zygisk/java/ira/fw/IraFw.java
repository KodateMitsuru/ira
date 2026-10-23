// SPDX-License-Identifier: AGPL-3.0-or-later
package ira.fw;

import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.FileObserver;
import android.os.Handler;
import android.os.Message;
import android.util.Log;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Framework adapter for the unchanged upstream libadbd_auth PK/CK/DC/OK/NO/DD protocol. */
public final class IraFw {
    private static final String TAG = "ira-fw";
    public static String sockName = "";
    public static String controlName = "";
    private static volatile LocalSocket channel;
    private static FileObserver keyObserver;
    private static Set<String> knownKeys = new LinkedHashSet<>();
    // Key snapshots, removed-key reports and reply writes share this ordered I/O worker.
    private static final Set<String> removedKeys = new LinkedHashSet<>();
    private static final ExecutorService authIo = Executors.newSingleThreadExecutor(task -> {
        Thread thread = new Thread(task, "ira-auth-io");
        thread.setDaemon(true);
        return thread;
    });

    public static void main() {
        try {
            Object manager = waitForManager();
            if (manager == null) throw new IllegalStateException("No ADB manager");
            Handler handler = (Handler) get(manager, "mHandler");
            if (handler == null) throw new IllegalStateException("No ADB handler");
            AdbPromptRouter router = new AdbPromptRouter(manager, handler);
            router.install();
            AdbRevocationClient revocations = new AdbRevocationClient(IraFw::notifyRevoked);
            AdbRevocationObserver.install(manager, handler, () -> { router.cancel(); revocations.request(); });
            int connected = AdbResponseThreadBinding.messageCode(manager, handler, "MESSAGE_ADB_CONNECTED_KEY");
            int disconnected = AdbResponseThreadBinding.messageCode(manager, handler, "MESSAGE_ADB_DISCONNECT");
            startKeyObserver();
            for (;;) {
                try (LocalSocket socket = new LocalSocket(LocalSocket.SOCKET_SEQPACKET)) {
                    socket.connect(new LocalSocketAddress(sockName, LocalSocketAddress.Namespace.ABSTRACT));
                    try (AdbAuthWriter output = new AdbAuthWriter(socket.getOutputStream(), authIo, error -> {
                        Log.w(TAG, "cannot send auth reply; closing channel", error);
                        try { socket.close(); } catch (Exception ignored) {}
                    })) {
                        channel = socket;
                        authIo.execute(IraFw::syncRemovedKeys);
                        Log.i(TAG, "connected to private libadbd_auth channel");
                        byte[] packet = new byte[8193];
                        int size;
                        while ((size = socket.getInputStream().read(packet)) > 0) {
                            if (size < 2 || size == packet.length) throw new IllegalStateException("Invalid auth packet");
                            String code = new String(packet, 0, 2, "UTF-8");
                            String key = new String(packet, 2, size - 2, "UTF-8").trim();
                            if ("PK".equals(code)) {
                                if (!looksLikePubKey(key)) { send(output, "NO"); continue; }
                                router.request(key, original -> withReplySocket(manager, handler, socket, output, original),
                                               () -> send(output, "NO"));
                            } else if ("CK".equals(code) || "DC".equals(code)) {
                                Message.obtain(handler, "CK".equals(code) ? connected : disconnected, key).sendToTarget();
                            } else {
                                throw new IllegalStateException("Unsupported private auth packet: " + code);
                            }
                        }
                    }
                } catch (Exception e) {
                    Log.w(TAG, "private auth channel disconnected", e);
                } finally {
                    channel = null;
                    router.channelClosed();
                }
                Thread.sleep(1000);
            }
        } catch (Throwable t) { Log.e(TAG, "framework half failed", t); }
    }

    private static void withReplySocket(Object manager, Handler handler, LocalSocket socket,
                                         OutputStream output, Runnable original) throws Exception {
        // Runs only during one allow/deny dispatch on the owning Handler looper. No field is
        // borrowed while a dialog is visible, a socket read blocks, or another message executes.
        AdbResponseThreadBinding binding = AdbResponseThreadBinding.find(manager, handler);
        Object thread = binding.createThread(manager);
        set(thread, "mHandler", handler);
        set(thread, "mSocket", socket);
        set(thread, "mInputStream", socket.getInputStream());
        set(thread, "mOutputStream", output);
        Object previous = binding.get();
        binding.set(thread);
        try { original.run(); }
        finally { if (binding.get() == thread) binding.set(previous); }
    }
    private static void send(OutputStream output, String packet) {
        try { output.write(packet.getBytes("UTF-8")); }
        catch (Exception e) { Log.w(TAG, "cannot send auth reply", e); }
    }
    private static Set<String> readKeys() {
        Set<String> result = new LinkedHashSet<>();
        try (BufferedReader in = new BufferedReader(new FileReader("/data/misc/adb/adb_keys"))) {
            String line;
            while ((line = in.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty()) result.add(line);
            }
        } catch (java.io.FileNotFoundException missing) {
            // Deleting adb_keys is a legitimate revoke event.
        } catch (Exception e) {
            Log.e(TAG, "cannot read adb key changes", e);
            return null;
        }
        return result;
    }
    private static void syncRemovedKeys() {
        Set<String> current = readKeys();
        if (current == null) return;
        for (String key : knownKeys) if (!current.contains(key)) removedKeys.add(key);
        knownKeys = current;
        LocalSocket socket = channel;
        if (socket == null) return;
        for (String key : new LinkedHashSet<>(removedKeys)) {
            try {
                socket.getOutputStream().write(("DD" + key).getBytes("UTF-8"));
                removedKeys.remove(key);
            } catch (Exception e) { Log.w(TAG, "cannot report removed key", e); break; }
        }
    }
    private static void startKeyObserver() {
        keyObserver = new FileObserver("/data/misc/adb", FileObserver.CLOSE_WRITE | FileObserver.MOVED_TO |
                                      FileObserver.DELETE | FileObserver.MOVED_FROM) {
            @Override public void onEvent(int event, String path) {
                if ("adb_keys".equals(path)) authIo.execute(IraFw::syncRemovedKeys);
            }
        };
        keyObserver.startWatching();
        authIo.execute(IraFw::syncRemovedKeys);
    }
    private static void notifyRevoked() throws Exception {
        AdbRevocationCommand.send(controlName);
    }
    private static Object waitForManager() throws Exception {
        Class<?> sm = Class.forName("android.os.ServiceManager");
        Method getService = sm.getDeclaredMethod("getService", String.class);
        getService.setAccessible(true);
        for (int i = 0; i < 600; ++i) {
            Object service = getService.invoke(null, "adb");
            if (service != null) {
                Object manager = get(service, "mDebuggingManager");
                if (manager != null) return manager;
            }
            Thread.sleep(250);
        }
        return null;
    }
    private static Object get(Object target, String name) throws Exception {
        Field field = AdbResponseThreadBinding.findField(target.getClass(), name);
        field.setAccessible(true);
        return field.get(target);
    }
    private static void set(Object target, String name, Object value) throws Exception {
        Field field = AdbResponseThreadBinding.findField(target.getClass(), name);
        field.setAccessible(true);
        field.set(target, value);
    }
    private static boolean looksLikePubKey(String key) {
        if (key.length() < 200 || key.length() > 4096) return false;
        try {
            String blob = key.split("[ \\t]", 2)[0];
            byte[] bytes = android.util.Base64.decode(blob, android.util.Base64.DEFAULT);
            return bytes.length == 524 && bytes[0] == 64 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0;
        } catch (IllegalArgumentException invalid) { return false; }
    }
}
