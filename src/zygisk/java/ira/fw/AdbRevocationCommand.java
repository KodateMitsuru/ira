// SPDX-License-Identifier: AGPL-3.0-or-later
package ira.fw;

import android.net.LocalSocket;
import android.net.LocalSocketAddress;

/** The actual Android socket operation, kept independently testable from framework reflection. */
final class AdbRevocationCommand {
    static void send(String controlName) throws Exception {
        try (LocalSocket socket = new LocalSocket(LocalSocket.SOCKET_STREAM)) {
            // Android creates the native fd in connect(), not in the Java constructor.
            socket.connect(new LocalSocketAddress(controlName, LocalSocketAddress.Namespace.ABSTRACT));
            socket.setSoTimeout(1000);
            socket.getOutputStream().write("auth revoke\n".getBytes("UTF-8"));
            byte[] answer = new byte[3];
            int used = 0;
            while (used < answer.length) {
                int n = socket.getInputStream().read(answer, used, answer.length - used);
                if (n <= 0) break;
                used += n;
            }
            if (used != 3 || !"ok\n".equals(new String(answer, "UTF-8")))
                throw new IllegalStateException("Daemon did not acknowledge revocation");
        }
    }
}
