// SPDX-License-Identifier: AGPL-3.0-or-later
package ira.fw;
import android.net.LocalSocket;
import java.nio.charset.StandardCharsets;

public final class AdbRevocationCommandTest {
    private static int checks;
    private static void expect(boolean condition, String reason) {
        if (!condition) throw new AssertionError(reason);
        ++checks;
    }
    public static void main(String[] args) throws Exception {
        AdbRevocationCommand.send("fixture.ctl");
        expect("fixture.ctl".equals(LocalSocket.name), "control endpoint is used");
        expect(LocalSocket.timeout == 1000, "timeout is set after native socket creation");
        expect("auth revoke\n".equals(LocalSocket.request.toString(StandardCharsets.UTF_8)),
               "exact revoke command written");
        expect(LocalSocket.closed, "socket closed after fragmented ACK");
        for (String response : new String[] {"", "ok", "err"}) {
            LocalSocket.response = response;
            try {
                AdbRevocationCommand.send("fixture.ctl");
                throw new AssertionError("accepted invalid acknowledgement");
            } catch (IllegalStateException expected) {
                expect(LocalSocket.closed, "failed acknowledgement releases socket for retry");
            }
        }
        LocalSocket.failConnect = true;
        try {
            AdbRevocationCommand.send("fixture.ctl");
            throw new AssertionError("lost daemon ignored");
        } catch (java.io.IOException expected) {
            expect(LocalSocket.closed, "failed connect releases socket");
        }
        System.out.println("PASS: " + checks + " actual revocation command checks (Android lazy socket)");
    }
}
