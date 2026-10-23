// SPDX-License-Identifier: AGPL-3.0-or-later
package framework.fixture;

/** Deliberately absent from the payload ClassLoader and named unlike any AOSP internal class. */
public final class PlatformAuthFixture {
    public static final class Manager {
        public static final int MESSAGE_ADB_CONFIRM = 71;
        private Worker mThread;
        public final class Worker extends Thread {
            private Worker() {}
        }
    }
    public static final class Handler {
        private static final int MESSAGE_ADB_CONFIRM = 93;
        private final Responder mThread = new Responder();
    }
    public static class Responder extends Thread {
        private Responder() {}
    }
}
