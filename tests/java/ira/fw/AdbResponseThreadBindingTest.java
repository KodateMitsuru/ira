// SPDX-License-Identifier: AGPL-3.0-or-later
package ira.fw;

import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;

public final class AdbResponseThreadBindingTest {
    private static int checks;

    private static final class LegacyManager {
        private static final int MESSAGE_ADB_CONFIRM = 5;
        private LegacyResponder mThread;
        private final class LegacyResponder extends Thread {
            private LegacyResponder() {}
        }
    }
    private static final class StaticResponder extends Thread {
        private StaticResponder() {}
    }
    private static final class StaticManager {
        private StaticResponder mThread;
    }
    private static class LegacyHandler {
        private static final int MESSAGE_ADB_CONFIRM = 5;
    }
    private static final class VendorHandler extends LegacyHandler {}
    private static class ModernHandler {
        private static final int MESSAGE_ADB_CONFIRM = 7;
        private final StaticResponder mThread = new StaticResponder();
    }
    private static final class ModernManager {}
    private static final class VendorModernHandler extends ModernHandler {}
    private static final class WrongField {
        private final String mThread = "wrong";
    }
    private static final class UnsupportedThread extends Thread {
        private UnsupportedThread(int required) {}
    }
    private static final class UnsupportedManager {
        private UnsupportedThread mThread;
    }

    private static void require(boolean value, String what) {
        if (!value) throw new AssertionError(what);
        ++checks;
    }

    private static void replaceAndRestore(Object manager, Object handler, String label)
            throws Exception {
        AdbResponseThreadBinding binding = AdbResponseThreadBinding.find(manager, handler);
        Object previous = binding.get();
        Object replacement = binding.createThread(manager);
        require(replacement instanceof Thread, label + ": thread created");
        require(!((Thread) replacement).isAlive(), label + ": constructor does not start thread");
        binding.set(replacement);
        require(binding.get() == replacement, label + ": replacement installed");
        binding.set(previous);
        require(binding.get() == previous, label + ": previous value restored");
    }

    public static void main(String[] args) throws Exception {
        LegacyManager legacy = new LegacyManager();
        replaceAndRestore(legacy, new LegacyHandler(), "Android 12 inner constructor");
        for (int release = 13; release <= 16; ++release) {
            replaceAndRestore(new StaticManager(), new LegacyHandler(),
                    "Android " + release + " static constructor and null initial thread");
        }
        ModernHandler modern = new ModernHandler();
        replaceAndRestore(new ModernManager(), modern, "Android 17 final handler field");
        replaceAndRestore(new ModernManager(), new VendorModernHandler(), "inherited handler field");
        require(AdbResponseThreadBinding.messageCode(legacy, new VendorHandler(), "MESSAGE_ADB_CONFIRM") == 5,
                "inherited handler confirmation constant");
        require(AdbResponseThreadBinding.messageCode(legacy, new ModernHandler(), "MESSAGE_ADB_CONFIRM") == 7,
                "handler confirmation constant takes precedence over manager");
        require(AdbResponseThreadBinding.messageCode(legacy, new Object(), "MESSAGE_ADB_CONFIRM") == 5,
                "manager constant supported when handler has none");
        try {
            AdbResponseThreadBinding.messageCode(new Object(), new Object(), "MESSAGE_ADB_CONFIRM");
            throw new AssertionError("missing constant must not silently use 5");
        } catch (NoSuchFieldException expected) {
            ++checks;
        }
        try {
            AdbResponseThreadBinding.find(new WrongField(), new ModernHandler());
            throw new AssertionError("wrong response field type accepted");
        } catch (IllegalStateException expected) {
            ++checks;
        }
        try {
            AdbResponseThreadBinding.find(new UnsupportedManager(), new LegacyHandler())
                    .createThread(legacy);
            throw new AssertionError("unsupported constructor guessed");
        } catch (NoSuchMethodException expected) {
            ++checks;
        }

        final String fixture = "framework.fixture.PlatformAuthFixture";
        try {
            Class.forName(fixture);
            throw new AssertionError("fixture unexpectedly visible from payload ClassLoader");
        } catch (ClassNotFoundException expected) {
            ++checks;
        }
        URL location = new File(args[0]).toURI().toURL();
        try (URLClassLoader frameworkLoader = new URLClassLoader(new URL[] {location},
                Thread.class.getClassLoader())) {
            Object manager = frameworkLoader.loadClass(fixture + "$Manager")
                    .getDeclaredConstructor().newInstance();
            Object handler = frameworkLoader.loadClass(fixture + "$Handler")
                    .getDeclaredConstructor().newInstance();
            // Android 12-16 shape, with an inner responder invisible from this test's loader.
            replaceAndRestore(manager, new Object(), "isolated framework manager and inner responder");
            // Android 17 shape, with a final handler field and a responder invisible here too.
            replaceAndRestore(new Object(), handler, "isolated framework handler and static responder");
            require(AdbResponseThreadBinding.messageCode(manager, handler, "MESSAGE_ADB_CONFIRM") == 93,
                    "confirmation constant read from real handler without guessing");
        }
        System.out.println("PASS: " + checks + " auth runtime binding checks (Android 12-17 layouts,"
                + " inherited fields, constructors, final slot, and isolated ClassLoader)");
    }
}
