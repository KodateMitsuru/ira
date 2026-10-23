// SPDX-License-Identifier: AGPL-3.0-or-later
package ira.fw;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

/** Resolves the response slot using framework objects, preserving their declaring ClassLoader. */
final class AdbResponseThreadBinding {
    private final Object owner;
    private final Field field;

    private AdbResponseThreadBinding(Object owner, Field field) throws Exception {
        this.owner = owner;
        this.field = field;
        if (Modifier.isStatic(field.getModifiers()) || !Thread.class.isAssignableFrom(field.getType())) {
            throw new IllegalStateException("Unsupported response-thread field: " + field);
        }
        field.setAccessible(true);
    }

    static Field findField(Class<?> type, String name) throws NoSuchFieldException {
        for (Class<?> c = type; c != null; c = c.getSuperclass()) {
            try {
                return c.getDeclaredField(name);
            } catch (NoSuchFieldException ignored) {
                // Vendor subclasses may inherit the framework field.
            }
        }
        throw new NoSuchFieldException(type.getName() + "." + name);
    }

    static AdbResponseThreadBinding find(Object manager, Object handler) throws Exception {
        try {
            return new AdbResponseThreadBinding(manager, findField(manager.getClass(), "mThread"));
        } catch (NoSuchFieldException managerFieldMissing) {
            return new AdbResponseThreadBinding(handler, findField(handler.getClass(), "mThread"));
        }
    }

    static int messageCode(Object manager, Object handler, String name) throws Exception {
        for (Object target : new Object[] {handler, manager}) {
            Field message;
            try {
                message = findField(target.getClass(), name);
            } catch (NoSuchFieldException ignored) {
                continue;
            }
            if (message.getType() != int.class || !Modifier.isStatic(message.getModifiers())) {
                throw new IllegalStateException("Unsupported confirmation-message field: " + message);
            }
            message.setAccessible(true);
            return message.getInt(null);
        }
        throw new NoSuchFieldException(name + " on framework handler or manager");
    }

    Object createThread(Object manager) throws Exception {
        // Android 12 uses an enclosing manager argument; later releases have a static no-arg class.
        // The Field already carries the correct type and ClassLoader: never re-load it by name.
        Constructor<?> chosen = null;
        for (Constructor<?> candidate : field.getType().getDeclaredConstructors()) {
            Class<?>[] params = candidate.getParameterTypes();
            if (params.length == 0) {
                chosen = candidate;
                break;
            }
            if (params.length == 1 && params[0].isInstance(manager)) {
                chosen = candidate;
            }
        }
        if (chosen == null) {
            throw new NoSuchMethodException("Unsupported response-thread constructor: "
                    + field.getType().getName());
        }
        chosen.setAccessible(true);
        return chosen.getParameterCount() == 0 ? chosen.newInstance() : chosen.newInstance(manager);
    }

    Object get() throws IllegalAccessException {
        return field.get(owner);
    }

    void set(Object value) throws IllegalAccessException {
        field.set(owner, value);
    }
}
