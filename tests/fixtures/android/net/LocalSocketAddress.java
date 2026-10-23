// SPDX-License-Identifier: AGPL-3.0-or-later
package android.net;
public final class LocalSocketAddress {
    public enum Namespace { ABSTRACT }
    public final String name;
    public final Namespace namespace;
    public LocalSocketAddress(String name, Namespace namespace) { this.name = name; this.namespace = namespace; }
}
