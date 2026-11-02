package com.asmolabs.vectispire.common.domain.auth;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.Optional;

/**
 * The address a forwarded hop names, as the proxies in front of Vectispire actually write it.
 *
 * <p><b>A hop is not always a bare literal.</b> Some balancers append the client's source port —
 * {@code 203.0.113.7:51234}, {@code [2001:db8::7]:51234} — and a value carrying one was neither
 * matched against the trusted proxies nor bucketed by {@link ClientBuckets}: it was kept as a string,
 * so every new source port of one client was a new client to the throttles. The port says which
 * connection, not who; it is dropped here, once, for every reader.
 *
 * <p><b>A bare IPv6 literal has colons and no port</b>, so a port is only read off a bracketed literal
 * or a value with exactly one colon (an IPv4 address and its port). Anything else is taken whole and
 * must parse as an address, or it is no address at all.
 */
public final class AddressLiterals {

    private AddressLiterals() {}

    /**
     * The literal a hop names — without brackets or a port, otherwise as written — or empty when the
     * hop is not an IP address literal ({@code unknown}, an obfuscated identifier, a host name, junk).
     */
    public static Optional<String> of(String hop) {
        if (hop == null) {
            return Optional.empty();
        }
        String value = hop.trim();
        if (value.startsWith("[")) {
            int close = value.indexOf(']');
            if (close < 0) {
                return Optional.empty();
            }
            String rest = value.substring(close + 1);
            if (!rest.isEmpty() && !isPort(rest)) {
                return Optional.empty();
            }
            String inner = value.substring(1, close);
            // Brackets hold an IPv6 literal and nothing else (RFC 3986, RFC 7239).
            return inner.contains(":") ? literal(inner).map(parsed -> inner) : Optional.empty();
        }
        int colon = value.indexOf(':');
        if (colon >= 0 && colon == value.lastIndexOf(':')) {
            String host = value.substring(0, colon);
            return isPort(value.substring(colon)) && literal(host).filter(Inet4Address.class::isInstance).isPresent()
                    ? Optional.of(host)
                    : Optional.empty();
        }
        return literal(value).map(parsed -> value);
    }

    /** {@code :} and one to five digits. */
    private static boolean isPort(String suffix) {
        if (suffix.length() < 2 || suffix.length() > 6 || suffix.charAt(0) != ':') {
            return false;
        }
        for (int i = 1; i < suffix.length(); i++) {
            char c = suffix.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return true;
    }

    private static Optional<InetAddress> literal(String text) {
        if (text.isEmpty()) {
            return Optional.empty();
        }
        try {
            // A literal only: `ofLiteral` never resolves a name, so a hop cannot make the server ask DNS.
            return Optional.of(InetAddress.ofLiteral(text));
        } catch (IllegalArgumentException notALiteral) {
            return Optional.empty();
        }
    }
}
