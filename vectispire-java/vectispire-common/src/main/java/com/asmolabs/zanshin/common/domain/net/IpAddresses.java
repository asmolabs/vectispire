package com.asmolabs.zanshin.common.domain.net;

import java.net.InetAddress;
import java.util.Arrays;
import java.util.Optional;

/**
 * Address classification, decided on the bytes and never on the text.
 *
 * <p>The rule in that sentence is the whole reason this class exists. An earlier
 * implementation compared string prefixes, and a URL parser normalizes an IPv6 address before
 * anyone reads it: {@code ::ffff:127.0.0.1} comes back as {@code ::ffff:7f00:1}, which the
 * pattern matching never saw. Loopback, the private ranges and the metadata endpoint all
 * walked through a guard written that way.
 */
final class IpAddresses {

    private IpAddresses() {}

    /** The first twelve bytes of an IPv6 that wraps an IPv4. */
    private static final byte[] V4_MAPPED = hex("00000000000000000000ffff");

    /** {@code 64:ff9b::/96}, the NAT64 translation prefix: the last four bytes are the IPv4. */
    private static final byte[] NAT64 = hex("0064ff9b0000000000000000");

    /** Parses a literal, or empty when the text is a hostname rather than an address. */
    static Optional<byte[]> parseLiteral(String text) {
        try {
            return Optional.of(InetAddress.ofLiteral(text).getAddress());
        } catch (IllegalArgumentException notALiteral) {
            return Optional.empty();
        }
    }

    /**
     * The IPv4 an IPv6 carries, if there is one.
     *
     * <p>Three wrappings, and all three are needed: {@code ::ffff:a.b.c.d} (the common one),
     * {@code 64:ff9b::a.b.c.d} (NAT64, which genuinely reaches the IPv4 wherever the
     * translation exists) and {@code ::a.b.c.d} (obsolete, still accepted by the stacks). Each
     * is one more spelling of the same destination, and missing one is enough to reopen the
     * bypass.
     *
     * <p>The JDK already folds {@code ::ffff:} literals down to an {@link java.net.Inet4Address},
     * so that case usually never reaches here. It is still handled, because "usually" is not a
     * property a security control should rest on — an address arriving from a resolver rather
     * than from a literal has had no such treatment.
     */
    private static Optional<byte[]> embeddedV4(byte[] bytes) {
        byte[] prefix = Arrays.copyOf(bytes, 12);
        if (Arrays.equals(prefix, V4_MAPPED) || Arrays.equals(prefix, NAT64)) {
            return Optional.of(Arrays.copyOfRange(bytes, 12, 16));
        }
        // `::` and `::1` are not wrapped IPv4s: they are the unspecified address and loopback,
        // classified as such below.
        if (allZero(prefix) && unsignedInt(bytes, 12) > 1) {
            return Optional.of(Arrays.copyOfRange(bytes, 12, 16));
        }
        return Optional.empty();
    }

    /** The instance metadata range, in IPv4 as in IPv6. */
    static boolean isLinkLocal(byte[] bytes) {
        if (bytes.length == 16) {
            Optional<byte[]> embedded = embeddedV4(bytes);
            if (embedded.isPresent()) {
                return isLinkLocalV4(embedded.get());
            }
            // `fe80::/10` covers fe80 through febf.
            return octet(bytes, 0) == 0xfe && (octet(bytes, 1) & 0xc0) == 0x80;
        }
        return isLinkLocalV4(bytes);
    }

    private static boolean isLinkLocalV4(byte[] bytes) {
        return octet(bytes, 0) == 169 && octet(bytes, 1) == 254;
    }

    /**
     * Is the address routable on the public Internet?
     *
     * <p>Written out rather than delegated to {@link InetAddress}'s predicates, which between
     * them miss carrier-grade NAT, the benchmarking range and the documentation ranges. Every
     * range omitted from a list like this is an internal destination a public webhook can
     * reach.
     */
    static boolean isGlobal(byte[] bytes) {
        return bytes.length == 16 ? isGlobalV6(bytes) : isGlobalV4(bytes);
    }

    private static boolean isGlobalV4(byte[] bytes) {
        int a = octet(bytes, 0);
        int b = octet(bytes, 1);

        if (a == 0 || a == 10 || a == 127) return false;
        if (a == 100 && b >= 64 && b <= 127) return false; // CGNAT, 100.64.0.0/10
        if (a == 169 && b == 254) return false;
        if (a == 172 && b >= 16 && b <= 31) return false;
        if (a == 192 && b == 168) return false;
        if (a == 192 && b == 0) return false; // 192.0.0.0/24 and 192.0.2.0/24
        if (a == 198 && (b == 18 || b == 19)) return false; // benchmarking
        if (a == 198 && b == 51) return false;
        if (a == 203 && b == 0) return false;
        return a < 224; // multicast and reserved above
    }

    private static boolean isGlobalV6(byte[] bytes) {
        // The decision belongs to the IPv4 part as soon as there is one.
        Optional<byte[]> embedded = embeddedV4(bytes);
        if (embedded.isPresent()) {
            return isGlobalV4(embedded.get());
        }

        if (allZero(bytes)) return false; // `::`, unspecified
        if (allZero(Arrays.copyOf(bytes, 15)) && octet(bytes, 15) == 1) return false; // `::1`
        if ((octet(bytes, 0) & 0xfe) == 0xfc) return false; // fc00::/7, unique local
        if (octet(bytes, 0) == 0xfe && (octet(bytes, 1) & 0xc0) == 0x80) return false; // fe80::/10
        return octet(bytes, 0) != 0xff; // multicast
    }

    private static int octet(byte[] bytes, int index) {
        return bytes[index] & 0xff;
    }

    private static long unsignedInt(byte[] bytes, int offset) {
        long value = 0;
        for (int i = 0; i < 4; i++) {
            value = (value << 8) | octet(bytes, offset + i);
        }
        return value;
    }

    private static boolean allZero(byte[] bytes) {
        for (byte b : bytes) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    private static byte[] hex(String value) {
        return java.util.HexFormat.of().parseHex(value);
    }
}
