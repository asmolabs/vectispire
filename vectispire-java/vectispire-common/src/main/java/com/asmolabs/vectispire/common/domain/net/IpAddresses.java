package com.asmolabs.vectispire.common.domain.net;

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

    /** {@code 64:ff9b:1::/48}, NAT64 for local use (RFC 8215): the last four bytes again. */
    private static final byte[] NAT64_LOCAL = hex("0064ff9b0001");

    /** {@code 2002::/16}, 6to4: bytes two to five are the IPv4 the tunnel ends at. */
    private static final byte[] SIX_TO_FOUR = hex("2002");

    /** {@code 2001:0::/32}, Teredo: the client's IPv4 is the last four bytes, each inverted. */
    private static final byte[] TEREDO = hex("20010000");

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
        if (Arrays.equals(prefix, V4_MAPPED) || Arrays.equals(prefix, NAT64) || startsWith(bytes, NAT64_LOCAL)) {
            return Optional.of(Arrays.copyOfRange(bytes, 12, 16));
        }
        // **Three more spellings, found by review rather than by an incident.** 6to4 and Teredo
        // carry an IPv4 that a relay will reach, and local-use NAT64 translates like its public
        // sibling: `2002:a9fe:a9fe::` is the metadata endpoint as much as `::ffff:169.254.169.254`
        // is, it only needs a relay on the path to get there.
        if (startsWith(bytes, SIX_TO_FOUR)) {
            return Optional.of(Arrays.copyOfRange(bytes, 2, 6));
        }
        if (startsWith(bytes, TEREDO)) {
            byte[] client = Arrays.copyOfRange(bytes, 12, 16);
            for (int i = 0; i < client.length; i++) {
                client[i] = (byte) ~client[i];
            }
            return Optional.of(client);
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
     * The metadata services that do not live in the link-local range, in IPv4 as in IPv6.
     *
     * <p>{@code 169.254.169.254} is the common address, not the only one: Alibaba Cloud answers on
     * {@code 100.100.100.200} (inside carrier-grade NAT), AWS on {@code fd00:ec2::254} for IPv6-only
     * instances (inside unique local), Oracle Cloud's legacy endpoint on {@code 192.0.0.192}, and Azure's
     * WireServer, which hands an instance its extension settings, on {@code 168.63.129.16} — a public
     * address. Each sits in a range the internal policies accept, so being private is no refusal there;
     * these are refused by address under every policy, like link-local.
     */
    static boolean isMetadata(byte[] bytes) {
        if (bytes.length == 16) {
            Optional<byte[]> embedded = embeddedV4(bytes);
            if (embedded.isPresent()) {
                return isMetadataV4(embedded.get());
            }
            return Arrays.equals(bytes, AWS_METADATA_V6);
        }
        return isMetadataV4(bytes);
    }

    private static final byte[] AWS_METADATA_V6 = hex("fd000ec2000000000000000000000254");

    private static boolean isMetadataV4(byte[] bytes) {
        int value = (int) unsignedInt(bytes, 0);
        return value == v4(100, 100, 100, 200) || value == v4(192, 0, 0, 192) || value == v4(168, 63, 129, 16);
    }

    /**
     * {@code 0.0.0.0/8} and {@code ::}: no host, but a connection to them reaches this machine on Linux, as
     * loopback would. Under a policy that accepts loopback that is merely another spelling; under every
     * policy it walked past a reservation written {@code localhost}, which resolves to {@code 127.0.0.1}
     * and never to {@code 0.0.0.0}. Nothing legitimate is addressed that way.
     */
    static boolean isUnspecified(byte[] bytes) {
        if (bytes.length == 16) {
            Optional<byte[]> embedded = embeddedV4(bytes);
            return embedded.map(IpAddresses::isUnspecified).orElseGet(() -> allZero(bytes));
        }
        return octet(bytes, 0) == 0;
    }

    /** {@code 127.0.0.0/8} and {@code ::1}, however wrapped: one machine, whichever of its addresses is written. */
    static boolean isLoopback(byte[] bytes) {
        if (bytes.length == 16) {
            Optional<byte[]> embedded = embeddedV4(bytes);
            if (embedded.isPresent()) {
                return isLoopback(embedded.get());
            }
            return allZero(Arrays.copyOf(bytes, 15)) && octet(bytes, 15) == 1;
        }
        return octet(bytes, 0) == 127;
    }

    private static int v4(int a, int b, int c, int d) {
        return (a << 24) | (b << 16) | (c << 8) | d;
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
        if (octet(bytes, 0) == 0xfe && (octet(bytes, 1) & 0xc0) == 0xc0) return false; // fec0::/10, site-local
        if (startsWith(bytes, hex("20010db8"))) return false; // 2001:db8::/32, documentation
        return octet(bytes, 0) != 0xff; // multicast
    }

    private static boolean startsWith(byte[] bytes, byte[] prefix) {
        return bytes.length >= prefix.length && Arrays.equals(Arrays.copyOf(bytes, prefix.length), prefix);
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
