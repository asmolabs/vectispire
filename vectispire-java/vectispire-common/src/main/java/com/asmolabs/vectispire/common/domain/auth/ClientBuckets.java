package com.asmolabs.vectispire.common.domain.auth;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.HexFormat;

/**
 * Which budget an address spends: the address itself in IPv4, its /64 in IPv6.
 *
 * <p><b>One IPv6 client is a /64, not an address.</b> A host is handed a whole /64 and picks addresses
 * in it at will — privacy extensions rotate them on their own — so a throttle keyed on the full address
 * gave every request a fresh bucket and a fresh failure counter, and only the per-account ceiling
 * remained (the audit of 10 October 2026). The audit log keeps the full address; only the counters
 * share.
 */
public final class ClientBuckets {

    private ClientBuckets() {}

    /** The bucket of an address; anything that is not an address literal is its own bucket. */
    public static String of(String address) {
        if (address == null || address.isBlank()) {
            return String.valueOf(address);
        }
        InetAddress parsed;
        try {
            parsed = InetAddress.ofLiteral(address.trim().replaceAll("^\\[|]$", ""));
        } catch (IllegalArgumentException notALiteral) {
            return address;
        }
        // `::ffff:a.b.c.d` comes back as an Inet4Address: an IPv4 client, counted as one.
        if (!(parsed instanceof Inet6Address)) {
            return parsed.getHostAddress();
        }
        byte[] prefix = java.util.Arrays.copyOf(parsed.getAddress(), 8);
        return HexFormat.of().formatHex(prefix) + "::/64";
    }
}
