package com.asmolabs.vectispire.common.domain.net;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

/**
 * Whether a host is, or resolves to, the link-local range — where the instance metadata lives.
 *
 * <p>For the one outbound path that does not go through {@link OutboundUrlGuard}: the clone,
 * which JGit performs itself. Private addresses stay allowed there, since a self-hosted forge on
 * the internal network is the ordinary case; the metadata endpoint is not, under any policy, as
 * the guard already holds for every HTTP destination. {@link IpAddresses} stays package-private —
 * this exposes the one question the clone needs, decided on the bytes like the rest.
 */
public final class LinkLocalHosts {

    private LinkLocalHosts() {}

    /** True when {@code host} is an address literal in the link-local range. */
    public static boolean isLinkLocalLiteral(String host) {
        return IpAddresses.parseLiteral(unbracketed(host)).map(IpAddresses::isLinkLocal).orElse(false);
    }

    /**
     * True when any address {@code host} resolves to is link-local.
     *
     * <p>A name that does not resolve is not refused here: the clone will fail on it with its own,
     * clearer message. This narrows the window rather than closing it — JGit resolves again when it
     * connects — but it stops the plain case, a name that points at the metadata endpoint.
     */
    public static boolean resolvesToLinkLocal(String host) {
        if (isLinkLocalLiteral(host)) {
            return true;
        }
        try {
            return Arrays.stream(InetAddress.getAllByName(unbracketed(host)))
                    .anyMatch(address -> IpAddresses.isLinkLocal(address.getAddress()));
        } catch (UnknownHostException unresolved) {
            return false;
        }
    }

    private static String unbracketed(String host) {
        return host.startsWith("[") && host.endsWith("]") ? host.substring(1, host.length() - 1) : host;
    }
}
