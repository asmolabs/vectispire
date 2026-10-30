package com.asmolabs.vectispire.common.domain.siem;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Where the SIEM configuration says events go, read according to its protocol.
 *
 * <p><b>One format per protocol, and the protocol decides the transport.</b> A webhook is a URL; a
 * syslog destination is {@code host:port} — {@code [2001:db8::1]:6514} for an IPv6 literal — and
 * nothing else. A scheme such as {@code syslog+tls://} was considered and refused: it would be a
 * second place to state the transport, and the day it disagreed with the protocol field one of
 * them would silently win. The port is required, because the defaults (514 for UDP and TCP, 6514
 * for TLS) differ by transport and a guessed port is a collector that receives nothing.
 *
 * <p>Parsing is syntax only. Whether the host may be reached is the outbound guard's question,
 * asked at send time against what the name resolves to then.
 */
public sealed interface SiemEndpoint {

    /** An HTTP(S) collector, reached through the pinned HTTP sender. */
    record Webhook(String url) implements SiemEndpoint {}

    /** A syslog collector. {@code host} is as written, brackets removed from an IPv6 literal. */
    record Syslog(SiemProtocol protocol, String host, int port) implements SiemEndpoint {}

    /** A DNS name: labels of letters, digits and hyphens. Anything else is not a host. */
    Pattern HOSTNAME = Pattern.compile(
            "(?i)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\\.?");

    /**
     * Digits and dots only: not a DNS name — no top-level label is numeric — so an IPv4 address or nothing.
     * {@link #HOSTNAME} let {@code 999.999.999.999} through, and a collector that could never be reached was saved.
     */
    Pattern NUMERIC_HOST = Pattern.compile("[0-9.]+");

    /**
     * Reads an endpoint for a protocol.
     *
     * @throws InvalidInputException worded for the person who typed it
     */
    static SiemEndpoint parse(SiemProtocol protocol, String endpoint) {
        String value = endpoint == null ? "" : endpoint.trim();
        if (value.isEmpty()) {
            throw new InvalidInputException("The endpoint is required.");
        }
        return switch (protocol) {
            case WEBHOOK -> webhook(value);
            case SYSLOG_UDP, SYSLOG_TCP, SYSLOG_TLS -> syslog(protocol, value);
        };
    }

    private static Webhook webhook(String value) {
        URI uri;
        try {
            uri = new URI(value);
        } catch (Exception unreadable) {
            throw new InvalidInputException("The webhook endpoint is not a readable URL.");
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("https") && !scheme.equals("http")) {
            throw new InvalidInputException(
                    "A webhook endpoint is an http(s) URL, for example https://collector.example.com/cef.");
        }
        if (uri.getHost() == null || uri.getHost().isBlank()) {
            throw new InvalidInputException("The webhook endpoint names no host.");
        }
        // `URI` reads any run of digits as a port: 99999 was saved, and every delivery failed for four hours.
        if (uri.getPort() == 0 || uri.getPort() > 65_535) {
            throw new InvalidInputException("The webhook endpoint's port must be a number between 1 and 65535.");
        }
        return new Webhook(value);
    }

    private static Syslog syslog(SiemProtocol protocol, String value) {
        String example = protocol == SiemProtocol.SYSLOG_TLS ? "collector.example.com:6514" : "collector.example.com:514";
        if (value.contains("://") || value.contains("/")) {
            throw new InvalidInputException(
                    "A syslog endpoint is host:port, for example " + example + " — no scheme and no path: the "
                            + "protocol field already says how events travel.");
        }
        String host;
        String port;
        if (value.startsWith("[")) {
            int close = value.indexOf(']');
            if (close < 0 || close + 1 >= value.length() || value.charAt(close + 1) != ':') {
                throw new InvalidInputException("An IPv6 syslog endpoint is written [address]:port.");
            }
            host = value.substring(1, close);
            port = value.substring(close + 2);
            if (!isIpv6Literal(host)) {
                throw new InvalidInputException("\"" + host + "\" is not an IPv6 address.");
            }
        } else {
            int colon = value.lastIndexOf(':');
            if (colon < 0) {
                throw new InvalidInputException(
                        "A syslog endpoint needs its port, for example " + example + ".");
            }
            if (value.indexOf(':') != colon) {
                throw new InvalidInputException("An IPv6 syslog endpoint is written [address]:port.");
            }
            host = value.substring(0, colon);
            port = value.substring(colon + 1);
            if (host.isEmpty() || !HOSTNAME.matcher(host).matches()
                    || NUMERIC_HOST.matcher(host).matches() && !isIpv4Literal(host)) {
                throw new InvalidInputException("\"" + host + "\" is not a host name or an IPv4 address.");
            }
        }
        return new Syslog(protocol, host, portOf(port));
    }

    /**
     * What the resolver reads as an address: the JDK's literal, its short forms included ({@code 10.1} is
     * 10.0.0.1), with the one trailing dot a fully qualified name may carry. Exactly what was reachable before
     * the numeric check existed, so no stored endpoint that worked is refused at its next delivery.
     */
    private static boolean isIpv4Literal(String text) {
        String address = text.endsWith(".") ? text.substring(0, text.length() - 1) : text;
        try {
            Inet4Address.ofLiteral(address);
            return true;
        } catch (IllegalArgumentException notALiteral) {
            return false;
        }
    }

    private static boolean isIpv6Literal(String text) {
        try {
            return InetAddress.ofLiteral(text) instanceof Inet6Address;
        } catch (IllegalArgumentException notALiteral) {
            return false;
        }
    }

    /**
     * A port of one to five ASCII digits. Leading zeros are kept: {@code 00514} is 514 and nothing else, and a
     * stored endpoint is read again at each delivery — refusing it now would stop an export that works.
     */
    private static int portOf(String text) {
        if (text.isEmpty() || text.length() > 5 || !text.chars().allMatch(c -> c >= '0' && c <= '9')) {
            throw new InvalidInputException("The port must be a number between 1 and 65535.");
        }
        int port = Integer.parseInt(text);
        if (port < 1 || port > 65_535) {
            throw new InvalidInputException("The port must be a number between 1 and 65535.");
        }
        return port;
    }
}
