package com.asmolabs.vectispire.common.domain.net;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * Validation of the URLs Vectispire will send a request to.
 *
 * <p>Three settings become server-side requests: the notification webhook, the Ollama server,
 * and the local scan API. Each is a string set by an administrator and then called by the
 * server — a server-side request forgery primitive, whose classic target is the metadata
 * endpoint {@code 169.254.169.254}, which hands out the instance's credentials to whoever
 * asks.
 *
 * <p>"Only an administrator can set it" is a mitigation, not an answer: a Vectispire
 * administrator is not necessarily someone cleared to read the host's IAM credentials, and
 * that is exactly the pivot an attacker who has phished an account is looking for.
 *
 * <p><b>Blocking private addresses outright would break two of the three settings by
 * construction</b> — Ollama and the scan side-car are <em>meant</em> to sit on loopback or the
 * internal network. The rule is therefore per use, and named by {@link OutboundPolicy}.
 *
 * <h2>Two limits, recorded rather than hidden</h2>
 *
 * <p><b>DNS rebinding — closed, but only for callers that take the addresses.</b> Names are
 * resolved here so that one pointing at a blocked address is refused too. Validating and then
 * letting the client resolve the name a second time leaves a window: between the two lookups
 * the answer can change, and the address that was checked is not the address that is reached.
 * {@link #validateAndResolve} therefore returns <em>what was checked</em>, so the caller can
 * connect to exactly that and resolve nothing again. {@link #validate}, which returns the URL
 * alone, leaves the window open and is kept for the callers that only need a verdict — a
 * settings screen saving a value, not sending to it.
 *
 * <p><b>Redirects.</b> This validates the first destination only. A validated host answering
 * {@code 302 Location: http://169.254.169.254/} defeats the whole guard, so every caller must
 * refuse redirects, and that is not something this class can enforce for them. What does
 * enforce it is that there is only one caller — the sender in {@code vectispire-core} that turns a
 * {@link Destination} into a request — and an architecture rule that keeps it that way.
 */
public final class OutboundUrlGuard {

    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");

    /** Injectable so DNS resolution is not a dependency of the tests. */
    @FunctionalInterface
    public interface HostResolver {
        /**
         * Every address a name resolves to.
         *
         * <p><b>Every one, not the first</b>: a name can return a public address and a private
         * one, and checking a single answer lets the other through.
         */
        List<byte[]> resolve(String hostname);
    }

    private final HostResolver resolver;

    public OutboundUrlGuard() {
        this(OutboundUrlGuard::resolveHostname);
    }

    public OutboundUrlGuard(HostResolver resolver) {
        this.resolver = resolver;
    }

    /**
     * A destination that has been checked, and the addresses it was checked at.
     *
     * @param url the cleaned URL, unchanged — the host name still travels to the server, so
     *     virtual hosting, SNI and certificate verification all keep working
     * @param host the host as written, which is what a TLS certificate is verified against
     * @param addresses every address the name resolved to at validation time, all of them
     *     accepted by the policy. <b>Connect to these and resolve nothing again</b>: that is
     *     what makes the check binding. Empty only when the name did not resolve at all and the
     *     policy tolerated it
     */
    public record Destination(String url, String host, List<InetAddress> addresses) {}

    /**
     * Validates, and hands back the addresses so the connection can be pinned to them.
     *
     * <p>The addresses come from the same lookup the policy was applied to — not a second one.
     * A caller that re-resolved would be checking one answer and using another, which is the
     * whole of DNS rebinding.
     */
    public Destination validateAndResolve(String url, OutboundPolicy policy, String label) {
        Checked checked = check(url, policy, label);
        List<InetAddress> addresses = new ArrayList<>();
        for (byte[] address : checked.addresses()) {
            try {
                addresses.add(InetAddress.getByAddress(checked.host(), address));
            } catch (UnknownHostException impossible) {
                // `getByAddress` only rejects a wrong length, and these came from a parser.
                throw new UnsafeUrlException(label + ": unusable address for " + checked.host() + ".");
            }
        }
        return new Destination(checked.url(), checked.host(), List.copyOf(addresses));
    }

    /** Returns the cleaned URL, or throws {@link UnsafeUrlException}. */
    public String validate(String url, OutboundPolicy policy, String label) {
        return check(url, policy, label).url();
    }

    /** What one validation established, before it is turned into either shape above. */
    private record Checked(String url, String host, List<byte[]> addresses) {}

    private Checked check(String url, OutboundPolicy policy, String label) {
        String candidate = url == null ? "" : url.trim();
        if (candidate.isEmpty()) {
            throw new UnsafeUrlException(label + ": empty value.");
        }

        URI parsed;
        try {
            parsed = new URI(candidate);
        } catch (Exception unreadable) {
            throw new UnsafeUrlException(label + ": unreadable URL.");
        }

        String scheme = parsed.getScheme() == null ? "" : parsed.getScheme().toLowerCase(Locale.ROOT);
        if (!ALLOWED_SCHEMES.contains(scheme)) {
            throw new UnsafeUrlException(label + ": scheme \"" + (scheme.isEmpty() ? "(none)" : scheme)
                    + "\" is not allowed (expected: https, http).");
        }

        String hostname = hostOf(parsed);
        if (hostname.isEmpty()) {
            throw new UnsafeUrlException(label + ": missing host.");
        }

        List<byte[]> addresses = resolver.resolve(hostname);

        if (policy == OutboundPolicy.INTERNAL_REQUIRED && addresses.isEmpty()) {
            // Failing open is defensible for "is this private?" — the request would fail
            // anyway. It is not defensible for "this *must* be private": an unresolvable name
            // proves nothing, and this check is what separates the scanned source code from an
            // external host.
            throw new UnsafeUrlException(label + ": the host could not be resolved, so it cannot be verified as "
                    + "internal — and this endpoint receives source code.");
        }

        for (byte[] address : addresses) {
            check(address, policy, label);
        }
        return new Checked(candidate, hostname, addresses);
    }

    private static void check(byte[] address, OutboundPolicy policy, String label) {
        String text = textOf(address);

        if (IpAddresses.isLinkLocal(address)) {
            throw new UnsafeUrlException(label + ": the host resolves to a link-local address (" + text
                    + "), used by instance metadata services.");
        }

        boolean global = IpAddresses.isGlobal(address);
        if (policy == OutboundPolicy.PUBLIC_ONLY && !global) {
            throw new UnsafeUrlException(label + ": the host resolves to a private or local address (" + text
                    + "). A public destination is expected here.");
        }
        if (policy == OutboundPolicy.INTERNAL_REQUIRED && global) {
            throw new UnsafeUrlException(label + ": the host resolves to a public address (" + text
                    + "). A local or internal destination is expected here — this endpoint receives source code.");
        }
    }

    /** The reason, or empty when the URL is acceptable. Non-throwing variant. */
    public Optional<String> unsafeReason(String url, OutboundPolicy policy, String label) {
        try {
            validate(url, policy, label);
            return Optional.empty();
        } catch (UnsafeUrlException refused) {
            return Optional.of(refused.getMessage());
        }
    }

    private static String hostOf(URI parsed) {
        String host = parsed.getHost();
        if (host == null) {
            // `URI` returns null for a host it considers malformed, which includes some literal
            // IPv6 forms. Falling back to the authority keeps those parseable rather than
            // letting them through as "no host".
            String authority = parsed.getAuthority();
            host = authority == null ? "" : authority;
        }
        // Brackets around a literal IPv6 are syntax, not part of the address.
        return host.replaceAll("^\\[|]$", "");
    }

    private static List<byte[]> resolveHostname(String hostname) {
        Optional<byte[]> literal = IpAddresses.parseLiteral(hostname);
        if (literal.isPresent()) {
            return List.of(literal.get());
        }

        try {
            List<byte[]> addresses = new ArrayList<>();
            for (InetAddress address : InetAddress.getAllByName(hostname)) {
                addresses.add(address.getAddress());
            }
            return addresses;
        } catch (UnknownHostException unresolvable) {
            // Refusing on a resolution failure would make the settings screen unusable at the
            // slightest DNS hiccup, and the request itself would fail anyway. The one policy
            // for which that is not good enough is handled by the caller.
            return List.of();
        }
    }

    private static String textOf(byte[] address) {
        try {
            return InetAddress.getByAddress(address).getHostAddress();
        } catch (UnknownHostException impossible) {
            // `getByAddress` only rejects a wrong length, and these come from a parser.
            return java.util.HexFormat.of().formatHex(address);
        }
    }
}
