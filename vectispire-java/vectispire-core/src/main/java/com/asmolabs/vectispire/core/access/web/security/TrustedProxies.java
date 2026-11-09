package com.asmolabs.vectispire.core.access.web.security;

import com.asmolabs.vectispire.common.domain.auth.AddressLiterals;
import com.asmolabs.vectispire.core.access.web.security.chain.LoginRateLimitFilter;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.util.matcher.IpAddressMatcher;

/**
 * Which peers may speak for somebody else.
 *
 * <p>Two `X-Forwarded-*` headers decide something here: {@code X-Forwarded-For} says who is
 * being rate-limited and audited, and {@code X-Forwarded-Proto} whether a cookie is marked secure.
 * It also decided, until decision 0031, whether a deployment key could travel to an agent in the
 * clear; a delegated credential now leaves sealed or not at all, whatever the link. Both headers
 * are written by whoever sends the request, so both are worth exactly what the peer that sent them
 * is worth — and that is one question with one answer, which is why it lives in one class rather
 * than being decided twice.
 *
 * <p><b>It was decided twice, and the two halves disagreed.</b> {@link LoginRateLimitFilter}
 * already refused to read {@code X-Forwarded-For} from an untrusted peer, and documented why at
 * length. {@code AgentsController.isSecureTransport} read {@code X-Forwarded-Proto} from any peer
 * at all, called it "trivially forgeable" in its own javadoc, and let it decide whether an SSH
 * deployment key crossed the network in the clear. The stricter of the two rules is the one that
 * survives, and it now applies to both headers from the same configured list.
 *
 * <p><b>Empty means "no proxy in front", and that is the safe reading.</b> With no trusted proxy
 * configured, {@code X-Forwarded-Proto} is ignored entirely and only a genuinely encrypted
 * connection counts as one.
 */
public class TrustedProxies {

    private static final Logger log = LoggerFactory.getLogger(TrustedProxies.class);

    /**
     * The request attribute holding the address {@link #clientAddress} resolved at the head of the
     * chain — see {@code ClientAddressFilter}.
     */
    public static final String CLIENT_ADDRESS = TrustedProxies.class.getName() + ".clientAddress";

    private static final String FORWARDED_FOR = "X-Forwarded-For";

    private final List<IpAddressMatcher> matchers;

    public TrustedProxies(String configured) {
        this.matchers = parse(configured);
        if (this.matchers.isEmpty()) {
            log.info("No trusted proxies configured — X-Forwarded-For and X-Forwarded-Proto are ignored. "
                    + "Set vectispire.security.trusted-proxies when running behind a reverse proxy or a "
                    + "load balancer.");
        }
    }

    /** True when nothing is trusted, which is the shipped default. */
    public boolean none() {
        return matchers.isEmpty();
    }

    /**
     * Whether an address — a bare literal, or one with the port a balancer appended — is a proxy we
     * run. A value that is not an address literal matches nothing, which is the answer.
     */
    public boolean isTrusted(String address) {
        return AddressLiterals.of(address).map(this::matches).orElse(false);
    }

    private boolean matches(String literal) {
        for (IpAddressMatcher matcher : matchers) {
            try {
                if (matcher.matches(literal)) {
                    return true;
                }
            } catch (IllegalArgumentException malformed) {
                return false;
            }
        }
        return false;
    }

    /**
     * The peer's address, or what a proxy we trust says is behind it.
     *
     * <p>The rightmost entry a client cannot control is the correct one to take, and with a
     * single trusted hop that is the first: everything to its left was written by whoever called
     * the proxy. With several hops the leftmost untrusted entry is the honest answer, which is
     * what the walk below finds.
     *
     * <p><b>Every line of the header, in order.</b> {@code getHeader} answers the first line only,
     * and a proxy may append its hop as a line of its own rather than to the existing one (HAProxy's
     * {@code option forwardfor} does): the first line is then the one the client wrote, and its
     * rightmost entry — read as the hop behind the trusted chain — was the client's choice. RFC 9110
     * §5.3 makes several lines of a list header one list, joined in order, and so are they here.
     *
     * <p><b>A hop is read through {@link AddressLiterals}</b>: its port dropped, so one client is one
     * address whatever source port the balancer reports.
     *
     * <p><b>A hop that is no address at all is not a client.</b> The first untrusted hop was written
     * by the trusted proxy to its right; when that proxy wrote {@code unknown}, an obfuscated
     * identifier or junk, nothing identifies the client. Taking the text as the client would give
     * whatever produced it a bucket of its own per value; refusing it would refuse the request for
     * the proxy's habit. The answer is the proxy that wrote it — a real address we trust, one bucket
     * for everything it cannot name, which errs towards throttling too much rather than too little.
     */
    public String clientAddress(HttpServletRequest request) {
        // The container's peer is a bare literal, unless something before this filter rewrote it
        // from a header (Tomcat's RemoteIpValve, which Spring Boot installs on its own on a detected
        // cloud platform): then it may carry a port too.
        String remote = request.getRemoteAddr() == null ? "unknown" : request.getRemoteAddr();
        String peer = AddressLiterals.of(remote).orElse(remote);

        if (!isTrusted(peer)) {
            return peer;
        }

        List<String> hops = forwardedHops(request);
        String nearestTrusted = peer;
        for (int i = hops.size() - 1; i >= 0; i--) {
            Optional<String> hop = AddressLiterals.of(hops.get(i));
            if (hop.isEmpty()) {
                return nearestTrusted;
            }
            if (!matches(hop.get())) {
                return hop.get();
            }
            nearestTrusted = hop.get();
        }

        // Every hop claims to be a trusted proxy. Nothing here identifies a client, so the peer
        // is what is left — and it is a real address rather than a claimed one.
        return peer;
    }

    /** Every {@code X-Forwarded-For} line, in the order received, split into its non-empty entries. */
    private static List<String> forwardedHops(HttpServletRequest request) {
        Enumeration<String> lines = request.getHeaders(FORWARDED_FOR);
        if (lines == null) {
            return List.of();
        }
        List<String> hops = new ArrayList<>();
        for (String line : Collections.list(lines)) {
            if (line == null) {
                continue;
            }
            for (String entry : line.split(",")) {
                String hop = entry.trim();
                if (!hop.isEmpty()) {
                    hops.add(hop);
                }
            }
        }
        return hops;
    }

    /**
     * The client's address as the chain resolved it, for a caller that holds no instance — a static
     * helper, the access-denied handler, a route building an actor.
     *
     * <p>A request that never crossed the chain has no resolution, and then the peer is all that is
     * known — which is what {@link #clientAddress} answers with no proxy trusted.
     */
    public static String resolvedClientAddress(HttpServletRequest request) {
        return request.getAttribute(CLIENT_ADDRESS) instanceof String resolved
                ? resolved
                : request.getRemoteAddr() == null ? "unknown" : request.getRemoteAddr();
    }

    /**
     * Did this request arrive over an encrypted link?
     *
     * <p><b>The connection first, the header only from a peer we run.</b> {@code request.isSecure()}
     * is a fact about the socket and needs no trust. {@code X-Forwarded-Proto} is a claim, and a
     * claim is worth the peer making it — which is why an untrusted peer sending
     * {@code X-Forwarded-Proto: https} over plain HTTP gets {@code false} here.
     *
     * <p>Only the first hop is read. The header is a comma-separated list written left to right
     * as the request travels, so the leftmost element describes the client's own leg — the one
     * that decides whether the secret is exposed on the public side.
     */
    public boolean isSecureTransport(HttpServletRequest request) {
        if (request.isSecure()) {
            return true;
        }
        if (!isTrusted(request.getRemoteAddr())) {
            return false;
        }
        String proto = request.getHeader("X-Forwarded-Proto");
        return proto != null && "https".equalsIgnoreCase(proto.split(",")[0].trim());
    }

    private static List<IpAddressMatcher> parse(String configured) {
        if (configured == null || configured.isBlank()) {
            return List.of();
        }
        return Arrays.stream(configured.split(","))
                .map(String::trim)
                .filter(entry -> !entry.isEmpty())
                .map(IpAddressMatcher::new)
                .toList();
    }
}
