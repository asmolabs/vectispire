package com.asmolabs.vectispire.core.access.web.security;

import com.asmolabs.vectispire.core.access.web.security.chain.LoginRateLimitFilter;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.stereotype.Component;

/**
 * Which peers may speak for somebody else.
 *
 * <p>Two `X-Forwarded-*` headers decide something here: {@code X-Forwarded-For} says who is
 * being rate-limited, and {@code X-Forwarded-Proto} says whether a deployment key may travel to
 * an agent. Both are written by whoever sends the request, so both are worth exactly what the
 * peer that sent them is worth — and that is one question with one answer, which is why it lives
 * in one class rather than being decided twice.
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
 * connection counts as one. A deployment that terminates TLS at a reverse proxy and forgets to
 * declare it will see its agents refused with 412 — loud, immediate, and fixed by one setting —
 * rather than see its deployment keys accepted on a header anybody can send.
 */
@Component
public class TrustedProxies {

    private static final Logger log = LoggerFactory.getLogger(TrustedProxies.class);

    /**
     * The request attribute holding the address {@link #clientAddress} resolved at the head of the
     * chain — see {@code ClientAddressFilter}.
     */
    public static final String CLIENT_ADDRESS = TrustedProxies.class.getName() + ".clientAddress";

    private final List<IpAddressMatcher> matchers;

    public TrustedProxies(@Value("${vectispire.security.trusted-proxies:}") String configured) {
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

    public boolean isTrusted(String address) {
        if (address == null || address.isBlank()) {
            return false;
        }
        for (IpAddressMatcher matcher : matchers) {
            try {
                if (matcher.matches(address)) {
                    return true;
                }
            } catch (IllegalArgumentException malformed) {
                // A header value that is not an address matches nothing, which is the answer.
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
     */
    public String clientAddress(HttpServletRequest request) {
        String peer = request.getRemoteAddr() == null ? "unknown" : request.getRemoteAddr();

        if (!isTrusted(peer)) {
            return peer;
        }

        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded == null || forwarded.isBlank()) {
            return peer;
        }

        String[] hops = forwarded.split(",");
        for (int i = hops.length - 1; i >= 0; i--) {
            String hop = hops[i].trim();
            if (!hop.isEmpty() && !isTrusted(hop)) {
                return hop;
            }
        }

        // Every hop claims to be a trusted proxy. Nothing here identifies a client, so the peer
        // is what is left — and it is a real address rather than a claimed one.
        return peer;
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
     * {@code X-Forwarded-Proto: https} over plain HTTP gets {@code false} here, and its agent gets
     * a 412 instead of a deployment key in the clear.
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
