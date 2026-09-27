package com.asmolabs.vectispire.core.outbound;

import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard;
import java.net.URI;
import java.time.Duration;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * Every file Vectispire downloads from the outside, through the same door as its JSON calls: the
 * address resolved, checked against the policy, and connected to as checked ({@link
 * PinnedHttpSender}).
 *
 * <p><b>One redirect, to the same origin, and checked again.</b> FIRST publishes its daily EPSS file
 * at one stable address that answers {@code 302} to the day's dated file on the same host; a mirror
 * behind a load balancer may do the same. {@code OutboundJson} refuses every redirect because a
 * client that follows one has validated nothing — the destination checked is not the destination
 * reached. Here the target is resolved against the address asked, must keep its scheme, host and
 * port, and goes through the guard and the pin a second time as a request of its own. A redirect to
 * another host, a second redirect, or one the guard refuses is a failure that names the address, so
 * that the operator configures the final one.
 *
 * <p><b>The body is bytes, bounded.</b> A text decoding would corrupt an archive, and an unbounded
 * read would let whoever answers exhaust the heap; the ceiling is the caller's, counted as the bytes
 * arrive.
 */
@Service
public class OutboundDownload {

    private final PinnedHttpSender sender;
    private final OutboundUrlGuard guard;

    public OutboundDownload(PinnedHttpSender sender, OutboundUrlGuard guard) {
        this.sender = sender;
        this.guard = guard;
    }

    /**
     * The file at {@code url}, or empty when the server answers 404.
     *
     * @param timeout each read's, and half the whole exchange's ({@link PinnedHttpSender#DEADLINE_IN_TIMEOUTS})
     * @throws OutboundJson.OutboundFailureException on any other answer that is not a file, on a
     *     redirect this does not follow, and on a file past {@code maxBytes}
     */
    public Optional<byte[]> get(String url, OutboundPolicy policy, String label, long maxBytes, Duration timeout) {
        PinnedHttpSender.Download answer = fetch(url, policy, label, maxBytes, timeout);
        if (isRedirect(answer.status())) {
            String target = sameOrigin(url, answer.location().orElseThrow(() -> new OutboundJson.OutboundFailureException(
                    label + ": HTTP " + answer.status() + " without a Location.")), label);
            PinnedHttpSender.Download redirected = fetch(target, policy, label, maxBytes, timeout);
            if (isRedirect(redirected.status())) {
                throw new OutboundJson.OutboundFailureException(label + ": " + target
                        + " redirects again; only one redirect is followed — configure the final address.");
            }
            return body(redirected, label);
        }
        return body(answer, label);
    }

    private PinnedHttpSender.Download fetch(
            String url, OutboundPolicy policy, String label, long maxBytes, Duration timeout) {
        return sender.download(guard.validateAndResolve(url, policy, label), Map.of(), timeout, label, maxBytes);
    }

    private static Optional<byte[]> body(PinnedHttpSender.Download answer, String label) {
        if (answer.status() == 404) {
            return Optional.empty();
        }
        if (answer.status() / 100 != 2) {
            throw new OutboundJson.OutboundFailureException(label + ": HTTP " + answer.status() + ".");
        }
        return Optional.of(answer.body());
    }

    private static boolean isRedirect(int status) {
        return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
    }

    /** The redirect's target, resolved against the address asked, when it stays on that origin. */
    static String sameOrigin(String asked, String location, String label) {
        URI from;
        URI to;
        try {
            from = URI.create(asked);
            to = from.resolve(location.trim());
        } catch (IllegalArgumentException unreadable) {
            throw new OutboundJson.OutboundFailureException(
                    label + ": the redirect's target \"" + location + "\" is not an address.");
        }
        boolean same = to.getScheme() != null
                && to.getScheme().equalsIgnoreCase(from.getScheme())
                && to.getHost() != null
                && to.getHost().toLowerCase(Locale.ROOT).equals(from.getHost().toLowerCase(Locale.ROOT))
                && port(to) == port(from)
                && to.getRawUserInfo() == null;
        if (!same) {
            throw new OutboundJson.OutboundFailureException(label + ": " + asked + " redirects to another origin ("
                    + Objects.requireNonNullElse(to.getHost(), location)
                    + "); a redirect is followed only on the same host — configure the final address.");
        }
        return to.toString();
    }

    private static int port(URI uri) {
        if (uri.getPort() >= 0) {
            return uri.getPort();
        }
        return "http".equalsIgnoreCase(uri.getScheme()) ? 80 : 443;
    }
}
