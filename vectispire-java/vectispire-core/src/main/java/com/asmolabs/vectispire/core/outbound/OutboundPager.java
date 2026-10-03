package com.asmolabs.vectispire.core.outbound;

import com.asmolabs.vectispire.common.domain.net.LinkHeader;
import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.net.PinnedCa;
import com.asmolabs.vectispire.common.domain.net.RateLimit;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

/**
 * A listing read page by page through {@link OutboundJson}'s door — the guard, the pin, no redirect, the
 * pinned CA — with what a listing adds (decision 0037 §3, lot D2). Opened for one origin, used by one thread.
 *
 * <p><b>The next page is followed on the pager's own origin, or not at all.</b> A forge names its next page
 * in a header or a body, and that URL is the forge's to write: a {@code Link} to another host — a proxy's
 * rewrite, a compromised server, a mirror — would carry the token there. The guard would check the new
 * destination's address, but by then the credential would already be on its way. So every URL is compared
 * with the origin the pager was opened for — scheme, host and port — <em>before</em> anything is sent, and
 * a URL elsewhere throws {@link CrossOriginPageException} with nothing sent. The credential headers are
 * attached here, after that comparison, and never handed to a request of the caller's own making.
 *
 * <p><b>Rate limits are waited out, within a bound, never raced.</b> A 429, or a 403 carrying the limit's
 * headers ({@link RateLimit#limited}), is a wait: up to {@link Settings#maxWait} it is slept inside the run and
 * the request sent again; longer, it throws {@link RateLimitedException} naming when the limit lifts, and the
 * caller ends its run there rather than holding a thread for an hour. A limit naming no wait is waited for
 * {@code maxWait}: once more is what the forge would accept soonest without saying so. Any wait that would
 * cross the deadline throws {@link DeadlineReachedException} instead.
 *
 * <p><b>A failing server is retried three times, with back-off</b> — one, two, four seconds — on a 5xx and on
 * an exchange that produced no answer (a timeout, a reset). The fourth failure is the page's: it throws.
 * Every other status is handed back as it came, for the caller to read: a 401 or a 404 means something to a
 * forge adapter that it does not mean here.
 *
 * <p><b>A deadline for the whole listing</b>, checked before each request and before each wait: the per-request
 * timeout bounds one exchange, not the hundred a listing makes.
 */
public final class OutboundPager {

    /** How many times a page that failed is sent again before its failure is the caller's. */
    static final int RETRIES = 3;

    /** The first back-off; each next one doubles it. */
    static final Duration FIRST_BACK_OFF = Duration.ofSeconds(1);

    /**
     * What a pager is opened with.
     *
     * @param origin any URL of the origin the pager may reach — the API's root; only its scheme, host and port
     *     are read
     * @param credential the headers that authenticate to that origin, attached to its requests and to no other
     * @param trust the CA the server must chain to, in place of the runtime's store; empty for that store
     * @param deadline after it, no request is sent and no wait begun
     * @param maxWait the longest rate-limit wait slept inside the listing
     * @param timeout one exchange's bound — {@link OutboundJson#TIMEOUT} but in a test
     * @param beforeEachRequest called before every request, retries and waits included: where a listing that
     *     runs for minutes renews its lease, and stops when it has lost it
     */
    public record Settings(
            String origin,
            OutboundPolicy policy,
            String label,
            Map<String, String> credential,
            Optional<PinnedCa> trust,
            Instant deadline,
            Duration maxWait,
            Duration timeout,
            Runnable beforeEachRequest) {

        public Settings {
            Objects.requireNonNull(origin, "origin");
            Objects.requireNonNull(policy, "policy");
            credential = Map.copyOf(credential);
            Objects.requireNonNull(trust, "trust");
            Objects.requireNonNull(deadline, "deadline");
            Objects.requireNonNull(maxWait, "maxWait");
            Objects.requireNonNull(timeout, "timeout");
            beforeEachRequest = beforeEachRequest == null ? () -> {} : beforeEachRequest;
        }
    }

    /** Sleeps; a test's records the wait and moves its clock instead. */
    @FunctionalInterface
    public interface Sleeper {

        Sleeper REAL = duration -> Thread.sleep(duration);

        void sleep(Duration duration) throws InterruptedException;
    }

    /** How a forge names its next page: read from an answer and the URL that produced it. */
    @FunctionalInterface
    public interface NextPage {

        /** RFC 8288's {@code Link: <…>; rel="next"} — GitHub, GitLab's keyset listings. */
        NextPage LINK = (answer, url) -> LinkHeader.target(joined(answer, "link"), "next");

        /**
         * GitLab: {@code Link} when it is there, and otherwise {@code X-Next-Page}, the page number its offset
         * listings state — GitLab leaves the {@code Link} out of an answer it would make too long.
         */
        NextPage GITLAB = (answer, url) -> LINK.next(answer, url)
                .or(() -> answer.header("x-next-page").map(String::trim).filter(page -> page.matches("[0-9]{1,9}"))
                        .map(page -> withQueryParameter(url, "page", page)));

        Optional<String> next(OutboundJson.Answer answer, String url);
    }

    private final OutboundJson outbound;
    private final Settings settings;
    private final Clock clock;
    private final Sleeper sleeper;
    private final Origin origin;
    private int requests;
    private Duration waited = Duration.ZERO;

    OutboundPager(OutboundJson outbound, Settings settings, Clock clock, Sleeper sleeper) {
        this.outbound = outbound;
        this.settings = settings;
        this.clock = clock;
        this.sleeper = sleeper;
        this.origin = Origin.of(settings.origin()).orElseThrow(() -> new IllegalArgumentException(
                "A pager is opened for an absolute URL: " + settings.origin()));
    }

    /**
     * Fetches one page — or any document — of the pager's origin, the credential attached.
     *
     * @param url absolute, of the pager's origin
     * @return the answer, whatever its status but a 5xx or a rate limit
     * @throws CrossOriginPageException the URL is not of the pager's origin; nothing was sent
     * @throws RateLimitedException a rate limit asked for a wait longer than {@link Settings#maxWait}
     * @throws DeadlineReachedException the deadline passed, or a wait would cross it
     * @throws OutboundJson.OutboundFailureException the page failed {@value #RETRIES} retries over
     * @throws com.asmolabs.vectispire.common.domain.net.UnsafeUrlException the guard refused the address
     */
    public OutboundJson.Answer get(String url) {
        requireSameOrigin(url);
        int failures = 0;
        while (true) {
            requireBeforeDeadline(Duration.ZERO);
            settings.beforeEachRequest().run();
            OutboundJson.Answer answer;
            try {
                requests++;
                answer = outbound.answer(url, settings.policy(), settings.label(), settings.credential(),
                        settings.trust(), settings.timeout());
            } catch (OutboundJson.OutboundFailureException unanswered) {
                failures = backOff(failures, unanswered);
                continue;
            }
            if (answer.status() / 100 == 5) {
                failures = backOff(failures, new OutboundJson.OutboundFailureException(
                        settings.label() + ": HTTP " + answer.status() + "."));
                continue;
            }
            Function<String, Optional<String>> header = answer::header;
            if (RateLimit.limited(answer.status(), header)) {
                Instant now = clock.instant();
                Duration wait = RateLimit.waitOf(header, now).orElse(settings.maxWait());
                if (wait.compareTo(settings.maxWait()) > 0) {
                    throw new RateLimitedException(settings.label() + ": rate limited for " + wait.toSeconds()
                            + " s, longer than the " + settings.maxWait().toSeconds() + " s a listing waits.",
                            now.plus(wait));
                }
                // At least a second: a limit lifting "now" by the server's clock is often a second ahead of ours.
                Duration slept = wait.compareTo(Duration.ofSeconds(1)) < 0 ? Duration.ofSeconds(1) : wait;
                requireBeforeDeadline(slept);
                sleep(slept);
                waited = waited.plus(slept);
                continue;
            }
            return answer;
        }
    }

    /**
     * The next page's URL, resolved against {@code url} when the forge wrote it relative; empty on the last page.
     * Not checked here: {@link #get} refuses it if it leads elsewhere, before anything is sent.
     */
    public Optional<String> next(OutboundJson.Answer answer, String url, NextPage nextPage) {
        return nextPage.next(answer, url).map(target -> {
            try {
                return new URI(url).resolve(new URI(target)).toString();
            } catch (URISyntaxException | IllegalArgumentException unreadable) {
                // Handed on as written: get() reads no origin in it and refuses it.
                return target;
            }
        });
    }

    /** How many requests this pager sent, retries included. */
    public int requests() {
        return requests;
    }

    /** How long it slept on rate limits — back-offs after a failure not counted. */
    public Duration rateLimitWaited() {
        return waited;
    }

    private int backOff(int failures, OutboundJson.OutboundFailureException failure) {
        if (failures >= RETRIES) {
            throw failure;
        }
        Duration pause = FIRST_BACK_OFF.multipliedBy(1L << failures);
        requireBeforeDeadline(pause);
        sleep(pause);
        return failures + 1;
    }

    private void requireBeforeDeadline(Duration ahead) {
        if (!clock.instant().plus(ahead).isBefore(settings.deadline())) {
            throw new DeadlineReachedException(settings.label() + ": the listing reached its time bound.");
        }
    }

    private void sleep(Duration duration) {
        try {
            sleeper.sleep(duration);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new OutboundJson.OutboundFailureException(settings.label() + ": interrupted while waiting.", interrupted);
        }
    }

    private void requireSameOrigin(String url) {
        Optional<Origin> target = Origin.of(url);
        if (target.isEmpty() || !target.get().equals(origin)) {
            throw new CrossOriginPageException(settings.label() + ": the forge pointed the next request at "
                    + describe(url) + ", which is not " + origin + "; nothing was sent there.");
        }
    }

    /** Where a refused URL pointed, without its query — a cursor or a token somebody put in it stays out of logs. */
    private static String describe(String url) {
        return Origin.of(url).map(Origin::toString).orElse("an unreadable address");
    }

    private static String joined(OutboundJson.Answer answer, String header) {
        List<String> values = answer.headers().get(header);
        return values == null ? null : String.join(",", values);
    }

    /** {@code url} with {@code name} set to {@code value}, replacing it where the query has it already. */
    static String withQueryParameter(String url, String name, String value) {
        int hash = url.indexOf('#');
        String base = hash < 0 ? url : url.substring(0, hash);
        int question = base.indexOf('?');
        String path = question < 0 ? base : base.substring(0, question);
        StringBuilder query = new StringBuilder();
        if (question >= 0) {
            for (String pair : base.substring(question + 1).split("&")) {
                if (pair.isEmpty() || pair.equals(name) || pair.startsWith(name + "=")) {
                    continue;
                }
                query.append(query.isEmpty() ? "" : "&").append(pair);
            }
        }
        query.append(query.isEmpty() ? "" : "&").append(name).append('=').append(value);
        return path + "?" + query;
    }

    /** Scheme, host and port — the default port spelled out, so that {@code :443} and nothing are one origin. */
    record Origin(String scheme, String host, int port) {

        static Optional<Origin> of(String url) {
            try {
                URI uri = new URI(url);
                if (uri.getScheme() == null || uri.getHost() == null || uri.getRawUserInfo() != null) {
                    return Optional.empty();
                }
                String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
                int port = uri.getPort() > 0 ? uri.getPort() : switch (scheme) {
                    case "https" -> 443;
                    case "http" -> 80;
                    default -> -1;
                };
                String host = uri.getHost().toLowerCase(Locale.ROOT);
                while (host.endsWith(".")) {
                    host = host.substring(0, host.length() - 1);
                }
                return Optional.of(new Origin(scheme, host, port));
            } catch (URISyntaxException unreadable) {
                return Optional.empty();
            }
        }

        @Override
        public String toString() {
            return scheme + "://" + host + ":" + port;
        }
    }

    /** The next request would have left the pager's origin; nothing was sent. A security event, not an outage. */
    public static final class CrossOriginPageException extends RuntimeException {

        private static final long serialVersionUID = 1L;

        CrossOriginPageException(String message) {
            super(message);
        }
    }

    /** A rate limit asked for longer than the listing waits. */
    public static final class RateLimitedException extends RuntimeException {

        private static final long serialVersionUID = 1L;

        private final transient Instant liftsAt;

        RateLimitedException(String message, Instant liftsAt) {
            super(message);
            this.liftsAt = liftsAt;
        }

        /** When the forge said the limit lifts. */
        public Instant liftsAt() {
            return liftsAt;
        }
    }

    /** The listing's deadline passed, or a wait would have crossed it. */
    public static final class DeadlineReachedException extends RuntimeException {

        private static final long serialVersionUID = 1L;

        DeadlineReachedException(String message) {
            super(message);
        }
    }
}
