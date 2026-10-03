package com.asmolabs.vectispire.core.outbound;

import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard;
import com.asmolabs.vectispire.common.domain.net.PinnedCa;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * Every JSON call Vectispire makes to the outside, through one door.
 *
 * <p><b>Redirects are refused, not followed.</b> A guard that validates a URL and then lets the
 * client follow a 302 has validated nothing: the destination that was checked is not the
 * destination that was reached. The NestJS tree found this the hard way — one redirect
 * cancelled the whole URL guard — and the fix is the same here, expressed as a client that
 * never redirects rather than as a rule somebody has to remember.
 *
 * <p><b>And the connection goes to the address that was checked</b>, not to a second lookup of
 * the same name — see {@link PinnedHttpSender} for the window that closes and why the JDK's
 * client could not close it.
 *
 * <p><b>Bounded in time.</b> Without a deadline a silent server holds a scan open for as long
 * as it likes, and the scan's lease lapses while its worker is alive and waiting.
 */
@Service
public class OutboundJson {

    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    private final PinnedHttpSender sender;
    private final OutboundUrlGuard guard;
    private final ObjectMapper json;

    public OutboundJson(PinnedHttpSender sender, OutboundUrlGuard guard, ObjectMapper json) {
        this.sender = sender;
        this.guard = guard;
        this.json = json;
    }

    /**
     * Fetches a JSON document.
     *
     * <p><b>404 is empty, not a failure.</b> "This product is not in the catalog" is an answer,
     * and one worth neither a log line at error level nor a retry. Every other non-2xx status
     * raises: those are failures, and a caller that swallowed them would treat an outage as an
     * empty catalog.
     *
     * @param label what the operator would call this destination, for the message they will read
     */
    public Optional<JsonNode> get(String url, OutboundPolicy policy, String label) {
        return get(url, policy, label, Map.of());
    }

    /**
     * The same, for a catalogue that will not answer an anonymous caller.
     *
     * <p>Plain pairs rather than a request builder, for the reason {@code OutboundPost} gives:
     * a header is a header, and taking a builder here would pin this signature to one HTTP client.
     *
     * @param headers what this destination needs beyond the content type, typically authentication
     */
    public Optional<JsonNode> get(
            String url, OutboundPolicy policy, String label, Map<String, String> headers) {
        return get(url, policy, label, headers, PinnedHttpSender.DEFAULT_MAX_BODY_BYTES);
    }

    /**
     * The same, for a document larger than an ordinary answer — a catalogue.
     *
     * @param maxBodyBytes the ceiling on the answer; see {@link PinnedHttpSender#DEFAULT_MAX_BODY_BYTES}
     */
    public Optional<JsonNode> get(
            String url, OutboundPolicy policy, String label, Map<String, String> headers, long maxBodyBytes) {
        Map<String, String> all = new java.util.LinkedHashMap<>(headers);
        // Accept last: a caller cannot quietly turn this into a request for something else.
        all.put("Accept", "application/json");

        PinnedHttpSender.Response response = sender.send(
                PinnedHttpSender.Method.GET,
                guard.validateAndResolve(url, policy, label),
                Map.copyOf(all),
                null,
                TIMEOUT,
                label,
                maxBodyBytes);

        if (response.status() == 404) {
            return Optional.empty();
        }
        if (response.status() / 100 != 2) {
            throw new OutboundFailureException(label + ": HTTP " + response.status() + ".");
        }
        try {
            return Optional.of(json.readTree(response.body()));
        } catch (IOException | UncheckedIOException unreadable) {
            throw new OutboundFailureException(label + ": " + unreadable.getMessage(), unreadable);
        }
    }

    /**
     * An answer whatever its status, with its headers: for a caller to whom a 401 or a 403 means
     * something of its own — a forge refusing a token is not an outage (decision 0037).
     *
     * @param body the document on a 2xx; empty on any other status, whose body is not read as JSON
     * @param headers by lower-case name
     */
    public record Answer(int status, Optional<JsonNode> body, Map<String, List<String>> headers) {

        /** The first value of a header, by name in any case; empty when the answer did not carry it. */
        public Optional<String> header(String name) {
            List<String> values = headers.get(name.toLowerCase(Locale.ROOT));
            return values == null || values.isEmpty() ? Optional.empty() : Optional.of(values.getFirst());
        }
    }

    /**
     * Fetches a JSON document and hands back the status and the headers too, verifying the server
     * against a pinned CA when one is given.
     *
     * <p>The same door as {@link #get}: the guard, the pin, no redirect, ten seconds. What differs is
     * that no status is an exception here — only an exchange that produced no answer, or a 2xx that is
     * not JSON. Lot D1 of decision 0037 needs one request's headers (a token's scopes and expiry, a
     * server's version); the paged form with the rate-limit headers is lot D2's.
     *
     * @param trust the CA the server must chain to, in place of the runtime's store; empty for that store
     * @throws com.asmolabs.vectispire.common.domain.net.UnsafeUrlException when the guard refuses the URL
     * @throws OutboundFailureException when no answer came back, or a 2xx carried no JSON
     */
    public Answer answer(
            String url, OutboundPolicy policy, String label, Map<String, String> headers, Optional<PinnedCa> trust) {
        Map<String, String> all = new java.util.LinkedHashMap<>(headers);
        all.put("Accept", "application/json");

        PinnedHttpSender.Response response = sender.send(
                PinnedHttpSender.Method.GET,
                guard.validateAndResolve(url, policy, label),
                Map.copyOf(all),
                null,
                TIMEOUT,
                label,
                PinnedHttpSender.DEFAULT_MAX_BODY_BYTES,
                trust);

        if (response.status() / 100 != 2) {
            return new Answer(response.status(), Optional.empty(), response.headers());
        }
        try {
            return new Answer(response.status(), Optional.of(json.readTree(response.body())), response.headers());
        } catch (IOException | UncheckedIOException unreadable) {
            throw new OutboundFailureException(label + ": the answer is not JSON.", unreadable);
        }
    }

    /** A destination that did not answer usefully. Never a reason to fail a scan. */
    public static class OutboundFailureException extends RuntimeException {

        private static final long serialVersionUID = 1L;

        public OutboundFailureException(String message) {
            super(message);
        }

        public OutboundFailureException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
