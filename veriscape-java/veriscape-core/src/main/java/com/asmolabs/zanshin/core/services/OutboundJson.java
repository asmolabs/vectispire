package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.net.OutboundPolicy;
import com.asmolabs.zanshin.common.domain.net.OutboundUrlGuard;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * Every JSON call Zanshin makes to the outside, through one door.
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
        PinnedHttpSender.Response response = sender.send(
                guard.validateAndResolve(url, policy, label),
                Map.of("Accept", "application/json"),
                null,
                TIMEOUT,
                label);

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
