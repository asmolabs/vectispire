package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.net.OutboundPolicy;
import com.asmolabs.zanshin.common.domain.net.OutboundUrlGuard;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
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
 * <p><b>Bounded in time.</b> Without a deadline a silent server holds a scan open for as long
 * as it likes, and the scan's lease lapses while its worker is alive and waiting.
 */
@Service
public class OutboundJson {

    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    private final HttpClient http;
    private final OutboundUrlGuard guard;
    private final ObjectMapper json;

    public OutboundJson(OutboundUrlGuard guard, ObjectMapper json) {
        this.guard = guard;
        this.json = json;
        this.http = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(TIMEOUT)
                .build();
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
        String validated = guard.validate(url, policy, label);
        HttpRequest request = HttpRequest.newBuilder(URI.create(validated))
                .timeout(TIMEOUT)
                .header("Accept", "application/json")
                .GET()
                .build();

        try {
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 404) {
                return Optional.empty();
            }
            if (response.statusCode() / 100 != 2) {
                throw new OutboundFailureException(label + ": HTTP " + response.statusCode() + ".");
            }
            return Optional.of(json.readTree(response.body()));
        } catch (IOException | UncheckedIOException unreachable) {
            throw new OutboundFailureException(label + ": " + unreachable.getMessage(), unreachable);
        } catch (InterruptedException interrupted) {
            // Restore the flag: swallowing it leaves a thread that will not notice the next
            // shutdown request either.
            Thread.currentThread().interrupt();
            throw new OutboundFailureException(label + ": interrupted.", interrupted);
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
