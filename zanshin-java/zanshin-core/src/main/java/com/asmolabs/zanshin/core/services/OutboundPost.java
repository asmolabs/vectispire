package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.net.OutboundPolicy;
import com.asmolabs.zanshin.common.domain.net.OutboundUrlGuard;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import org.springframework.stereotype.Service;

/**
 * Posting JSON outwards — webhooks, ticket providers, the model reviewer.
 *
 * <p>Apart from {@link OutboundJson} because the contract is the opposite: this one <b>throws
 * on any failure</b>. Its callers are behind an outbox or a retry, and a swallowed failure
 * there is a failure never retried.
 *
 * <p>The response body is not read: the receiver has nothing to tell us, and a proxy can return
 * a several-kilobyte error page. Redirects are refused for the reason given in {@link
 * OutboundJson} — a validated webhook answering 302 would otherwise reach any internal address.
 */
@Service
public class OutboundPost {

    /**
     * Right for a webhook and a tracker: a destination that has not answered in ten seconds is a
     * destination to retry, not to wait on while a scan's transaction stays open.
     *
     * <p><b>Wrong for a model, and that is why the timeout is now a parameter.</b> A local model
     * writing a report takes minutes on ordinary hardware — this ceiling turned every OWASP run
     * into "Ollama: request timed out" after ten seconds, which reads as a broken Ollama rather
     * than as a limit Zanshin chose.
     */
    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    private final HttpClient http;
    private final OutboundUrlGuard guard;
    private final ObjectMapper json;

    public OutboundPost(OutboundUrlGuard guard, ObjectMapper json) {
        this.guard = guard;
        this.json = json;
        this.http = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(TIMEOUT)
                .build();
    }

    /**
     * Validates a URL without calling it.
     *
     * <p>For callers that need the checked destination before they build a request against it —
     * and so that a base URL is never validated by one component and posted to by another that
     * checked something else.
     */
    public String validate(String url, OutboundPolicy policy, String label) {
        return guard.validate(url, policy, label);
    }

    public void postJson(String url, Object body, OutboundPolicy policy, String label) {
        postForResponse(url, body, policy, label);
    }

    /** The body, for the callers that need the answer — a ticket's identifier, a model's reply. */
    public String postForResponse(String url, Object body, OutboundPolicy policy, String label) {
        return postForResponse(url, body, policy, label, HttpRequest.newBuilder());
    }

    /** @param prepared a builder already carrying the headers this destination needs, typically authentication */
    public String postForResponse(
            String url, Object body, OutboundPolicy policy, String label, HttpRequest.Builder prepared) {
        return postForResponse(url, body, policy, label, prepared, TIMEOUT);
    }

    /**
     * @param timeout for a destination whose normal answer takes longer than a webhook's. Taken
     *     alongside the builder rather than as its own overload: a five-argument form would sit
     *     next to the one taking a builder, and a mock matching on {@code any()} could not tell
     *     them apart — which is a compile error in the tests and a coin toss at a call site.
     */
    public String postForResponse(
            String url, Object body, OutboundPolicy policy, String label, HttpRequest.Builder prepared,
            Duration timeout) {

        String validated = guard.validate(url, policy, label);
        String encoded;
        try {
            encoded = json.writeValueAsString(body);
        } catch (JsonProcessingException impossible) {
            throw new IllegalStateException("Payload could not be serialized", impossible);
        }

        HttpRequest request = prepared
                .uri(URI.create(validated))
                .timeout(timeout)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(encoded))
                .build();

        try {
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() / 100 != 2) {
                throw new OutboundJson.OutboundFailureException(label + ": HTTP " + response.statusCode() + ".");
            }
            return response.body();
        } catch (IOException unreachable) {
            throw new OutboundJson.OutboundFailureException(label + ": " + unreachable.getMessage(), unreachable);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new OutboundJson.OutboundFailureException(label + ": interrupted.", interrupted);
        }
    }
}
