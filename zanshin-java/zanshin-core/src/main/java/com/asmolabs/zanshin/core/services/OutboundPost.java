package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.net.OutboundPolicy;
import com.asmolabs.zanshin.common.domain.net.OutboundUrlGuard;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.util.Map;
import org.springframework.stereotype.Service;

/**
 * Posting JSON outwards — webhooks, ticket providers, the model reviewer.
 *
 * <p>Apart from {@link OutboundJson} because the contract is the opposite: this one <b>throws
 * on any failure</b>. Its callers are behind an outbox or a retry, and a swallowed failure
 * there is a failure never retried.
 *
 * <p>Redirects are refused for the reason given in {@link OutboundJson} — a validated webhook
 * answering 302 would otherwise reach any internal address — and the connection is pinned to the
 * address the guard checked, which is what {@link PinnedHttpSender} is for.
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

    private final PinnedHttpSender sender;
    private final OutboundUrlGuard guard;
    private final ObjectMapper json;

    public OutboundPost(PinnedHttpSender sender, OutboundUrlGuard guard, ObjectMapper json) {
        this.sender = sender;
        this.guard = guard;
        this.json = json;
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
        return postForResponse(url, body, policy, label, Map.of());
    }

    /** @param headers what this destination needs beyond the content type, typically authentication */
    public String postForResponse(
            String url, Object body, OutboundPolicy policy, String label, Map<String, String> headers) {
        return postForResponse(url, body, policy, label, headers, TIMEOUT);
    }

    /**
     * @param headers plain pairs rather than a client's request builder. The builder used to be
     *     {@code java.net.http.HttpRequest.Builder}, which made every caller needing one
     *     authentication header import the JDK's HTTP client — and pinned this signature to a
     *     client that turned out to have no resolver hook. A header is a header.
     * @param timeout for a destination whose normal answer takes longer than a webhook's. Taken
     *     alongside the headers rather than as its own overload: a five-argument form would sit
     *     next to the one taking headers, and a mock matching on {@code any()} could not tell
     *     them apart — which is a compile error in the tests and a coin toss at a call site.
     */
    public String postForResponse(
            String url, Object body, OutboundPolicy policy, String label, Map<String, String> headers,
            Duration timeout) {

        String encoded;
        try {
            encoded = json.writeValueAsString(body);
        } catch (JsonProcessingException impossible) {
            throw new IllegalStateException("Payload could not be serialized", impossible);
        }

        PinnedHttpSender.Response response = sender.send(
                guard.validateAndResolve(url, policy, label), headers, encoded, timeout, label);

        if (response.status() / 100 != 2) {
            throw new OutboundJson.OutboundFailureException(label + ": HTTP " + response.status() + ".");
        }
        return response.body();
    }
}
