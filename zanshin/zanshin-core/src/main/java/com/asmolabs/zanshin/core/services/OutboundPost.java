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

        String validated = guard.validate(url, policy, label);
        String encoded;
        try {
            encoded = json.writeValueAsString(body);
        } catch (JsonProcessingException impossible) {
            throw new IllegalStateException("Payload could not be serialized", impossible);
        }

        HttpRequest request = prepared
                .uri(URI.create(validated))
                .timeout(TIMEOUT)
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
