package com.asmolabs.zanshin.agent;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * The HTTP call, with the key on every request.
 *
 * <p><b>Redirects are refused, as everywhere else in this repository.</b> The control plane is a
 * fixed configuration address: it has no reason to redirect, and following one would send a
 * scan's results — or the claim that carries the API key — to a host nobody declared. A proxy
 * that redirects HTTP to HTTPS then fails the agent loudly, which is the right outcome: the fix
 * is to set the URL to https.
 */
public class AgentHttp {

    private final HttpClient client;
    private final ObjectMapper json;
    private final String baseUrl;
    private final String token;

    public AgentHttp(ObjectMapper json, String baseUrl, String token) {
        this.json = json;
        this.baseUrl = baseUrl;
        this.token = token;
        this.client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(15))
                .build();
    }

    /**
     * @param body the parsed answer, or a null node. A 204 has none, and parsing it would raise
     *     where there is nothing to read
     */
    public record Response(int status, JsonNode body) {

        /** The server's message when it gives one, otherwise the caller's own wording. */
        public String messageOr(String fallback) {
            String detail = body.path("detail").asText("");
            if (!detail.isEmpty()) {
                return detail;
            }
            String message = body.path("message").asText("");
            return message.isEmpty() ? fallback : message;
        }
    }

    public Response call(String path, String method, Object body, Duration timeout) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .timeout(timeout)
                .header("Authorization", "Bearer " + token)
                .header("Accept", "application/json");

        HttpRequest.BodyPublisher publisher = HttpRequest.BodyPublishers.noBody();
        if (body != null) {
            builder = builder.header("Content-Type", "application/json");
            publisher = HttpRequest.BodyPublishers.ofString(write(body));
        }

        HttpRequest request = builder.method(method, publisher).build();
        try {
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            return new Response(response.statusCode(), parse(response.body()));
        } catch (IOException unreachable) {
            throw new IllegalStateException("The control plane is unreachable: " + unreachable.getMessage(), unreachable);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while calling the control plane.", interrupted);
        }
    }

    private JsonNode parse(String text) {
        if (text == null || text.isBlank()) {
            return json.nullNode();
        }
        try {
            return json.readTree(text);
        } catch (IOException notJson) {
            // An unreadable answer is information: a proxy returning HTML, for instance. The raw
            // text beats a parsing exception, and the first five hundred characters are enough to
            // recognize what answered.
            return json.createObjectNode().put("message", text.substring(0, Math.min(text.length(), 500)));
        }
    }

    private String write(Object body) {
        try {
            return json.writeValueAsString(body);
        } catch (com.fasterxml.jackson.core.JsonProcessingException impossible) {
            throw new IllegalStateException("Request body could not be serialized", impossible);
        }
    }
}
