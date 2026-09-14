package com.asmolabs.vectispire.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The agent's only way of talking to the control plane, and the only class of the module no test
 * spoke about.
 *
 * <p><b>Why that mattered.</b> This is where the API key is attached to every request, where
 * redirects are refused, and where timeouts are set — three properties whose failure is silent.
 * A redirect quietly followed sends the bearer token, or a scan's results, to a host nobody
 * declared; a request built without the header fails as an authorization problem somewhere else
 * entirely. The module's other classes were fully covered and this one was at zero, so the
 * number said fifty per cent and the gap was all in one place.
 *
 * <p><b>Against a real server, not a mock.</b> The JDK ships one, so it costs no dependency, and
 * the properties under test are properties of an actual exchange: a mocked {@code HttpClient}
 * would happily report that redirects are refused because the mock was told to say so.
 */
@DisplayName("the agent's HTTP client")
class AgentHttpTest {

    private static final String TOKEN = "agent-key-not-a-secret";

    private HttpServer server;
    private String baseUrl;
    private final List<Map<String, String>> received = new CopyOnWriteArrayList<>();
    private final List<String> bodies = new CopyOnWriteArrayList<>();

    private AgentHttp client;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
        server.start();
        client = new AgentHttp(new ObjectMapper(), baseUrl, TOKEN);
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    @DisplayName("carries the API key and asks for JSON on every request")
    void carries_the_key_on_every_request() {
        respondWith("/agent/hello", 200, "application/json", "{\"ok\":true}");

        AgentHttp.Response response = client.call("/agent/hello", "GET", null, Duration.ofSeconds(5));

        assertThat(response.status()).isEqualTo(200);
        assertThat(received.getFirst())
                .containsEntry("authorization", "Bearer " + TOKEN)
                .containsEntry("accept", "application/json");
    }

    @Test
    @DisplayName("does not follow a redirect, because the next host is one nobody declared")
    void refuses_to_follow_a_redirect() {
        server.createContext("/agent/jobs", exchange -> {
            record(exchange);
            exchange.getResponseHeaders().add("Location", "http://elsewhere.invalid/agent/jobs");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });

        AgentHttp.Response response = client.call("/agent/jobs", "GET", null, Duration.ofSeconds(5));

        assertThat(response.status())
                .as("a followed redirect would have sent the bearer token to the Location host")
                .isEqualTo(302);
    }

    @Test
    @DisplayName("sends a pre-serialized body byte for byte, so a signature still covers it")
    void sends_raw_json_verbatim() {
        respondWith("/agent/result", 200, "application/json", "{\"accepted\":true}");

        // Deliberately not what this mapper would produce: spacing and key order are the point.
        String signed = "{ \"b\" : 2,  \"a\":1 }";
        client.call("/agent/result", "POST", new AgentHttp.RawJson(signed), Duration.ofSeconds(5));

        assertThat(bodies.getFirst())
                .as("re-serializing here would sign a document the server never sees")
                .isEqualTo(signed);
        assertThat(received.getFirst()).containsEntry("content-type", "application/json");
    }

    @Test
    @DisplayName("adds the headers a caller passes, which is how a signature travels")
    void adds_the_callers_headers() {
        respondWith("/agent/result", 200, "application/json", "{}");

        client.call(
                "/agent/result",
                "POST",
                new AgentHttp.RawJson("{}"),
                Duration.ofSeconds(5),
                Map.of("X-Vectispire-Agent-Signature", "c2lnbmF0dXJl"));

        assertThat(received.getFirst()).containsEntry("x-vectispire-agent-signature", "c2lnbmF0dXJl");
    }

    @Test
    @DisplayName("sets no content type when there is no body")
    void sets_no_content_type_without_a_body() {
        respondWith("/agent/hello", 200, "application/json", "{}");

        client.call("/agent/hello", "GET", null, Duration.ofSeconds(5));

        assertThat(received.getFirst()).doesNotContainKey("content-type");
    }

    @Test
    @DisplayName("reads an empty answer as an empty node rather than raising on it")
    void reads_an_empty_answer_as_a_null_node() {
        server.createContext("/agent/heartbeat", exchange -> {
            record(exchange);
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        });

        AgentHttp.Response response = client.call("/agent/heartbeat", "POST", null, Duration.ofSeconds(5));

        assertThat(response.status()).isEqualTo(204);
        assertThat(response.body().isNull()).isTrue();
    }

    @Test
    @DisplayName("turns an answer that is not JSON into something an operator can recognise")
    void keeps_a_non_json_answer_readable() {
        String html = "<html><body>502 Bad Gateway — nginx</body></html>";
        respondWith("/agent/jobs", 502, "text/html", html);

        AgentHttp.Response response = client.call("/agent/jobs", "GET", null, Duration.ofSeconds(5));

        assertThat(response.status()).isEqualTo(502);
        assertThat(response.body().path("message").asText())
                .as("a parsing exception here would hide which proxy answered")
                .contains("502 Bad Gateway");
    }

    @Test
    @DisplayName("truncates a long unreadable answer rather than carrying a page into a log line")
    void truncates_a_long_unreadable_answer() {
        respondWith("/agent/jobs", 500, "text/html", "x".repeat(2_000));

        AgentHttp.Response response = client.call("/agent/jobs", "GET", null, Duration.ofSeconds(5));

        assertThat(response.body().path("message").asText()).hasSize(500);
    }

    @Test
    @DisplayName("says the control plane is unreachable rather than leaking an IO exception")
    void reports_an_unreachable_control_plane() {
        AgentHttp unreachable =
                new AgentHttp(new ObjectMapper(), "http://127.0.0.1:1", TOKEN);

        assertThatThrownBy(() -> unreachable.call("/agent/hello", "GET", null, Duration.ofSeconds(2)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("The control plane is unreachable");
    }

    @Test
    @DisplayName("prefers the server's own wording, then its message, then the caller's")
    void prefers_the_servers_wording() {
        respondWith("/a", 400, "application/json", "{\"detail\":\"the key is not pinned\"}");
        respondWith("/b", 400, "application/json", "{\"message\":\"nope\"}");
        respondWith("/c", 400, "application/json", "{}");

        assertThat(client.call("/a", "GET", null, Duration.ofSeconds(5)).messageOr("fallback"))
                .isEqualTo("the key is not pinned");
        assertThat(client.call("/b", "GET", null, Duration.ofSeconds(5)).messageOr("fallback"))
                .isEqualTo("nope");
        assertThat(client.call("/c", "GET", null, Duration.ofSeconds(5)).messageOr("fallback"))
                .isEqualTo("fallback");
    }

    private void respondWith(String path, int status, String contentType, String body) {
        server.createContext(path, exchange -> {
            record(exchange);
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", contentType);
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
    }

    private void record(HttpExchange exchange) throws IOException {
        received.add(exchange.getRequestHeaders().entrySet().stream()
                .collect(java.util.stream.Collectors.toMap(
                        entry -> entry.getKey().toLowerCase(java.util.Locale.ROOT),
                        entry -> String.join(",", entry.getValue()))));
        bodies.add(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
    }
}
