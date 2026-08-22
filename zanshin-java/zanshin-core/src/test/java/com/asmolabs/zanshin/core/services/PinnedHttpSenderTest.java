package com.asmolabs.zanshin.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.zanshin.common.domain.net.OutboundUrlGuard;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The pin, demonstrated against a real socket.
 *
 * <p><b>Why a server and not a mock.</b> The claim being tested is "the connection went to the
 * address the guard checked, and DNS was not consulted a second time". A mocked client can only
 * show that a method was called with the right argument, which is the part nobody doubted. The
 * proof used here is that the request reaches a listening socket <b>through a host name that
 * does not resolve at all</b>: if anything in the path asked the system resolver, the request
 * could not arrive.
 */
@DisplayName("an outbound request goes to the address that was checked")
class PinnedHttpSenderTest {

    /**
     * A name with a reserved TLD, so it cannot resolve here or anywhere.
     *
     * <p>{@code .invalid} is reserved by RFC 2606 for exactly this. A made-up name under a real
     * TLD would resolve the day somebody registers it, and a wildcard DNS provider on the test
     * machine's network would resolve it today.
     */
    private static final String UNRESOLVABLE_HOST = "rebound.invalid";

    private HttpServer server;
    private final AtomicReference<String> hostHeader = new AtomicReference<>();

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/hook", exchange -> {
            hostHeader.set(exchange.getRequestHeaders().getFirst("Host"));
            byte[] body = "{\"ok\":true}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    @DisplayName("a name that resolves nowhere still reaches the checked address")
    void thePinIsWhatTheConnectionUses() {
        OutboundUrlGuard.Destination destination = new OutboundUrlGuard.Destination(
                "http://" + UNRESOLVABLE_HOST + ":" + server.getAddress().getPort() + "/hook",
                UNRESOLVABLE_HOST,
                List.of(InetAddress.getLoopbackAddress()));

        PinnedHttpSender.Response response =
                new PinnedHttpSender().send(destination, Map.of(), "{}", Duration.ofSeconds(5), "webhook");

        assertThat(response.status()).isEqualTo(200);
        assertThat(response.body()).contains("\"ok\":true");
        // And the name still travelled: the server saw the host it was addressed as, which is
        // what keeps virtual hosting, SNI and certificate verification working. Connecting to a
        // validated IP literal instead would have broken all three.
        assertThat(hostHeader.get()).startsWith(UNRESOLVABLE_HOST);
    }

    @Test
    @DisplayName("a host that was not checked is refused rather than resolved")
    void anUncheckedHostIsRefused() {
        // The URI and the checked host disagree — which is what a redirect somebody re-enabled,
        // or a rewritten URL, looks like from inside the sender. The resolver refuses instead of
        // falling back to the system one, so the request cannot leave.
        OutboundUrlGuard.Destination mismatched = new OutboundUrlGuard.Destination(
                "http://127.0.0.1:" + server.getAddress().getPort() + "/hook",
                UNRESOLVABLE_HOST,
                List.of(InetAddress.getLoopbackAddress()));

        assertThatThrownBy(() -> new PinnedHttpSender()
                        .send(mismatched, Map.of(), "{}", Duration.ofSeconds(5), "webhook"))
                .isInstanceOf(OutboundJson.OutboundFailureException.class)
                .hasMessageContaining("never checked");
    }

    @Test
    @DisplayName("a destination with no checked address is refused, not sent unpinned")
    void nothingToPinMeansNothingIsSent() {
        // The guard tolerates a name it could not resolve, because for "is this public?" the
        // request would fail anyway and refusing would break the settings screen on a DNS
        // hiccup. Here there is nothing to pin to, so sending would mean letting the client
        // resolve the name itself — and the validation would have decided nothing at all.
        OutboundUrlGuard.Destination unresolved =
                new OutboundUrlGuard.Destination("http://" + UNRESOLVABLE_HOST + "/hook", UNRESOLVABLE_HOST, List.of());

        assertThatThrownBy(() -> new PinnedHttpSender()
                        .send(unresolved, Map.of(), "{}", Duration.ofSeconds(5), "webhook"))
                .isInstanceOf(OutboundJson.OutboundFailureException.class)
                .hasMessageContaining("does not resolve");
    }
}
