package com.asmolabs.vectispire.core.outbound;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * A file downloaded through the guard and the pin, against a real socket — FIRST's EPSS address
 * answers with a redirect, and the rules about which one is followed are only true if a server makes
 * one.
 */
@DisplayName("a file is downloaded through the checked door, one same-origin redirect at most")
class OutboundDownloadTest {

    /** Bytes no text decoding survives: a gzip magic, a NUL, and an invalid UTF-8 sequence. */
    private static final byte[] FILE = {0x1f, (byte) 0x8b, 0x00, (byte) 0xc3, 0x28, (byte) 0xff, 0x41};

    private HttpServer server;
    private final AtomicInteger served = new AtomicInteger();
    private OutboundDownload download;

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/current.csv.gz", exchange -> redirect(exchange, "dated.csv.gz"));
        server.createContext("/dated.csv.gz", exchange -> {
            served.incrementAndGet();
            answer(exchange, 200, FILE);
        });
        server.createContext("/elsewhere", exchange -> redirect(exchange, "http://elsewhere.invalid/dated.csv.gz"));
        server.createContext("/twice", exchange -> redirect(exchange, "/current.csv.gz"));
        server.createContext("/large", exchange -> answer(exchange, 200, new byte[64 * 1024]));
        server.createContext("/gone", exchange -> answer(exchange, 404, new byte[0]));
        server.createContext("/broken", exchange -> answer(exchange, 503, "unavailable".getBytes()));
        server.start();
        download = new OutboundDownload(new PinnedHttpSender(), new OutboundUrlGuard());
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    @Test
    @DisplayName("follows a redirect to the same origin, and the bytes arrive as they were sent")
    void followsOneSameOriginRedirect() {
        assertThat(get("/current.csv.gz", 1024)).contains(FILE);
        assertThat(served).hasValue(1);
    }

    @Test
    @DisplayName("a redirect to another host is refused, and names the host")
    void refusesAnotherOrigin() {
        assertThatThrownBy(() -> get("/elsewhere", 1024))
                .isInstanceOf(OutboundJson.OutboundFailureException.class)
                .hasMessageContaining("another origin (elsewhere.invalid)");
    }

    @Test
    @DisplayName("a second redirect is refused rather than followed")
    void refusesASecondRedirect() {
        assertThatThrownBy(() -> get("/twice", 1024))
                .isInstanceOf(OutboundJson.OutboundFailureException.class)
                .hasMessageContaining("only one redirect is followed");
        assertThat(served).hasValue(0);
    }

    @Test
    @DisplayName("a file past the ceiling is refused, not truncated")
    void refusesPastTheCeiling() {
        assertThatThrownBy(() -> get("/large", 1024))
                .isInstanceOf(OutboundJson.OutboundFailureException.class)
                .hasMessageContaining("larger than 1024 bytes");
    }

    @Test
    @DisplayName("404 is absent; any other failure raises")
    void statuses() {
        assertThat(get("/gone", 1024)).isEmpty();
        assertThatThrownBy(() -> get("/broken", 1024))
                .isInstanceOf(OutboundJson.OutboundFailureException.class)
                .hasMessageContaining("HTTP 503");
    }

    @Test
    @DisplayName("the redirect's target keeps the scheme, the host and the port")
    void sameOriginIsScheme_host_andPort() {
        String asked = "https://epss.example.org/epss_scores-current.csv.gz";
        assertThat(OutboundDownload.sameOrigin(asked, "epss_scores-2026-09-27.csv.gz", "EPSS"))
                .isEqualTo("https://epss.example.org/epss_scores-2026-09-27.csv.gz");
        assertThat(OutboundDownload.sameOrigin(asked, "https://EPSS.example.org:443/x.gz", "EPSS"))
                .isEqualTo("https://EPSS.example.org:443/x.gz");
        for (String elsewhere : new String[] {
            "http://epss.example.org/x.gz", "https://epss.example.org:8443/x.gz", "//other.example.org/x.gz",
            "https://user@epss.example.org/x.gz"
        }) {
            assertThatThrownBy(() -> OutboundDownload.sameOrigin(asked, elsewhere, "EPSS")).as(elsewhere)
                    .isInstanceOf(OutboundJson.OutboundFailureException.class);
        }
    }

    private java.util.Optional<byte[]> get(String path, long max) {
        return download.get("http://127.0.0.1:" + server.getAddress().getPort() + path,
                OutboundPolicy.INTERNAL_ALLOWED, "EPSS file", max, Duration.ofSeconds(5));
    }

    private static void redirect(com.sun.net.httpserver.HttpExchange exchange, String location) throws IOException {
        exchange.getResponseHeaders().add("Location", location);
        answer(exchange, 302, new byte[0]);
    }

    private static void answer(com.sun.net.httpserver.HttpExchange exchange, int status, byte[] body)
            throws IOException {
        exchange.sendResponseHeaders(status, body.length == 0 ? -1 : body.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
        }
    }
}
