package com.asmolabs.vectispire.core.api.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("Which peers may speak for somebody else")
class TrustedProxiesTest {

    private static HttpServletRequest request(String peer, boolean secure, String proto) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenReturn(peer);
        when(request.isSecure()).thenReturn(secure);
        when(request.getHeader("X-Forwarded-Proto")).thenReturn(proto);
        return request;
    }

    @Nested
    @DisplayName("X-Forwarded-Proto, which decides whether a deployment key travels")
    class ForwardedProto {

        /**
         * The defect this class was written for.
         *
         * <p>{@code AgentsController.isSecureTransport} read this header from any peer at all and
         * said so in its own javadoc. An attacker holding an agent's API key could therefore ask
         * for the repository's SSH key over plain HTTP by sending one header.
         */
        @Test
        @DisplayName("is ignored from an untrusted peer, even when it says https")
        void forgedHeaderDecidesNothing() {
            TrustedProxies proxies = new TrustedProxies("");

            assertThat(proxies.isSecureTransport(request("203.0.113.9", false, "https"))).isFalse();
        }

        @Test
        @DisplayName("is honoured from a peer the operator declared")
        void trustedProxyIsBelieved() {
            TrustedProxies proxies = new TrustedProxies("10.0.0.0/8");

            assertThat(proxies.isSecureTransport(request("10.1.2.3", false, "https"))).isTrue();
        }

        @Test
        @DisplayName("a trusted proxy reporting http is still http")
        void trustedProxyCanAlsoSayNo() {
            TrustedProxies proxies = new TrustedProxies("10.0.0.0/8");

            assertThat(proxies.isSecureTransport(request("10.1.2.3", false, "http"))).isFalse();
        }

        @Test
        @DisplayName("a genuinely encrypted connection needs no header and no trust")
        void theSocketIsAFact() {
            TrustedProxies proxies = new TrustedProxies("");

            assertThat(proxies.isSecureTransport(request("203.0.113.9", true, null))).isTrue();
        }

        @Test
        @DisplayName("only the client's own leg is read, not a later hop")
        void firstHopOnly() {
            TrustedProxies proxies = new TrustedProxies("10.0.0.0/8");

            // The request reached the proxy over http and the proxy spoke https onwards. The leg
            // that matters for a secret is the first one.
            assertThat(proxies.isSecureTransport(request("10.1.2.3", false, "http, https"))).isFalse();
        }
    }

    @Nested
    @DisplayName("X-Forwarded-For, which decides who is rate-limited")
    class ForwardedFor {

        private static HttpServletRequest withForwardedFor(String peer, String forwarded) {
            HttpServletRequest request = mock(HttpServletRequest.class);
            when(request.getRemoteAddr()).thenReturn(peer);
            when(request.getHeader("X-Forwarded-For")).thenReturn(forwarded);
            return request;
        }

        @Test
        @DisplayName("a spoofed header from an untrusted peer buys no fresh bucket")
        void spoofedHeaderIgnored() {
            TrustedProxies proxies = new TrustedProxies("");

            assertThat(proxies.clientAddress(withForwardedFor("203.0.113.9", "1.2.3.4")))
                    .isEqualTo("203.0.113.9");
        }

        @Test
        @DisplayName("the leftmost untrusted hop is the client")
        void walksBackToTheClient() {
            TrustedProxies proxies = new TrustedProxies("10.0.0.0/8");

            assertThat(proxies.clientAddress(withForwardedFor("10.0.0.1", "198.51.100.7, 10.0.0.2")))
                    .isEqualTo("198.51.100.7");
        }

        @Test
        @DisplayName("when every hop is a trusted proxy, the peer is what is left")
        void allHopsTrusted() {
            TrustedProxies proxies = new TrustedProxies("10.0.0.0/8");

            assertThat(proxies.clientAddress(withForwardedFor("10.0.0.1", "10.0.0.5, 10.0.0.2")))
                    .isEqualTo("10.0.0.1");
        }
    }

    @Test
    @DisplayName("an empty configuration trusts nothing")
    void emptyMeansNothing() {
        assertThat(new TrustedProxies("").none()).isTrue();
        assertThat(new TrustedProxies("  ").none()).isTrue();
        assertThat(new TrustedProxies(null).none()).isTrue();
        assertThat(new TrustedProxies("10.0.0.0/8").none()).isFalse();
    }

    @Test
    @DisplayName("a header value that is not an address matches no proxy")
    void malformedAddress() {
        TrustedProxies proxies = new TrustedProxies("10.0.0.0/8");

        assertThat(proxies.isTrusted("not-an-address")).isFalse();
    }
}
