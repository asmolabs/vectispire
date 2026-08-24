package com.asmolabs.vectispire.common.domain.net;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.InetAddress;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("outbound URL guard")
class OutboundUrlGuardTest {

    /** A resolver that answers with fixed literals, so no test depends on DNS. */
    private static OutboundUrlGuard guardResolving(String... addresses) {
        return new OutboundUrlGuard(hostname -> Arrays.stream(addresses)
                .map(address -> {
                    try {
                        return InetAddress.ofLiteral(address).getAddress();
                    } catch (IllegalArgumentException e) {
                        throw new AssertionError("test fixture is not an address: " + address, e);
                    }
                })
                .toList());
    }

    private static final OutboundUrlGuard NO_DNS = new OutboundUrlGuard(hostname -> List.of());

    @Nested
    @DisplayName("shape of the URL")
    class Shape {

        @ParameterizedTest(name = "refuses the {0} scheme")
        @ValueSource(strings = {"file:///etc/passwd", "gopher://host/", "ftp://host/"})
        void refusesForeignSchemes(String url) {
            assertThatThrownBy(() -> NO_DNS.validate(url, OutboundPolicy.INTERNAL_ALLOWED, "Scan API"))
                    .isInstanceOf(UnsafeUrlException.class)
                    .hasMessageContaining("is not allowed");
        }

        @Test
        @DisplayName("refuses an empty value with a message naming the setting")
        void refusesEmpty() {
            // The message reaches an administrator on a settings screen. "Invalid URL" would
            // send them looking at the wrong field.
            assertThatThrownBy(() -> NO_DNS.validate("   ", OutboundPolicy.PUBLIC_ONLY, "Webhook"))
                    .hasMessageContaining("Webhook");
        }
    }

    @Nested
    @DisplayName("the metadata endpoint, refused under every policy")
    class LinkLocal {

        @ParameterizedTest(name = "refuses {0}, however it is spelled")
        @ValueSource(strings = {
            "169.254.169.254",
            // The normalized IPv6 form of the same address. Comparing text rather than bytes
            // is what let this one through a guard written on string prefixes.
            "::ffff:169.254.169.254",
            "::ffff:a9fe:a9fe",
            // NAT64, which genuinely reaches the IPv4 wherever the translation exists.
            "64:ff9b::169.254.169.254",
            // Obsolete IPv4-compatible form, still accepted by the stacks.
            "::169.254.169.254",
            "fe80::1"
        })
        void refusesLinkLocalEverySpelling(String address) {
            // Nothing legitimate lives in 169.254.0.0/16, and it is precisely the address the
            // attack wants: the metadata endpoint hands out the host's credentials.
            for (OutboundPolicy policy : OutboundPolicy.values()) {
                assertThatThrownBy(() -> guardResolving(address).validate("http://host/", policy, "Setting"))
                        .as("policy %s", policy)
                        .isInstanceOf(UnsafeUrlException.class)
                        .hasMessageContaining("link-local");
            }
        }
    }

    @Nested
    @DisplayName("a public destination is expected")
    class PublicOnly {

        @ParameterizedTest(name = "refuses {0}")
        @ValueSource(strings = {
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            // Carrier-grade NAT, which InetAddress's own predicates do not classify.
            "100.64.0.1",
            "198.18.0.1",
            "::1",
            "fc00::1",
            "::ffff:127.0.0.1"
        })
        void refusesInternalAddresses(String address) {
            assertThatThrownBy(() -> guardResolving(address).validate("https://host/", OutboundPolicy.PUBLIC_ONLY, "Webhook"))
                    .isInstanceOf(UnsafeUrlException.class);
        }

        @Test
        @DisplayName("accepts a public address")
        void acceptsPublic() {
            assertThat(guardResolving("93.184.216.34").validate("https://example.com/hook", OutboundPolicy.PUBLIC_ONLY, "Webhook"))
                    .isEqualTo("https://example.com/hook");
        }

        @Test
        @DisplayName("refuses a name that resolves to both a public and a private address")
        void checksEveryResolvedAddress() {
            // Checking only the first answer lets the other through, which is the entire point
            // of resolving them all.
            assertThatThrownBy(() -> guardResolving("93.184.216.34", "10.0.0.1")
                            .validate("https://host/", OutboundPolicy.PUBLIC_ONLY, "Webhook"))
                    .isInstanceOf(UnsafeUrlException.class);
        }
    }

    @Nested
    @DisplayName("an internal destination is expected — the endpoint receives source code")
    class InternalRequired {

        @Test
        @DisplayName("refuses a well-formed public URL, which no anti-SSRF check would flag")
        void refusesPublic() {
            // The mirror image of the webhook rule. Ollama receives the scanned repository's
            // source: the risk is that the URL points outward, and a public URL is exactly what
            // an exfiltration channel looks like.
            assertThatThrownBy(() -> guardResolving("93.184.216.34")
                            .validate("https://evil.example.com/", OutboundPolicy.INTERNAL_REQUIRED, "Ollama"))
                    .isInstanceOf(UnsafeUrlException.class)
                    .hasMessageContaining("receives source code");
        }

        @Test
        @DisplayName("accepts loopback")
        void acceptsLoopback() {
            assertThat(guardResolving("127.0.0.1")
                            .validate("http://localhost:11434", OutboundPolicy.INTERNAL_REQUIRED, "Ollama"))
                    .isEqualTo("http://localhost:11434");
        }

        @Test
        @DisplayName("refuses an unresolvable host rather than failing open")
        void refusesUnresolvable() {
            // Failing open is defensible for "is this private?". It is not defensible for
            // "this must be private": an unresolvable name proves nothing.
            assertThatThrownBy(() -> NO_DNS.validate("http://ollama.internal", OutboundPolicy.INTERNAL_REQUIRED, "Ollama"))
                    .isInstanceOf(UnsafeUrlException.class)
                    .hasMessageContaining("could not be resolved");
        }
    }

    @Nested
    @DisplayName("the non-throwing variant")
    class Reason {

        @Test
        @DisplayName("gives the reason, or nothing at all")
        void reportsWithoutThrowing() {
            assertThat(guardResolving("93.184.216.34").unsafeReason("https://example.com", OutboundPolicy.PUBLIC_ONLY, "Webhook"))
                    .isEmpty();
            assertThat(guardResolving("10.0.0.1").unsafeReason("https://host", OutboundPolicy.PUBLIC_ONLY, "Webhook"))
                    .isPresent();
        }
    }
}
