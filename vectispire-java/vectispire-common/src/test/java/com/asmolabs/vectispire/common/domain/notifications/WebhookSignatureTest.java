package com.asmolabs.vectispire.common.domain.notifications;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The signature scheme, pinned.
 *
 * <p><b>These assertions are a contract with code that does not live here.</b> A receiver — a
 * script, a bus, a gateway — reimplements this from the documentation, so a change that keeps
 * Vectispire self-consistent still breaks every verifier in the field, silently, as a rejected
 * message somebody blames on the network. The literal values below are what makes that change
 * loud.
 */
@DisplayName("signing a webhook message")
class WebhookSignatureTest {

    private static final String SECRET = "a-shared-secret";
    private static final Instant AT = Instant.parse("2026-08-22T10:00:00Z");
    private static final String BODY = "{\"scan_id\":7}";

    @Test
    @DisplayName("the signed string is the timestamp, a full stop, then the exact body")
    void pinsTheSignedString() {
        // Spelt out because "concatenate them" is not a specification, and a receiver that guesses
        // the order or the separator computes a different MAC and rejects every message.
        assertThat(WebhookSignature.signedString("1787392800", BODY)).isEqualTo("1787392800." + BODY);
    }

    @Test
    @DisplayName("both headers are sent, and the signature names its algorithm")
    void sendsBothHeaders() {
        Map<String, String> headers = WebhookSignature.headers(SECRET, AT, BODY);

        assertThat(headers).containsOnlyKeys(WebhookSignature.TIMESTAMP_HEADER, WebhookSignature.SIGNATURE_HEADER);
        assertThat(headers.get(WebhookSignature.TIMESTAMP_HEADER)).isEqualTo("1787392800");
        assertThat(headers.get(WebhookSignature.SIGNATURE_HEADER))
                // The prefix is what lets a second algorithm be added later without a receiver
                // having to guess which one it is looking at.
                .startsWith("sha256=")
                .isEqualTo("sha256=" + WebhookSignature.hex(SECRET, "1787392800", BODY));
    }

    @Test
    @DisplayName("the timestamp is covered by the signature, or a receiver's replay window is the attacker's")
    void theTimestampIsSigned() {
        String atOneMoment = WebhookSignature.hex(SECRET, "1787392800", BODY);
        String atAnother = WebhookSignature.hex(SECRET, "1787392801", BODY);

        // If these were equal, an attacker could rewrite the timestamp header freely and replay a
        // captured message forever — which makes the header decorative rather than protective.
        assertThat(atOneMoment).isNotEqualTo(atAnother);
    }

    @Test
    @DisplayName("a changed body changes the signature")
    void theBodyIsSigned() {
        assertThat(WebhookSignature.hex(SECRET, "1787392800", BODY))
                .isNotEqualTo(WebhookSignature.hex(SECRET, "1787392800", "{\"scan_id\":8}"));
    }

    @Test
    @DisplayName("a different secret cannot produce the same signature")
    void theSecretIsTheKey() {
        assertThat(WebhookSignature.hex(SECRET, "1787392800", BODY))
                .isNotEqualTo(WebhookSignature.hex("another-secret", "1787392800", BODY));
    }

    @Test
    @DisplayName("no secret sends no headers, rather than a signature anybody could compute")
    void unsignedWhenNoSecret() {
        // A header computed with an empty key is worse than no header: it looks like
        // authentication and any receiver could reproduce it.
        assertThat(WebhookSignature.headers("", AT, BODY)).isEmpty();
        assertThat(WebhookSignature.headers("   ", AT, BODY)).isEmpty();
        assertThat(WebhookSignature.headers(null, AT, BODY)).isEmpty();
    }

    @Test
    @DisplayName("the MAC is HMAC-SHA256, against a vector computed outside this codebase")
    void isAKeyedMac() {
        // **A vector, not a round trip.** Asserting that this function equals itself would pass
        // over any algorithm, including `sha256(secret || message)` — which is length-extendable,
        // so a receiver verifying it accepts a message somebody appended to. These two are
        // openssl's answers, and they are how a receiver in any language checks its own
        // implementation:
        //
        //   printf '1.x' | openssl dgst -sha256 -hmac "key"
        //   printf '1787392800.{"scan_id":7}' | openssl dgst -sha256 -hmac "a-shared-secret"
        assertThat(WebhookSignature.hex("key", "1", "x"))
                .isEqualTo("fc4913c41a7bf793267e2a384f3261c9436ec2cd097bd745e7b0d99113f510ec");
        assertThat(WebhookSignature.hex(SECRET, "1787392800", BODY))
                .isEqualTo("32fb38fb4b21bff3e38440f9969b0789ae3d144277df3e7f3bb3d6d80957234b");
    }
}
