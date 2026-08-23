package com.asmolabs.zanshin.common.domain.notifications;

import com.asmolabs.zanshin.common.domain.crypto.Digests;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Proof that a webhook message came from this Zanshin.
 *
 * <h2>What it is for</h2>
 *
 * <p>A webhook URL is a <b>bearer capability</b>: whoever knows it can post into the channel where
 * a team waits for Zanshin's alerts, which is exactly where a forged message carries most weight —
 * "no new vulnerabilities" is a lie somebody has an interest in telling. Zanshin already refuses to
 * return the URL from any route for that reason. This closes the other half: a receiver can tell a
 * message Zanshin sent from a message somebody who learned the URL sent.
 *
 * <p><b>Which receivers this actually helps, stated plainly.</b> A receiver has to check the
 * signature for it to be worth anything, and Slack, Teams and Discord will not — they accept
 * whatever arrives at an incoming webhook. So this is for the case the setting's help text names
 * first: a script, a bus, or a gateway of your own. Signing a message to Slack costs one header and
 * buys nothing; it is sent anyway rather than special-cased, because a rule about which
 * destinations get a header is a rule that will be wrong the day somebody puts a gateway in front
 * of Slack.
 *
 * <h2>The timestamp is inside the signature, not beside it</h2>
 *
 * <p>The signed string is {@code <unix seconds>.<body>}, and the timestamp travels in its own
 * header. Both halves matter. A receiver needs the timestamp to reject a message replayed weeks
 * later, and a timestamp that is not covered by the MAC is one an attacker rewrites freely — which
 * makes the replay window whatever they choose and the header decorative. It is also why the
 * signature cannot be computed over the body alone.
 *
 * <p>Replay <em>within</em> the window is closed by something already there: every payload carries
 * a {@code messageId}, because delivery is at-least-once and a receiver must dedupe on it anyway.
 *
 * <h2>The body signed is the body sent</h2>
 *
 * <p>This takes the <b>encoded</b> body, never an object to serialize. Signing one serialization
 * and sending another produces a signature that verifies nowhere, from two lines that both read
 * correctly — the same failure as validating one URL and connecting to another, which is why
 * {@code PinnedHttpSender} exists. {@code OutboundPost} therefore signs the exact string it is
 * about to write.
 */
public final class WebhookSignature {

    /** {@code sha256=<hex>}, prefixed so a second algorithm can be added without ambiguity. */
    public static final String SIGNATURE_HEADER = "X-Veriscape-Signature";

    /** Unix seconds. Covered by the signature — see the class comment. */
    public static final String TIMESTAMP_HEADER = "X-Veriscape-Timestamp";

    private static final String ALGORITHM_PREFIX = "sha256=";

    private WebhookSignature() {}

    /**
     * The headers to add, or none at all when no secret is configured.
     *
     * <p><b>Empty rather than a signature over an empty key.</b> Signing with no secret would put a
     * header on every message that any receiver could compute, which is worse than no header: it
     * looks like authentication.
     *
     * @param secret the shared secret, already decrypted. Blank means "not configured"
     */
    public static Map<String, String> headers(String secret, Instant at, String encodedBody) {
        if (secret == null || secret.isBlank()) {
            return Map.of();
        }

        String timestamp = String.valueOf(at.getEpochSecond());
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put(TIMESTAMP_HEADER, timestamp);
        headers.put(SIGNATURE_HEADER, ALGORITHM_PREFIX + hex(secret, timestamp, encodedBody));
        return Map.copyOf(headers);
    }

    /**
     * The signature's hex, for a receiver's own implementation and for the tests that pin the
     * scheme.
     *
     * <p>Public because the format is a contract with something outside this repository: a
     * receiver written against it must be able to be checked against the same function, and a
     * scheme that only exists inside a private method is a scheme that drifts.
     */
    public static String hex(String secret, String timestamp, String encodedBody) {
        return Digests.hmacSha256Hex(
                secret.getBytes(StandardCharsets.UTF_8), signedString(timestamp, encodedBody));
    }

    /**
     * What is actually run through the MAC.
     *
     * <p>The separator is a full stop and the timestamp comes first, so the two fields cannot be
     * confused by a body that begins with digits: the timestamp is read up to the first {@code .},
     * and a JSON body always begins with {@code &#123;}. Written down because a receiver has to
     * reproduce it exactly, and "concatenate them" is not a specification.
     */
    public static String signedString(String timestamp, String encodedBody) {
        return timestamp + "." + encodedBody;
    }
}
