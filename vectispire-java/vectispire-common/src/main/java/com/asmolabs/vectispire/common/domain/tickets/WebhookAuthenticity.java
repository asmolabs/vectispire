package com.asmolabs.vectispire.common.domain.tickets;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Optional;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Whether an inbound ticketing webhook really came from the tracker.
 *
 * <p><b>The route it guards is anonymous by necessity and mutating by design.</b> Jira holds no
 * session, so the endpoint cannot require one; and what it does on arrival is move a triage
 * decision — closing a finding, reopening it — which is the outcome the four-eyes workflow exists
 * to make deliberate. Without this, an anonymous caller who guesses a ticket reference decides
 * what the backlog says.
 *
 * <p><b>Three shapes because the trackers have three conventions</b>, not because more felt safer:
 *
 * <ul>
 *   <li>GitLab sends the secret verbatim in {@code X-Gitlab-Token}. Compared, not hashed — there
 *       is nothing to hash it against.
 *   <li>GitHub sends {@code X-Hub-Signature-256}: {@code sha256=} followed by HMAC-SHA256 over the
 *       exact bytes it posted. The <em>raw</em> body, which is why the controller keeps the string
 *       it received rather than re-serialising what it parsed.
 *   <li>Jira and ServiceNow have no convention, so a shared token in {@code X-Vectispire-Token} is
 *       accepted for those two and for nothing else.
 * </ul>
 *
 * <p><b>Comparison is constant-time throughout.</b> A webhook secret is guessable one byte at a
 * time by anybody who can measure a response, and this endpoint answers unauthenticated callers
 * by design.
 *
 * <p><b>An unset secret closes the route.</b> It used to leave it open, on the grounds that
 * refusing unsigned calls on upgrade would stop existing deployments synchronising without anyone
 * seeing it. The cost of that default was an anonymous door that queued a "not affected" for any
 * ticket reference somebody guessed, on every deployment whose administrator had not found the
 * setting — which was nearly all of them. The tracker now receives a 403 saying the webhook is not
 * configured, in its own delivery log, which is where a broken integration is looked for.
 */
public final class WebhookAuthenticity {

    private WebhookAuthenticity() {}

    /** What the caller presented, in whichever of the three forms its tracker uses. */
    public record Presented(String gitlabToken, String githubSignature, String sharedToken) {}

    public enum Verdict {
        /** No secret configured: nothing is accepted until one is. */
        NOT_CONFIGURED,
        ACCEPTED,
        REJECTED
    }

    public static Verdict verify(
            TicketProvider provider, String configuredSecret, Presented presented, String rawBody) {

        if (configuredSecret == null || configuredSecret.isBlank()) {
            return Verdict.NOT_CONFIGURED;
        }

        boolean ok = switch (provider) {
            case GITLAB -> constantTimeEquals(configuredSecret, presented.gitlabToken());
            case GITHUB -> constantTimeEquals(
                    "sha256=" + hmacSha256Hex(configuredSecret, rawBody), presented.githubSignature());
            // Jira and ServiceNow sign nothing, so the shared token is the only thing to check.
            default -> constantTimeEquals(configuredSecret, presented.sharedToken());
        };

        return ok ? Verdict.ACCEPTED : Verdict.REJECTED;
    }

    /**
     * HMAC-SHA256, lower-case hex.
     *
     * <p>Exposed for the test that pins the wire format: a signature that is right about the
     * bytes and wrong about the encoding fails in production and passes a round-trip test that
     * uses this method on both sides.
     */
    public static String hmacSha256Hex(String secret, String body) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(
                    (body == null ? "" : body).getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.GeneralSecurityException impossible) {
            // Both the algorithm and the key shape are fixed here; a failure would mean the JVM
            // has no HMAC-SHA256, which is not a condition to degrade gracefully around.
            throw new IllegalStateException("HMAC-SHA256 unavailable", impossible);
        }
    }

    private static boolean constantTimeEquals(String expected, String presented) {
        return Optional.ofNullable(presented)
                .map(value -> MessageDigest.isEqual(
                        expected.getBytes(StandardCharsets.UTF_8), value.getBytes(StandardCharsets.UTF_8)))
                .orElse(false);
    }
}
