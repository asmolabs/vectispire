package com.asmolabs.vectispire.common.domain.crypto;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

/**
 * The signature an agent puts on a scan result, and what makes it worth checking.
 *
 * <h2>The thing this protects</h2>
 *
 * <p>Handing back a result is the highest-integrity operation in Vectispire. A result whose
 * artifacts are <em>present and empty</em> means "analysed, found nothing", which resolves every
 * open issue of that type on the target — silently, by design, and correctly
 * ({@code 0007-none-is-not-an-empty-list}). Whoever can post one can therefore make a target's
 * vulnerabilities disappear from every screen, every export and every gate verdict, and the only
 * trace is a scan that looks like it ran.
 *
 * <p>Until now the sole control on that operation was the agent's API key. A key is a bearer
 * token: it sits in a compose file, an environment variable, a CI secret store, and it travels
 * on every poll. Losing one is the ordinary accident this class exists for.
 *
 * <h2>Why the key cannot be one the agent announces</h2>
 *
 * <p>{@link SealedEnvelope} works the other way round — the agent publishes an ephemeral public
 * key on every {@code hello} and the control plane seals for it. That is right for
 * confidentiality: the recipient is whoever is running, and a restarted agent is a new recipient.
 *
 * <p>It would be worthless here. A signature verified against a key the <em>signer announced over
 * the same channel</em> proves only that the announcer and the signer are the same party — which
 * the bearer token already proved. Whoever steals the API key announces their own key and signs
 * with it.
 *
 * <p>So the signing key is <b>pinned by an operator</b>, out of band, on the agent's row. The
 * agent holds the private half in its own configuration; the control plane holds the public half
 * and never accepts a change to it over the agent protocol. That is the whole point: a stolen API
 * key claims tasks and burns CPU, but it cannot declare a target clean.
 *
 * <h2>What is signed</h2>
 *
 * <p>{@code "vectispire:agent-result:v1" ‖ scanId ‖ sha256(body)}, over the <b>exact bytes</b> the
 * agent sent. Two things are bound deliberately:
 *
 * <ul>
 *   <li><b>The scan id</b>, so a legitimately signed empty result cannot be replayed onto another
 *       scan. Without it, one captured "nothing found" would resolve any target it was replayed
 *       against.
 *   <li><b>The raw body, not the parsed object.</b> Signing a re-serialization would mean the
 *       signature covers what the server chose to write rather than what the agent chose to send,
 *       and the two differ on field order, absent-versus-null and number formatting — the three
 *       places where a signature quietly stops covering anything.
 * </ul>
 *
 * <p>Ed25519 through BouncyCastle's lightweight API, for the reason given in {@link Digests}:
 * which implementation runs should not be a property of the host.
 */
public final class ResultAttestation {

    /** The header the signature travels in. Named here because both sides read this constant. */
    public static final String HEADER = "X-Vectispire-Agent-Signature";

    /** Separates this signature from anything else ever signed by the same key. */
    private static final byte[] CONTEXT = "vectispire:agent-result:v1".getBytes(StandardCharsets.UTF_8);

    private static final int SEED_LENGTH_BYTES = Ed25519PrivateKeyParameters.KEY_SIZE;
    private static final int PUBLIC_LENGTH_BYTES = Ed25519PublicKeyParameters.KEY_SIZE;
    private static final int SIGNATURE_LENGTH_BYTES = Ed25519PrivateKeyParameters.SIGNATURE_SIZE;

    private ResultAttestation() {}

    /**
     * A pair to hand to an operator: the private half goes in the agent's configuration, the
     * public half on the agent's row.
     *
     * @param privateKey base64 of the 32-byte seed. <b>Shown once</b> — the control plane never
     *     stores it, and cannot show it again
     * @param publicKey base64 of the 32-byte public key
     */
    public record KeyPair(String privateKey, String publicKey) {}

    public static KeyPair generate() {
        byte[] seed = new byte[SEED_LENGTH_BYTES];
        new SecureRandom().nextBytes(seed);
        Ed25519PrivateKeyParameters priv = new Ed25519PrivateKeyParameters(seed, 0);
        return new KeyPair(
                Base64.getEncoder().encodeToString(seed),
                Base64.getEncoder().encodeToString(priv.generatePublicKey().getEncoded()));
    }

    /**
     * Is this a public key this class could ever verify against?
     *
     * <p>Asked before storing rather than at the first verification: a key that is 31 bytes long
     * because somebody trimmed a character would otherwise be accepted by the administration
     * screen and refuse every result afterwards, with the failure showing up on the agent.
     */
    public static boolean isUsablePublicKey(String base64) {
        return decode(base64, PUBLIC_LENGTH_BYTES).isPresent();
    }

    public static boolean isUsablePrivateKey(String base64) {
        return decode(base64, SEED_LENGTH_BYTES).isPresent();
    }

    /** @throws IllegalArgumentException when the configured key is not a 32-byte seed */
    public static String sign(String base64PrivateKey, long scanId, byte[] body) {
        byte[] seed = decode(base64PrivateKey, SEED_LENGTH_BYTES)
                .orElseThrow(() -> new IllegalArgumentException(
                        "The configured result-signing key is not 32 bytes of base64."));

        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, new Ed25519PrivateKeyParameters(seed, 0));
        byte[] message = message(scanId, body);
        signer.update(message, 0, message.length);
        return Base64.getEncoder().encodeToString(signer.generateSignature());
    }

    /**
     * <b>False, never an exception.</b> Every way this can fail — no signature, a malformed one, a
     * key that does not match, a body altered on the way — is one refusal with one meaning, and
     * telling them apart from the outside says which of the four the caller got right.
     */
    public static boolean verify(String base64PublicKey, long scanId, byte[] body, String base64Signature) {
        Optional<byte[]> key = decode(base64PublicKey, PUBLIC_LENGTH_BYTES);
        Optional<byte[]> signature = decode(base64Signature, SIGNATURE_LENGTH_BYTES);
        if (key.isEmpty() || signature.isEmpty() || body == null) {
            return false;
        }

        try {
            Ed25519Signer verifier = new Ed25519Signer();
            verifier.init(false, new Ed25519PublicKeyParameters(key.get(), 0));
            byte[] message = message(scanId, body);
            verifier.update(message, 0, message.length);
            return verifier.verifySignature(signature.get());
        } catch (RuntimeException rejected) {
            // BouncyCastle raises on a point that is not on the curve. That is a refusal like any
            // other here.
            return false;
        }
    }

    /**
     * The bytes both sides sign.
     *
     * <p>The body is hashed rather than signed directly so that a multi-megabyte SBOM is not held
     * in a second buffer inside the signer — and because the separator discipline of
     * {@link Digests} then applies to a fixed-length field, which is what keeps
     * {@code scanId=1, hash="2…"} from colliding with {@code scanId=12, hash="…"}.
     */
    private static byte[] message(long scanId, byte[] body) {
        return Digests.sha256(
                CONTEXT,
                separator(),
                Long.toString(scanId).getBytes(StandardCharsets.UTF_8),
                separator(),
                Digests.sha256(body));
    }

    private static byte[] separator() {
        return new byte[] {(byte) Digests.SEPARATOR};
    }

    private static Optional<byte[]> decode(String base64, int expectedLength) {
        if (base64 == null || base64.isBlank()) {
            return Optional.empty();
        }
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(base64.trim());
        } catch (IllegalArgumentException notBase64) {
            return Optional.empty();
        }
        return raw.length == expectedLength ? Optional.of(raw) : Optional.empty();
    }
}
