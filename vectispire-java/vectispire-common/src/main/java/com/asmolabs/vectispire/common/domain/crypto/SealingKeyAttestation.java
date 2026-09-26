package com.asmolabs.vectispire.common.domain.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

/**
 * The signature an agent puts on the sealing key it announces, and what the control plane checks
 * before sealing anything for it.
 *
 * <h2>What an unsigned announcement allowed</h2>
 *
 * <p>{@link SealedEnvelope} keeps a delegated credential from a TLS-terminating proxy: the agent
 * announces an X25519 public key, the control plane seals for it, and only the agent's process can
 * open the envelope. That holds only if the key the control plane seals for is the agent's. An
 * announcement carried by the very channel the sealing distrusts proves nothing about who made it:
 * whoever sits on that channel can replace it with a key of their own, or remove it. Sealing was
 * therefore only as strong as the proxy's honesty — the one party it was written to exclude.
 *
 * <h2>Why the result-signing key vouches for it</h2>
 *
 * <p>The agent already holds a key the control plane did <em>not</em> learn over the agent protocol:
 * the Ed25519 key an administrator pins for {@link ResultAttestation}. Signing the sealing key with
 * it moves the trust to that out-of-band step. A proxy can still read the announcement, and it can
 * still drop it, but it cannot produce one the control plane accepts. No pinned key, nothing to
 * verify against — and the control plane then delegates nothing at all (decision 0031).
 *
 * <h2>What is signed</h2>
 *
 * <p>{@code sha256("vectispire:agent-sealing-key:v1" ‖ agentId ‖ generation ‖ sha256(key))},
 * separated by {@link Digests#SEPARATOR}, and each part is there for a reason:
 *
 * <ul>
 *   <li><b>Its own context string</b>, distinct from the result's. The same Ed25519 key signs both,
 *       and without it a result signature could be presented as a key announcement or the reverse:
 *       the two messages are then digests of different prefixes, and one cannot stand for the other.
 *   <li><b>The agent's id</b>, so an announcement made for one agent cannot be replayed onto
 *       another that an operator configured with the same signing key.
 *   <li><b>The generation</b> — the time the pair was made, in epoch milliseconds — so an old
 *       announcement cannot be replayed to bring back a key the agent no longer holds, or one
 *       whose private half has leaked since. The control plane keeps the newest it accepted.
 *   <li><b>The key's decoded bytes</b>, not its base64 spelling, which is what the envelope is
 *       sealed to.
 * </ul>
 *
 * <p>Ed25519 through BouncyCastle's lightweight API, for the reason given in {@link Digests}.
 */
public final class SealingKeyAttestation {

    /** Separates this signature from the result attestation made with the same key. */
    private static final byte[] CONTEXT = "vectispire:agent-sealing-key:v1".getBytes(StandardCharsets.UTF_8);

    private static final int SEED_LENGTH_BYTES = Ed25519PrivateKeyParameters.KEY_SIZE;
    private static final int PUBLIC_LENGTH_BYTES = Ed25519PublicKeyParameters.KEY_SIZE;
    private static final int SIGNATURE_LENGTH_BYTES = Ed25519PrivateKeyParameters.SIGNATURE_SIZE;

    private SealingKeyAttestation() {}

    /**
     * @param base64PrivateKey the agent's result-signing seed, the one whose public half is pinned
     * @param sealingPublicKey base64 of the X25519 SPKI encoding, as {@link SealedEnvelope} writes it
     * @throws IllegalArgumentException when the seed is not 32 bytes, the sealing key is not a
     *     usable X25519 key or the generation is not positive — signing something the other side
     *     will refuse would only move the error there
     */
    public static String sign(String base64PrivateKey, UUID agentId, long generation, String sealingPublicKey) {
        byte[] seed = ResultAttestation.decode(base64PrivateKey, SEED_LENGTH_BYTES)
                .orElseThrow(() -> new IllegalArgumentException(
                        "The configured result-signing key is not 32 bytes of base64."));
        byte[] message = message(agentId, generation, sealingPublicKey)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Only a usable X25519 key, a known agent and a positive generation can be signed."));

        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, new Ed25519PrivateKeyParameters(seed, 0));
        signer.update(message, 0, message.length);
        return Base64.getEncoder().encodeToString(signer.generateSignature());
    }

    /**
     * <b>False, never an exception</b>, for the reason {@link ResultAttestation#verify} gives: every
     * way this fails is one refusal, and telling them apart tells a prober which part they got right.
     */
    public static boolean verify(
            String base64PublicKey, UUID agentId, long generation, String sealingPublicKey, String base64Signature) {
        Optional<byte[]> key = ResultAttestation.decode(base64PublicKey, PUBLIC_LENGTH_BYTES);
        Optional<byte[]> signature = ResultAttestation.decode(base64Signature, SIGNATURE_LENGTH_BYTES);
        Optional<byte[]> message = message(agentId, generation, sealingPublicKey);
        if (key.isEmpty() || signature.isEmpty() || message.isEmpty()) {
            return false;
        }

        try {
            Ed25519Signer verifier = new Ed25519Signer();
            verifier.init(false, new Ed25519PublicKeyParameters(key.get(), 0));
            verifier.update(message.get(), 0, message.get().length);
            return verifier.verifySignature(signature.get());
        } catch (RuntimeException rejected) {
            // A point that is not on the curve raises in BouncyCastle; here it is a refusal.
            return false;
        }
    }

    /** Empty when there is nothing a signature could honestly cover. */
    private static Optional<byte[]> message(UUID agentId, long generation, String sealingPublicKey) {
        if (agentId == null || generation <= 0 || !SealedEnvelope.isUsablePublicKey(sealingPublicKey)) {
            return Optional.empty();
        }
        byte[] separator = {(byte) Digests.SEPARATOR};
        return Optional.of(Digests.sha256(
                CONTEXT,
                separator,
                // The canonical, lower-case spelling: both sides hold a UUID, not the string they
                // were handed, so an upper-case id on the wire cannot make them sign different bytes.
                agentId.toString().getBytes(StandardCharsets.UTF_8),
                separator,
                Long.toString(generation).getBytes(StandardCharsets.UTF_8),
                separator,
                Digests.sha256(Base64.getDecoder().decode(sealingPublicKey))));
    }
}
