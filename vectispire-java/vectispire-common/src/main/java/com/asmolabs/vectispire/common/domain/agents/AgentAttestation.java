package com.asmolabs.vectispire.common.domain.agents;

import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Cryptographic attestation of scan results submitted by remote agents.
 *
 * <p>Ensures integrity and non-repudiation: an agent cryptographically signs the
 * SHA-256 fingerprint of the normalized scan artifacts using its assigned secret.
 */
public final class AgentAttestation {

    private AgentAttestation() {}

    /**
     * Computes HMAC-SHA256 over {@code <scanId>:<agentId>:<payloadHash>}.
     */
    public static String sign(long scanId, String agentId, byte[] payload, String secret) {
        if (secret == null || secret.isBlank() || payload == null) {
            return null;
        }

        String payloadHash = Digests.sha256Hex(payload);
        String data = scanId + ":" + (agentId == null ? "" : agentId) + ":" + payloadHash;

        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);

        HMac mac = new HMac(new SHA256Digest());
        mac.init(new KeyParameter(keyBytes));
        mac.update(dataBytes, 0, dataBytes.length);

        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);

        return HexFormat.of().formatHex(out);
    }

    /**
     * Verifies the signature in constant time.
     */
    public static boolean verify(long scanId, String agentId, byte[] payload, String secret, String signature) {
        if (signature == null || signature.isBlank()) {
            return false;
        }
        String expected = sign(scanId, agentId, payload, secret);
        return expected != null && SecretCipher.secretEquals(expected, signature.trim());
    }
}
