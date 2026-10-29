package com.asmolabs.vectispire.core.golden;

import com.asmolabs.vectispire.common.domain.crypto.CosignSigner;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;

/**
 * The suite's document signing key, {@code vectispire.signing.key}: a fixture, the same at every run and on both
 * sides of the replay.
 *
 * <p><b>Why a fixed key.</b> The context used to generate one at start, so a signature it made — the one {@code
 * CryptoRoutesTest} sends to {@code /api/v1/crypto/verify} — verified under that run's key only: the replay, holding
 * a key of its own, could not accept it, and the recorder hid it anyway, as every random base64 run. With the key
 * fixed, the signature and the public key are recorded as they are (they are not secrets: README.md beside this
 * class), and the replay configures the same key — {@code crates/cp-agents/tests/golden.rs} builds it from
 * {@link #SCALAR} the same way. The stored-key path the context no longer takes is {@code SigningKeyServiceTest}'s.
 *
 * <p><b>Not a secret, on purpose.</b> Its scalar is thirty-two ASCII bytes anyone can read here; it signs nothing
 * but test documents. No deployment can end up with it: the property is set by the test context only.
 */
public final class FixtureSigningKey {

    /** The private scalar, big-endian: these thirty-two bytes, below P-256's order as any ASCII text is. */
    public static final String SCALAR = "vectispire golden replay fixture";

    private FixtureSigningKey() {}

    /** PKCS#8 PEM, as a deployment writes it into {@code vectispire.signing.key}. */
    public static String pem() {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance(CosignSigner.KEY_ALGORITHM);
            parameters.init(new ECGenParameterSpec(CosignSigner.CURVE_NAME));
            ECParameterSpec curve = parameters.getParameterSpec(ECParameterSpec.class);
            BigInteger scalar = new BigInteger(1, SCALAR.getBytes(StandardCharsets.US_ASCII));
            return CosignSigner.toPem(KeyFactory.getInstance(CosignSigner.KEY_ALGORITHM)
                    .generatePrivate(new ECPrivateKeySpec(scalar, curve)));
        } catch (java.security.GeneralSecurityException impossible) {
            throw new IllegalStateException("P-256 is not available", impossible);
        }
    }
}
