package com.asmolabs.vectispire.core.golden;

import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.crypto.SealedEnvelope;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

/**
 * The agents' sealing key pairs the HTTP suites announce: three X25519 pairs, the same at every run, whose private
 * halves are thirty-two ASCII bytes anyone can read here. They seal nothing but test credentials.
 *
 * <p><b>Why fixed.</b> {@code AgentSealingKeyRoutesTest} drew a pair with {@link SealedEnvelope#generateKeyPair} at
 * every run, and the recorder hid the public half as it hides every random base64 run ({@code «secret:N»}): the
 * replay then sent a minted token where Java had sent an X25519 key, which no server accepts, and the signature over
 * it could not be made either. With the pairs fixed, the public halves are recorded as they are — {@link #isFixture},
 * by fingerprint, and no other key — and the signature the agent's pinned key makes over one is written as the
 * computation the replay repeats ({@code «sealing-signature:…»}, README.md beside this class).
 *
 * <p>The pair is built as {@link SealedEnvelope#generateKeyPair} builds one, from a chosen private half: the public
 * half is the same SPKI encoding, so the control plane reads it as it reads an agent's.
 */
public final class FixtureSealingKeys {

    /** How many there are: as many as one test announces distinct keys. */
    public static final int COUNT = 3;

    private static final List<SealedEnvelope.KeyPair> PAIRS =
            IntStream.rangeClosed(1, COUNT).mapToObj(FixtureSealingKeys::make).toList();

    private static final Set<String> FINGERPRINTS = PAIRS.stream()
            .map(pair -> Digests.sha256Hex(pair.publicKey()))
            .collect(Collectors.toUnmodifiableSet());

    private FixtureSealingKeys() {}

    /** The {@code n}th pair, from 1 to {@link #COUNT}: distinct pairs for the distinct keys one test announces. */
    public static SealedEnvelope.KeyPair pair(int n) {
        return PAIRS.get(n - 1);
    }

    /** Whether this public key, as an agent announces it, is one of the fixtures', by its SHA-256. */
    public static boolean isFixture(String publicKey) {
        return publicKey != null && FINGERPRINTS.contains(Digests.sha256Hex(publicKey));
    }

    /** The private half: {@code "vectispire sealing fixture no. N"}, thirty-two bytes. */
    private static SealedEnvelope.KeyPair make(int n) {
        byte[] seed = ("vectispire sealing fixture no. " + n).getBytes(StandardCharsets.US_ASCII);
        X25519PrivateKeyParameters privateKey = new X25519PrivateKeyParameters(seed, 0);
        try {
            String publicKey = Base64.getEncoder().encodeToString(SubjectPublicKeyInfoFactory
                    .createSubjectPublicKeyInfo(privateKey.generatePublicKey()).getEncoded());
            return new SealedEnvelope.KeyPair(publicKey, privateKey);
        } catch (IOException impossible) {
            throw new UncheckedIOException("An X25519 public key could not be encoded", impossible);
        }
    }
}
