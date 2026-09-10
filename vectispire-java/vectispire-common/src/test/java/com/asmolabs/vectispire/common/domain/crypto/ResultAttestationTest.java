package com.asmolabs.vectispire.common.domain.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("A scan result's attestation")
class ResultAttestationTest {

    private static final byte[] BODY =
            "{\"dependencies\":[],\"sast\":[]}".getBytes(StandardCharsets.UTF_8);

    @Test
    @DisplayName("verifies against the key that signed it")
    void roundTrip() {
        ResultAttestation.KeyPair pair = ResultAttestation.generate();

        String signature = ResultAttestation.sign(pair.privateKey(), 42L, BODY);

        assertThat(ResultAttestation.verify(pair.publicKey(), 42L, BODY, signature)).isTrue();
    }

    /**
     * The reason the scan id is in the signed message.
     *
     * <p>An empty result is the most valuable thing to replay: it resolves a target's whole
     * backlog. Without this binding, one captured "nothing found" would do it to every scan it
     * was replayed against.
     */
    @Test
    @DisplayName("does not verify against another scan — a captured empty result cannot be replayed")
    void boundToTheScan() {
        ResultAttestation.KeyPair pair = ResultAttestation.generate();

        String signature = ResultAttestation.sign(pair.privateKey(), 42L, BODY);

        assertThat(ResultAttestation.verify(pair.publicKey(), 43L, BODY, signature)).isFalse();
    }

    @Test
    @DisplayName("does not verify when a single byte of the body changed")
    void boundToTheBody() {
        ResultAttestation.KeyPair pair = ResultAttestation.generate();
        String signature = ResultAttestation.sign(pair.privateKey(), 42L, BODY);

        byte[] altered = "{\"dependencies\":[],\"sast\":[ ]}".getBytes(StandardCharsets.UTF_8);

        assertThat(ResultAttestation.verify(pair.publicKey(), 42L, altered, signature)).isFalse();
    }

    @Test
    @DisplayName("does not verify against a different agent's key")
    void boundToTheKey() {
        ResultAttestation.KeyPair mine = ResultAttestation.generate();
        ResultAttestation.KeyPair theirs = ResultAttestation.generate();

        String signature = ResultAttestation.sign(mine.privateKey(), 42L, BODY);

        assertThat(ResultAttestation.verify(theirs.publicKey(), 42L, BODY, signature)).isFalse();
    }

    /**
     * Every malformed input is one refusal.
     *
     * <p>Asserted as a group because the property under test is that none of them <em>throws</em>:
     * a verification that raises on a truncated header turns a refusal into a 500, and a 500 is
     * an outage rather than a denial.
     */
    @Test
    @DisplayName("refuses rather than raising on anything malformed")
    void malformedIsARefusal() {
        ResultAttestation.KeyPair pair = ResultAttestation.generate();
        String signature = ResultAttestation.sign(pair.privateKey(), 42L, BODY);

        assertThat(ResultAttestation.verify(pair.publicKey(), 42L, BODY, null)).isFalse();
        assertThat(ResultAttestation.verify(pair.publicKey(), 42L, BODY, "")).isFalse();
        assertThat(ResultAttestation.verify(pair.publicKey(), 42L, BODY, "not base64 at all")).isFalse();
        assertThat(ResultAttestation.verify(pair.publicKey(), 42L, BODY, "c2hvcnQ=")).isFalse();
        assertThat(ResultAttestation.verify(null, 42L, BODY, signature)).isFalse();
        assertThat(ResultAttestation.verify("c2hvcnQ=", 42L, BODY, signature)).isFalse();
        assertThat(ResultAttestation.verify(pair.publicKey(), 42L, null, signature)).isFalse();
    }

    @Test
    @DisplayName("recognises a usable key by its decoded length, not by its shape")
    void keyShape() {
        ResultAttestation.KeyPair pair = ResultAttestation.generate();

        assertThat(ResultAttestation.isUsablePublicKey(pair.publicKey())).isTrue();
        assertThat(ResultAttestation.isUsablePrivateKey(pair.privateKey())).isTrue();

        // 44 base64 characters that do not decode to 32 bytes: the case a length check on the
        // string would let through.
        assertThat(ResultAttestation.isUsablePublicKey("c2hvcnQ=")).isFalse();
        assertThat(ResultAttestation.isUsablePublicKey("")).isFalse();
        assertThat(ResultAttestation.isUsablePublicKey(null)).isFalse();
    }

    @Test
    @DisplayName("generates a distinct pair every time")
    void freshPairs() {
        assertThat(ResultAttestation.generate().privateKey())
                .isNotEqualTo(ResultAttestation.generate().privateKey());
    }
}
