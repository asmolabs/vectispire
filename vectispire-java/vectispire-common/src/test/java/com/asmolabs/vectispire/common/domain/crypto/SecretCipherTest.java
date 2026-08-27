package com.asmolabs.vectispire.common.domain.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("secret encryption")
class SecretCipherTest {

    private final SecretCipher cipher = new SecretCipher();
    private final EncryptionKey key = EncryptionKey.derive(EncryptionKey.generate());
    private final EncryptionKey otherKey = EncryptionKey.derive(EncryptionKey.generate());

    /**
     * One ciphertext from 26 August 2026, and the reason it is not a round trip.
     *
     * <p><b>Every other test here re-encrypts before it decrypts.</b> They pin properties —
     * a fresh nonce each time, the context binding, another key refused — and every one of them
     * stays green through a change to the wire format, because both halves move together. What
     * breaks is the data already in the database, in production, on the day of the deployment.
     *
     * <p>So this vector is decrypt-only. It asks the one question the round trip cannot: <em>can
     * today's code still read what an earlier version wrote?</em> A changed AAD construction, a
     * different nonce length, a new version prefix — each would fail here and nowhere else.
     *
     * <p><b>If this fails, updating the constant is the wrong repair.</b> It means stored secrets
     * became unreadable, and what is owed is a migration that re-encrypts them, or a reader that
     * still understands the old format — the way {@code decryptWithAny} already carries a
     * previous key across a rotation.
     *
     * <p>The key is a fixture and says so in its own plaintext: base64 of
     * {@code kat-vector-key-not-a-secret-32by}.
     */
    @Nested
    @DisplayName("what was written before")
    class Compatibility {

        private static final String FIXTURE_KEY = "a2F0LXZlY3Rvci1rZXktbm90LWEtc2VjcmV0LTMyYnk=";
        private static final String WRITTEN_2026_08_26 =
                "v2:LWcoBNnyN+hImt21g9QgLg2vlCOV0SIoFDq1++9B/PTWxJREGSvBr9ldmQp+rsu5ix2ZoGtN4hYQ4G8=";

        @Test
        @DisplayName("a secret sealed by an earlier build still opens")
        void anOldCiphertextStillDecrypts() {
            EncryptionKey fixture = EncryptionKey.derive(FIXTURE_KEY);

            assertThat(cipher.decrypt(fixture, WRITTEN_2026_08_26, SecretCipher.privateKeyContext("k1")))
                    .contains("ssh-ed25519 AAAA-not-a-real-key");
        }

        @Test
        @DisplayName("and it is still bound to the context it was written under")
        void theOldCiphertextIsStillContextBound() {
            EncryptionKey fixture = EncryptionKey.derive(FIXTURE_KEY);

            // The pair matters: a vector that decrypted under any context would pass the test
            // above while proving the AAD had stopped being applied.
            assertThat(cipher.decrypt(fixture, WRITTEN_2026_08_26, SecretCipher.privateKeyContext("k2")))
                    .isEmpty();
        }
    }

    @Nested
    @DisplayName("round trip")
    class RoundTrip {

        @Test
        @DisplayName("reads back what it wrote")
        void roundTrips() {
            String secret = "ssh-rsa-test-private-key-material-xyz";
            String sealed = cipher.encrypt(key, secret, SecretCipher.privateKeyContext("k1"));

            assertThat(cipher.decrypt(key, sealed, SecretCipher.privateKeyContext("k1"))).contains(secret);
        }

        @Test
        @DisplayName("produces a different ciphertext every time")
        void nonceIsFresh() {
            // A repeated nonce under the same key is the one mistake GCM does not survive: it
            // leaks the XOR of the plaintexts and, worse, the authentication key itself.
            String first = cipher.encrypt(key, "same", null);
            String second = cipher.encrypt(key, "same", null);

            assertThat(first).isNotEqualTo(second);
        }

        @Test
        @DisplayName("carries a version prefix, so the next format change need not guess")
        void versionedFormat() {
            assertThat(cipher.encrypt(key, "x", null)).startsWith("v2:");
        }

        @Test
        @DisplayName("leaves an empty value alone")
        void emptyStaysEmpty() {
            assertThat(cipher.encrypt(key, "", null)).isEmpty();
        }
    }

    @Nested
    @DisplayName("what must not decrypt")
    class Refusals {

        @Test
        @DisplayName("a ciphertext moved to another row does not decrypt")
        void associatedDataBindsTheRow() {
            // The attack this defends against: somebody able to write to the database copies
            // key A's ciphertext into row B. Without associated data it decrypts cleanly, and
            // repository A gets cloned with B's key — silently.
            String sealed = cipher.encrypt(key, "private-key-a", SecretCipher.privateKeyContext("key-a"));

            assertThat(cipher.decrypt(key, sealed, SecretCipher.privateKeyContext("key-b"))).isEmpty();
        }

        @Test
        @DisplayName("a value written with a context does not read without one")
        void contextIsNotOptional() {
            String sealed = cipher.encrypt(key, "secret", SecretCipher.privateKeyContext("k1"));

            assertThat(cipher.decrypt(key, sealed, null)).isEmpty();
        }

        @Test
        @DisplayName("another key does not read it")
        void wrongKeyFails() {
            assertThat(cipher.decrypt(otherKey, cipher.encrypt(key, "secret", null), null)).isEmpty();
        }

        @Test
        @DisplayName("a single altered byte is refused, not silently decoded")
        void tamperingIsDetected() {
            // What AEAD buys over a bare cipher: without the tag this returns plausible
            // garbage, and the caller writes it to an SSH agent.
            String sealed = cipher.encrypt(key, "secret value", null);
            byte[] raw = Base64.getDecoder().decode(sealed.substring(3));
            raw[raw.length - 1] ^= 0x01;
            String tampered = "v2:" + Base64.getEncoder().encodeToString(raw);

            assertThat(cipher.decrypt(key, tampered, null)).isEmpty();
        }

        @Test
        @DisplayName("garbage is refused without throwing")
        void garbageIsEmptyNotAnException() {
            // The caller tries several keys in turn, so failure is the ordinary path. Throwing
            // would fill the log with stack traces nobody should act on.
            assertThat(cipher.decrypt(key, "not-encrypted-at-all", null)).isEmpty();
            assertThat(cipher.decrypt(key, "v2:!!!not-base64!!!", null)).isEmpty();
            assertThat(cipher.decrypt(key, "v2:c2hvcnQ=", null)).isEmpty();
        }
    }

    @Nested
    @DisplayName("key rotation")
    class Rotation {

        @Test
        @DisplayName("a value under the current key reports itself current")
        void currentKeyFirst() {
            String sealed = cipher.encrypt(key, "secret", null);

            assertThat(cipher.decryptWithAny(List.of(key, otherKey), sealed, null))
                    .isEqualTo(new SecretCipher.Decrypted("secret", SecretCipher.SecretState.CURRENT));
        }

        @Test
        @DisplayName("a value under an older key is readable and says so")
        void previousKeyIsReported() {
            // What drives the "re-encrypt these" prompt. A rotation that cannot tell which
            // values are still on the old key is a rotation nobody can finish.
            String sealed = cipher.encrypt(otherKey, "secret", null);

            assertThat(cipher.decryptWithAny(List.of(key, otherKey), sealed, null))
                    .isEqualTo(new SecretCipher.Decrypted("secret", SecretCipher.SecretState.PREVIOUS_KEY));
        }

        @Test
        @DisplayName("a value no key reads is unreadable, and does not pretend to be empty")
        void unreadableIsItsOwnState() {
            EncryptionKey lost = EncryptionKey.derive(EncryptionKey.generate());

            assertThat(cipher.decryptWithAny(List.of(key, otherKey), cipher.encrypt(lost, "secret", null), null).state())
                    .isEqualTo(SecretCipher.SecretState.UNREADABLE);
        }
    }

    @Nested
    @DisplayName("key derivation")
    class Derivation {

        @Test
        @DisplayName("32 base64 bytes are used as they are")
        void base64KeyIsUsedDirectly() {
            String material = EncryptionKey.generate();
            String sealed = new SecretCipher().encrypt(EncryptionKey.derive(material), "secret", null);

            assertThat(new SecretCipher().decrypt(EncryptionKey.derive(material), sealed, null)).contains("secret");
        }

        @Test
        @DisplayName("a passphrase is stretched, and two different ones do not collide")
        void passphrasesAreStretched() {
            String sealed = cipher.encrypt(EncryptionKey.derive("correct horse battery staple"), "secret", null);

            assertThat(cipher.decrypt(EncryptionKey.derive("correct horse battery staple"), sealed, null))
                    .contains("secret");
            assertThat(cipher.decrypt(EncryptionKey.derive("correct horse battery stapl"), sealed, null))
                    .isEmpty();
        }

        @Test
        @DisplayName("a 44-character string that is not base64 is treated as a passphrase")
        void lengthAloneIsNotAKey() {
            // A lenient decoder would return fewer than 32 bytes and the key would be weaker
            // than it looks, with nothing complaining. Falling through to scrypt is the safe
            // reading of an ambiguous value.
            String looksLikeAKey = "!".repeat(44);

            assertThat(cipher.decrypt(
                            EncryptionKey.derive(looksLikeAKey),
                            cipher.encrypt(EncryptionKey.derive(looksLikeAKey), "secret", null),
                            null))
                    .contains("secret");
        }

        @Test
        @DisplayName("the key never prints its material")
        void keyDoesNotLeakInToString() {
            // A key that prints itself ends up in a log, then an exception message, then a bug
            // report.
            assertThat(EncryptionKey.derive(EncryptionKey.generate()).toString()).isEqualTo("EncryptionKey[32 bytes]");
        }
    }

    @Nested
    @DisplayName("constant-time comparison")
    class ConstantTime {

        @Test
        @DisplayName("compares equal and unequal secrets correctly")
        void comparesCorrectly() {
            assertThat(SecretCipher.secretEquals("token", "token")).isTrue();
            assertThat(SecretCipher.secretEquals("token", "tokeN")).isFalse();
            assertThat(SecretCipher.secretEquals("token", "tokens")).isFalse();
            assertThat(SecretCipher.secretEquals("", "")).isTrue();
        }
    }
}
