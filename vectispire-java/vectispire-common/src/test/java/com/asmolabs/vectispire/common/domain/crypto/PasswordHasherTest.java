package com.asmolabs.vectispire.common.domain.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("password hashing")
class PasswordHasherTest {

    @Test
    @DisplayName("verifies the password it hashed, and nothing near it")
    void roundTrips() {
        String hash = PasswordHasher.hash("correct-horse-battery-staple");

        assertThat(PasswordHasher.verify("correct-horse-battery-staple", hash)).isTrue();
        assertThat(PasswordHasher.verify("correct-horse-battery-stapl", hash)).isFalse();
    }

    @Test
    @DisplayName("salts, so the same password hashes differently twice")
    void saltsEachHash() {
        assertThat(PasswordHasher.hash("same")).isNotEqualTo(PasswordHasher.hash("same"));
    }

    @Test
    @DisplayName("hashes the whole password, however long it is")
    void doesNotTruncate() {
        // The defect this replaces: bcrypt silently ignores everything past 72 bytes, so two
        // passphrases sharing their first 72 bytes were the same password. Here they are not.
        String shared = "x".repeat(72);

        String hash = PasswordHasher.hash(shared + "-alice");

        assertThat(PasswordHasher.verify(shared + "-alice", hash)).isTrue();
        assertThat(PasswordHasher.verify(shared + "-bob", hash)).isFalse();
    }

    @Test
    @DisplayName("carries its parameters, so raising the cost does not invalidate what is stored")
    void encodesItsParameters() {
        assertThat(PasswordHasher.hash("secret")).startsWith("$argon2id$v=19$m=19456,t=2,p=1$");
    }

    @ParameterizedTest(name = "refuses [{0}] without throwing")
    @ValueSource(strings = {"", "not-a-hash", "$argon2id$broken", "$2b$12$abcdefghijklmnopqrstuv"})
    void malformedHashesFailClosed(String stored) {
        // A row with a corrupt hash must fail authentication, not take down the login
        // endpoint — and an attacker must not be able to tell the two apart.
        assertThat(PasswordHasher.verify("secret", stored)).isFalse();
    }

    @Test
    @DisplayName("a null password or hash is a refusal, not an exception")
    void nullsFailClosed() {
        assertThat(PasswordHasher.verify(null, PasswordHasher.hash("x"))).isFalse();
        assertThat(PasswordHasher.verify("x", null)).isFalse();
    }

    @Test
    @DisplayName("flags a hash weaker than the current parameters for rewriting")
    void detectsOutdatedParameters() {
        // Costs are raised as hardware gets faster, and a hash written five years ago stays
        // exactly as weak as the day it was written unless something notices. A successful
        // login is the one moment the plaintext is in hand.
        assertThat(PasswordHasher.needsRehash(PasswordHasher.hash("secret"))).isFalse();
        assertThat(PasswordHasher.needsRehash("$argon2id$v=19$m=4096,t=1,p=1$c2FsdHNhbHQ$aGFzaA")).isTrue();
        assertThat(PasswordHasher.needsRehash("$2b$12$whatever")).isTrue();
        assertThat(PasswordHasher.needsRehash(null)).isTrue();
    }
}
