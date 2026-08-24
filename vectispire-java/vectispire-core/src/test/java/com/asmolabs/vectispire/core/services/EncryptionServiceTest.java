package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.crypto.EncryptionKey;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher.SecretState;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("encryption at rest, as the environment configures it")
class EncryptionServiceTest {

    private static final String CONTEXT = "ssh_key:7";

    // Deliberately 32-byte base64 keys rather than passphrases: scrypt costs a hundred
    // milliseconds per derivation, and this suite constructs a service per test.
    private static final String CURRENT = EncryptionKey.generate();
    private static final String PREVIOUS = EncryptionKey.generate();

    @Test
    void roundTripsUnderTheCurrentKey() {
        EncryptionService service = service(CURRENT, List.of());

        String secret = "ssh-rsa-test-private-key-material";
        String encrypted = service.encrypt(secret, CONTEXT);

        assertThat(encrypted).doesNotContain("test-private-key");
        assertThat(service.inspect(encrypted, CONTEXT))
                .returns(secret, d -> d.plainText())
                .returns(SecretState.CURRENT, d -> d.state());
    }

    @Test
    @DisplayName("a value written under the old key still reads, and says so")
    void reportsAValueThatHasNotBeenRotated() {
        String written = service(PREVIOUS, List.of()).encrypt("deployment key", CONTEXT);

        // The state is the whole point: rotation is not finished until nothing reports
        // PREVIOUS_KEY, and that is a screen, not a log line.
        assertThat(service(CURRENT, List.of(PREVIOUS)).inspect(written, CONTEXT))
                .returns("deployment key", d -> d.plainText())
                .returns(SecretState.PREVIOUS_KEY, d -> d.state());
    }

    @Test
    @DisplayName("the current key is never reported as previous, even when listed twice")
    void deduplicatesTheConfiguredKeys() {
        EncryptionService service = service(CURRENT, List.of(CURRENT, PREVIOUS));

        assertThat(service.inspect(service.encrypt("secret", CONTEXT), CONTEXT).state())
                .isEqualTo(SecretState.CURRENT);
    }

    @Test
    @DisplayName("a value relocated to another row does not read")
    void bindsTheCiphertextToItsContext() {
        EncryptionService service = service(CURRENT, List.of());

        String encrypted = service.encrypt("deployment key", CONTEXT);

        assertThat(service.inspect(encrypted, "ssh_key:8").state()).isEqualTo(SecretState.UNREADABLE);
    }

    @Test
    @DisplayName("with no key configured, reading keeps working and writing refuses")
    void readsWithoutAKeyAndRefusesToWrite() {
        String written = service(CURRENT, List.of()).encrypt("deployment key", CONTEXT);
        EncryptionService unconfigured = service(null, List.of(CURRENT));

        assertThat(unconfigured.isConfigured()).isFalse();
        assertThat(unconfigured.inspect(written, CONTEXT).plainText()).isEqualTo("deployment key");
        assertThatThrownBy(() -> unconfigured.encrypt("new secret", CONTEXT))
                .isInstanceOf(MissingEncryptionKeyException.class);
    }

    @Test
    @DisplayName("an empty value is left alone rather than refused")
    void anEmptyValueNeedsNoKey() {
        // A repository with no deployment key must still be saveable on a deployment that has
        // not configured encryption yet.
        assertThat(service(null, List.of()).encrypt("", CONTEXT)).isEmpty();
    }

    @Test
    void anUnreadableValueYieldsNoPlainText() {
        assertThat(service(CURRENT, List.of()).inspect("v2:not-even-base64", CONTEXT))
                .returns("", d -> d.plainText())
                .returns(SecretState.UNREADABLE, d -> d.state());
    }

    private static EncryptionService service(String key, List<String> previous) {
        return new EncryptionService(new EncryptionProperties(Optional.ofNullable(key), previous));
    }
}
