package com.asmolabs.vectispire.common.domain.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.crypto.SecretCipher.Decrypted;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher.SecretState;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Local KMS Provider")
class LocalKmsProviderTest {

    private static final String KEY_CURRENT = EncryptionKey.generate();
    private static final String KEY_PREVIOUS = EncryptionKey.generate();

    @Test
    @DisplayName("encrypts and decrypts with current key")
    void encryptAndDecryptCurrentKey() {
        EncryptionKey current = EncryptionKey.derive(KEY_CURRENT);
        LocalKmsProvider provider = new LocalKmsProvider(Optional.of(current), List.of(current));

        String plainText = "super-secret-ssh-key";
        String context = "ssh_key:42:private_key";

        String encrypted = provider.encrypt(plainText, context);
        assertThat(encrypted).startsWith("v2:");

        Optional<String> decrypted = provider.decrypt(encrypted, context);
        assertThat(decrypted).contains(plainText);

        Decrypted inspected = provider.inspect(encrypted, context);
        assertThat(inspected.plainText()).isEqualTo(plainText);
        assertThat(inspected.state()).isEqualTo(SecretState.CURRENT);
    }

    @Test
    @DisplayName("decrypts secrets encrypted with previous key during rotation")
    void decryptsWithPreviousKey() {
        EncryptionKey current = EncryptionKey.derive(KEY_CURRENT);
        EncryptionKey previous = EncryptionKey.derive(KEY_PREVIOUS);

        LocalKmsProvider oldProvider = new LocalKmsProvider(Optional.of(previous), List.of(previous));
        String encryptedWithOld = oldProvider.encrypt("old-secret", "ctx:1");

        LocalKmsProvider rotatedProvider = new LocalKmsProvider(Optional.of(current), List.of(current, previous));
        Decrypted inspected = rotatedProvider.inspect(encryptedWithOld, "ctx:1");

        assertThat(inspected.plainText()).isEqualTo("old-secret");
        assertThat(inspected.state()).isEqualTo(SecretState.PREVIOUS_KEY);
    }

    @Test
    @DisplayName("refuses to encrypt when no current key is configured")
    void unconfiguredRefusesToEncrypt() {
        LocalKmsProvider unconfigured = new LocalKmsProvider(Optional.empty(), List.of());
        assertThat(unconfigured.isConfigured()).isFalse();
        assertThatThrownBy(() -> unconfigured.encrypt("plain", "ctx"))
                .isInstanceOf(IllegalStateException.class);
    }
}
