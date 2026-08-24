package com.asmolabs.zanshin.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.zanshin.common.domain.crypto.EncryptionKey;
import com.asmolabs.zanshin.common.domain.crypto.SecretCipher.SecretState;
import com.asmolabs.zanshin.core.ZanshinContextTest;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * {@code ENCRYPTION_KEY_FILE}, through the whole chain a deployment actually uses.
 *
 * <p><b>Why this exists beside {@link EncryptionKeyFileTest}.</b> That suite calls {@code
 * resolved()} directly, so it proves the reading and every refusal — and it would pass just as
 * well with the variable misspelled in {@code application.yaml}, or with the property named
 * something {@code keyFile} does not bind from. Those are the two mistakes that produce an
 * application which starts, warns about no key in a log nobody reads, and refuses to save a
 * secret the day somebody tries.
 *
 * <p>So this one sets the variable by its real name and asks the wired {@link EncryptionService}
 * whether it has a key. Three links are covered at once: the placeholder in the yaml, the
 * relaxed binding onto the record component, and the resolution running before the service's
 * tolerance for a missing key applies.
 */
@DisplayName("the encryption key from a file, wired")
class EncryptionKeyFileDatabaseTest extends ZanshinContextTest {

    private static final String KEY = EncryptionKey.generate();

    /**
     * Written before the context starts, and with the trailing newline a real secret file has.
     *
     * <p>The name is the variable an operator sets — not the property — because the point of
     * this test is the chain between the two.
     */
    @DynamicPropertySource
    static void keyFromAFile(DynamicPropertyRegistry registry) {
        registry.add("ENCRYPTION_KEY_FILE", () -> secretFile().toString());
        // **The empty value is the production shape, not a way to silence the test profile.** The
        // yaml reads `key: ${ENCRYPTION_KEY:}`, so a deployment that sets only the file still
        // presents an empty string here — and reading that as "a value was supplied" is what made
        // the first version of this refuse to start on every correct configuration. The apitest
        // profile happens to set a key, which is what surfaced it.
        registry.add("zanshin.encryption.key", () -> "");
    }

    private static Path secretFile() {
        try {
            Path file = Path.of(
                    System.getProperty("java.io.tmpdir"), "zanshin-encryption-key-" + UUID.randomUUID());
            Files.writeString(file, KEY + "\n");
            file.toFile().deleteOnExit();
            return file;
        } catch (IOException cannotWrite) {
            throw new UncheckedIOException(cannotWrite);
        }
    }

    @Autowired
    private EncryptionService encryption;

    @Test
    @DisplayName("the application has a key, and it is the file's")
    void theFileIsRead() {
        // Without the chain intact this is `false`, the application starts anyway, and the first
        // person to notice is whoever tries to save an SSH key.
        assertThat(encryption.isConfigured()).isTrue();

        String cipherText = encryption.encrypt("a private key", "ssh_key:1:private_key");

        // CURRENT rather than PREVIOUS_KEY: the file supplied the *current* key, so a value just
        // written must not report itself as awaiting rotation.
        assertThat(encryption.inspect(cipherText, "ssh_key:1:private_key"))
                .returns("a private key", decrypted -> decrypted.plainText())
                .returns(SecretState.CURRENT, decrypted -> decrypted.state());
    }
}
