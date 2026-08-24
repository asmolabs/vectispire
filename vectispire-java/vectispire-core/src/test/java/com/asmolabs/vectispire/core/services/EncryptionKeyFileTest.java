package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.crypto.EncryptionKey;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Supplying the encryption secrets as files rather than as environment variables.
 *
 * <p>What is under test is mostly the <b>refusals</b>. Reading a file is three lines; the reason
 * this exists is that every way of getting it subtly wrong produces an application that starts,
 * serves every screen, and protects nothing — which is the failure {@link SecretFile} is written
 * against.
 */
@DisplayName("the encryption key, from a file")
class EncryptionKeyFileTest {

    private static final String KEY = EncryptionKey.generate();
    private static final String OLD_KEY = EncryptionKey.generate();

    @TempDir
    private Path directory;

    @Test
    @DisplayName("the file's contents become the key")
    void readsTheKey() throws IOException {
        Path file = write("key", KEY);

        EncryptionProperties resolved = fromKeyFile(file).resolved();

        assertThat(resolved.key()).contains(KEY);
        assertThat(resolved.keyFile()).isEmpty();
    }

    @Test
    @DisplayName("a trailing newline is not part of the key, or a migration would lose every secret")
    void trimsTheTrailingNewline() throws IOException {
        // What `openssl rand -base64 32 > key` and every heredoc actually produce. Untrimmed,
        // the same key differs from its variable form by one invisible byte, derives a different
        // key, and reports itself as "every stored secret is unreadable".
        Path file = write("key", KEY + "\n");

        assertThat(fromKeyFile(file).resolved().key()).contains(KEY);
    }

    @Test
    @DisplayName("a path that does not resolve stops the application, rather than falling back to no key")
    void refusesAMissingFile() {
        Path missing = directory.resolve("absent");

        assertThatThrownBy(() -> fromKeyFile(missing).resolved())
                .isInstanceOf(IllegalStateException.class)
                // The path is in the message because "cannot be read" without it sends an
                // operator to the wrong file.
                .hasMessageContaining(missing.toAbsolutePath().toString())
                .hasMessageContaining("ENCRYPTION_KEY_FILE");
    }

    @Test
    @DisplayName("a mount that is present and empty is refused too")
    void refusesAnEmptyFile() throws IOException {
        // The ordinary race on a cluster: the volume is attached before its contents exist, and
        // nothing but reading the file tells it apart from a correct mount.
        Path file = write("key", "   \n");

        assertThatThrownBy(() -> fromKeyFile(file).resolved())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("empty");
    }

    @Test
    @DisplayName("a value and a file together are refused, not silently ranked")
    void refusesBothSources() throws IOException {
        Path file = write("key", KEY);

        EncryptionProperties both =
                new EncryptionProperties(Optional.of(OLD_KEY), Optional.of(file.toString()), List.of(), Optional.empty());

        assertThatThrownBy(both::resolved)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("ENCRYPTION_KEY")
                .hasMessageContaining("ENCRYPTION_KEY_FILE");
    }

    @Test
    @DisplayName("an unset variable beside a file is not 'both set' — the yaml makes it an empty string")
    void anEmptyVariableIsNotASecondSource() throws IOException {
        Path file = write("key", KEY);

        // `key: ${ENCRYPTION_KEY:}` gives an empty string when nobody set the variable, so this is
        // what every correct file-only deployment looks like. Reading it as a supplied value made
        // the refusal fire on exactly the configuration the file form exists for.
        EncryptionProperties fileOnly =
                new EncryptionProperties(Optional.of(""), Optional.of(file.toString()), List.of(), Optional.empty());

        assertThat(fileOnly.resolved().key()).contains(KEY);
    }

    @Test
    @DisplayName("previous keys come from a file too, so a rotation need not put the old key back in the environment")
    void readsPreviousKeys() throws IOException {
        Path file = write("previous", OLD_KEY + "," + KEY);

        EncryptionProperties resolved = new EncryptionProperties(
                        Optional.empty(), Optional.empty(), List.of(), Optional.of(file.toString()))
                .resolved();

        assertThat(resolved.previousKeys()).containsExactly(OLD_KEY, KEY);
    }

    @Test
    @DisplayName("one key per line reads as a list, not as one malformed key")
    void readsPreviousKeysSeparatedByNewlines() throws IOException {
        // A file is where somebody stops squeezing the list onto a shell line. Read as a single
        // value it would derive a key that decrypts nothing, and be reported as unreadable rows
        // rather than as a formatting mistake.
        Path file = write("previous", OLD_KEY + "\n" + KEY + "\n");

        EncryptionProperties resolved = new EncryptionProperties(
                        Optional.empty(), Optional.empty(), List.of(), Optional.of(file.toString()))
                .resolved();

        assertThat(resolved.previousKeys()).containsExactly(OLD_KEY, KEY);
    }

    @Test
    @DisplayName("no file configured changes nothing, so the resolution is safe to call unconditionally")
    void isIdempotentWithoutFiles() {
        EncryptionProperties plain = new EncryptionProperties(Optional.of(KEY), List.of(OLD_KEY));

        assertThat(plain.resolved()).isSameAs(plain);
    }

    @Test
    @DisplayName("a key from a file encrypts what the same key in a variable decrypts")
    void theFileFormIsTheSameKey() throws IOException {
        Path file = write("key", KEY + "\n");

        String cipherText = new EncryptionService(fromKeyFile(file)).encrypt("a private key", "ssh_key:1:private_key");
        // The pair that matters: the two forms have to be one key, or moving a deployment to a
        // secret mount would quietly orphan everything it had already stored.
        EncryptionService fromVariable = new EncryptionService(new EncryptionProperties(Optional.of(KEY), List.of()));

        assertThat(fromVariable.inspect(cipherText, "ssh_key:1:private_key").plainText()).isEqualTo("a private key");
    }

    private EncryptionProperties fromKeyFile(Path file) {
        return new EncryptionProperties(Optional.empty(), Optional.of(file.toString()), List.of(), Optional.empty());
    }

    private Path write(String name, String content) throws IOException {
        return Files.writeString(directory.resolve(name), content);
    }
}
