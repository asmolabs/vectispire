package com.asmolabs.zanshin.core.services;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;

/**
 * Where the encryption secrets come from.
 *
 * <p>Bound rather than read from {@code System.getenv} inside the service, for the reason
 * given in {@code CoreConfiguration}: a value a test cannot vary is a value nobody has ever
 * exercised the other branch of — and here the other branch is "no key configured", which is
 * exactly the state a fresh deployment starts in.
 *
 * <h2>Two ways to supply each secret, and only one of them at a time</h2>
 *
 * <p>Each secret can arrive as a value or as the path to a file holding it — see {@link
 * SecretFile} for why the file is worth having, and why every failure reading one is fatal.
 * {@link #resolved()} turns the second form into the first, so nothing downstream has to know
 * which was used.
 *
 * <p><b>Setting both is refused.</b> Not because they might disagree — they usually will not —
 * but because nothing here could then answer "which key is in force" without picking a winner an
 * operator did not choose. It is the same objection that keeps {@code ddl-auto} at {@code
 * validate}: two authorities for one value, and the one that runs second wins silently. Refusing
 * costs the seconds of a restart during the deliberate migration from a variable to a file, and
 * it is the only reading in which the migration is finished when the operator thinks it is.
 *
 * @param key the current key. Everything is encrypted under it, and it is tried first when
 *     reading
 * @param keyFile a file holding {@code key} instead. What a secret manager mounts
 * @param previousKeys keys kept only for reading, so a rotation does not have to rewrite every
 *     row before the new key takes effect. Order is theirs; a key already listed as current is
 *     dropped rather than tried twice
 * @param previousKeysFile a file holding {@code previousKeys}, comma-separated, instead.
 *     Supported for the same reason as {@code keyFile} and not for symmetry: a previous key still
 *     decrypts live rows, and a rotation is precisely the moment at which two keys exist at once —
 *     so a deployment that moved the current key to a file would otherwise have to put the old one
 *     back into the environment to finish the job
 */
@ConfigurationProperties("zanshin.encryption")
public record EncryptionProperties(
        Optional<String> key, Optional<String> keyFile, List<String> previousKeys, Optional<String> previousKeysFile) {

    @ConstructorBinding
    public EncryptionProperties {
        // **`key` is deliberately not trimmed**, unlike the paths below. A deployment whose
        // variable carries a stray space derives its keys *with* that space today, and every
        // secret it stored is encrypted under the result. Trimming here would derive a different
        // key and present itself as "every stored secret is unreadable" after an upgrade that
        // touched nothing an operator can see. The file form has no such history, which is why
        // `SecretFile` trims and this does not.
        key = key == null ? Optional.empty() : key;
        keyFile = pathOrEmpty(keyFile);
        previousKeysFile = pathOrEmpty(previousKeysFile);
        previousKeys = previousKeys == null
                ? List.of()
                : previousKeys.stream().map(String::trim).filter(secret -> !secret.isEmpty()).toList();
    }

    /**
     * The form every caller other than {@link #resolved()} uses: values, no paths.
     *
     * <p>Kept so that a test naming a key inline says nothing about files, which is the whole of
     * what most of them are about.
     */
    public EncryptionProperties(Optional<String> key, List<String> previousKeys) {
        this(key, Optional.empty(), previousKeys, Optional.empty());
    }

    /**
     * The same secrets with every file read, or a failure that stops the application.
     *
     * <p>Called once, at startup, from {@link EncryptionService}. Idempotent on a value with no
     * paths — which is what makes it safe to call unconditionally rather than behind a test
     * nobody would notice going stale.
     */
    public EncryptionProperties resolved() {
        if (keyFile.isEmpty() && previousKeysFile.isEmpty()) {
            return this;
        }

        refuseBoth(isSupplied(key), keyFile.isPresent(), "ENCRYPTION_KEY", "ENCRYPTION_KEY_FILE");
        refuseBoth(
                !previousKeys.isEmpty(),
                previousKeysFile.isPresent(),
                "ZANSHIN_PREVIOUS_ENCRYPTION_KEYS",
                "ZANSHIN_PREVIOUS_ENCRYPTION_KEYS_FILE");

        Optional<String> resolvedKey =
                keyFile.map(path -> SecretFile.read(path, "ENCRYPTION_KEY_FILE")).or(() -> key);
        List<String> resolvedPrevious = previousKeysFile
                .map(path -> SecretFile.read(path, "ZANSHIN_PREVIOUS_ENCRYPTION_KEYS_FILE"))
                .map(EncryptionProperties::splitKeys)
                .orElse(previousKeys);

        return new EncryptionProperties(resolvedKey, resolvedPrevious);
    }

    /**
     * The file's form matches the variable's: comma-separated.
     *
     * <p>Newlines separate too, because a file holding one key per line is what somebody writes
     * when the value is no longer squeezed onto a shell line — and a key list silently read as one
     * malformed key would derive a key that decrypts nothing, reported as "these rows are
     * unreadable" rather than as a formatting mistake.
     */
    private static List<String> splitKeys(String content) {
        return Arrays.stream(content.split("[,\\r\\n]"))
                .map(String::trim)
                .filter(secret -> !secret.isEmpty())
                .toList();
    }

    /**
     * Whether a secret was really supplied, blank not counting.
     *
     * <p><b>The distinction is load-bearing, and it is not obvious.</b> The yaml reads {@code key:
     * ${ENCRYPTION_KEY:}}, so a variable nobody set arrives here as the <em>empty string</em> —
     * present, as far as {@link Optional} is concerned. Treating that as "a value was supplied"
     * makes the refusal above fire for every correct file-only configuration, which is to say the
     * feature would refuse to start in exactly the case it exists for. It is the same reading
     * {@code EncryptionService} has always applied to decide whether a key is configured at all.
     */
    private static boolean isSupplied(Optional<String> secret) {
        return secret.filter(value -> !value.isBlank()).isPresent();
    }

    private static void refuseBoth(boolean hasValue, boolean hasFile, String valueName, String fileName) {
        if (hasValue && hasFile) {
            throw new IllegalStateException(
                    valueName + " and " + fileName + " are both set. Nothing here can say which secret is "
                            + "in force without choosing one you did not, so it refuses rather than picking. "
                            + "Unset " + valueName + " once the file is in place.");
        }
    }

    /** A path, unlike a secret, is safe to trim: an unset variable arrives here as the empty string. */
    private static Optional<String> pathOrEmpty(Optional<String> value) {
        return value == null ? Optional.empty() : value.map(String::trim).filter(text -> !text.isEmpty());
    }
}
