package com.asmolabs.zanshin.core.services;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;

/**
 * A secret read from a file rather than from the environment.
 *
 * <h2>Why a file at all</h2>
 *
 * <p>An environment variable is readable by more things than an operator expects: {@code
 * /proc/<pid>/environ}, {@code docker inspect}, an orchestrator's own logs, a crash dump, and the
 * {@code .env} file somebody's backup swept up. For {@code ENCRYPTION_KEY} that matters more than
 * for anything else Zanshin reads — it decrypts <b>every</b> deployment key the installation
 * holds, so it is the one value whose exposure is not a degradation but the whole loss.
 *
 * <p>A file is what a secret manager actually produces: Docker's secrets land under {@code
 * /run/secrets}, Kubernetes mounts a secret as a volume, and both give the file an owner and a
 * mode. The {@code _FILE} suffix is the convention operators already know from the official
 * container images, which is the reason it is spelled that way rather than more descriptively.
 *
 * <h2>Every failure here is fatal, and that is the point</h2>
 *
 * <p>The tempting behaviour — an unreadable path falls back to the variable, or to nothing — is
 * the dangerous one, because <b>"no key configured" is a state Zanshin tolerates</b>:
 * {@code EncryptionService} warns, keeps decrypting what is stored and refuses to write anything
 * new. A secret mount that failed would therefore look exactly like a fresh installation. The
 * screens render, the application serves, and the first person to notice is whoever tries to save
 * an SSH key — or nobody, if the deployment saves none that week.
 *
 * <p>So a path that is set and does not resolve stops the application, with the path in the
 * message. An operator who wanted no key sets no variable at all; setting one is a statement that
 * there is a secret to read.
 */
final class SecretFile {

    private SecretFile() {}

    /**
     * The file's contents, trimmed.
     *
     * <p><b>Trimmed on purpose, and it is not cosmetic.</b> Practically every way of writing a
     * secret to a file appends a newline — {@code echo}, {@code openssl rand -base64 32 >
     * key}, a heredoc, the editor somebody used. An untrimmed read makes the key on disk differ
     * from the same key in a variable by one invisible byte, which derives a different key and
     * presents itself as "every stored secret is unreadable" after a migration that changed
     * nothing but where the value lives.
     *
     * @param path what the {@code *_FILE} variable was set to
     * @param what the variable's name, so the message names the thing an operator has to fix
     * @throws IllegalStateException if the path does not resolve, cannot be read, or holds
     *     nothing but whitespace
     */
    static String read(String path, String what) {
        Path file;
        try {
            file = Path.of(path.trim());
        } catch (InvalidPathException notAPath) {
            throw new IllegalStateException(
                    what + " is not a usable path: \"" + path + "\". " + REMEDY, notAPath);
        }

        String content;
        try {
            content = Files.readString(file, StandardCharsets.UTF_8);
        } catch (IOException unreadable) {
            // Missing, a directory, or unreadable by this user — the last being the ordinary
            // outcome of a secret mounted with a mode this process is not in.
            throw new IllegalStateException(
                    what + " points at " + file.toAbsolutePath() + ", which cannot be read: "
                            + unreadable.getMessage() + ". " + REMEDY,
                    unreadable);
        }

        String secret = content.trim();
        if (secret.isEmpty()) {
            // **The mount that is present and empty.** A secret volume attached before its
            // contents exist is the ordinary race on a cluster, and it is indistinguishable from
            // a correct mount by anything except reading the file.
            throw new IllegalStateException(
                    what + " points at " + file.toAbsolutePath() + ", which is empty. " + REMEDY);
        }
        return secret;
    }

    private static final String REMEDY =
            "Refusing to start rather than continuing with no key: a deployment with no key still "
                    + "reads what it stored and still serves every screen, so a failed secret mount "
                    + "would be indistinguishable from a fresh installation. Fix the path or unset "
                    + "the variable.";
}
