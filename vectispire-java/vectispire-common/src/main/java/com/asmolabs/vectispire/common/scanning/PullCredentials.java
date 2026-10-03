package com.asmolabs.vectispire.common.scanning;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.PullImageCmd;
import com.github.dockerjava.api.model.AuthConfig;
import com.github.dockerjava.core.NameParser;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Base64;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * The credentials an executor's pulls use, and the one way they leave this package: a Docker
 * configuration file that lives as long as one container.
 *
 * <p><b>Vectispire stores no registry credential.</b> An image is pulled by the daemon on the request
 * of the executor, with the credentials docker-java resolves from the executor's own Docker
 * configuration ({@code DOCKER_CONFIG}, {@code ~/.docker/config.json}) — the README's "registry
 * credentials belong to the Docker configuration of whichever machine scans". Nothing of them reaches
 * the control plane, the database or the agent protocol, so there is no {@code ENCRYPTION_KEY} in this
 * path and none is wanted.
 *
 * <p><b>The pull's rule, not a copy of it.</b> Which entry of the configuration applies to an image —
 * the registry's host, Docker Hub's legacy key, the {@code registry.*} properties that override every
 * entry — is decided by docker-java when it builds a pull command, and read back here from the command
 * it built, which is never executed. A second matcher would be a second answer to "which credentials
 * does this image get", and the first registry whose key it normalised differently would verify
 * anonymously what the daemon then pulls authenticated.
 */
final class PullCredentials {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private PullCredentials() {}

    /** What the pull of {@code reference} would send; empty when it would go anonymous. */
    static Optional<AuthConfig> of(DockerClient docker, String reference) {
        PullImageCmd pull;
        try {
            pull = docker.pullImageCmd(reference);
        } catch (RuntimeException unparsable) {
            // docker-java refuses some names before any pull (an explicit `index.docker.io/`): the pull
            // of such a reference fails the same way, so nothing is held for it.
            return Optional.empty();
        }
        return Optional.ofNullable(pull == null ? null : pull.getAuthConfig()).filter(PullCredentials::usable);
    }

    /**
     * An entry the client can answer a challenge with. A configuration whose credentials live in a
     * helper ({@code credsStore}, as Docker Desktop writes it) leaves an empty entry per registry, which
     * docker-java does not resolve; the pull sends nothing, and so does this.
     */
    private static boolean usable(AuthConfig auth) {
        return (auth.getUsername() != null && auth.getPassword() != null)
                || auth.getIdentitytoken() != null
                || auth.getRegistrytoken() != null;
    }

    /** The registry of {@code reference} as the pull keys it — its host, or Docker Hub's address. */
    static String registryOf(String reference) {
        try {
            return NameParser.resolveRepositoryName(NameParser.parseRepositoryTag(reference).repos).hostname;
        } catch (RuntimeException unparsable) {
            int slash = reference.indexOf('/');
            return slash < 0 ? reference : reference.substring(0, slash);
        }
    }

    /**
     * Writes a Docker configuration holding {@code auth} for {@code registry} alone, in a directory of
     * its own under {@code parent}, readable by this process's user only. Returns that directory.
     */
    static Path write(AuthConfig auth, String registry, Path parent) throws IOException {
        Files.createDirectories(parent);
        boolean posix = FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
        Path directory = posix
                ? Files.createTempDirectory(parent, "registry-login",
                        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
                : Files.createTempDirectory(parent, "registry-login");
        // Created with its mode rather than chmod'ed after: there is no instant at which it is readable
        // by anyone else.
        FileAttribute<?>[] mode = posix
                ? new FileAttribute<?>[] {PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))}
                : new FileAttribute<?>[0];
        Path file = Files.createFile(directory.resolve("config.json"), mode);
        Files.write(file, configuration(auth, registry));
        return directory;
    }

    /** The configuration's bytes: one entry, keyed as the pull keys the registry. */
    static byte[] configuration(AuthConfig auth, String registry) {
        ObjectNode root = MAPPER.createObjectNode();
        ObjectNode entry = root.putObject("auths").putObject(registry);
        if (auth.getUsername() != null && auth.getPassword() != null) {
            entry.put("auth", Base64.getEncoder().encodeToString(
                    (auth.getUsername() + ":" + auth.getPassword()).getBytes(StandardCharsets.UTF_8)));
        }
        if (auth.getIdentitytoken() != null) {
            entry.put("identitytoken", auth.getIdentitytoken());
        }
        if (auth.getRegistrytoken() != null) {
            entry.put("registrytoken", auth.getRegistrytoken());
        }
        try {
            return MAPPER.writeValueAsBytes(root);
        } catch (IOException impossible) {
            throw new IllegalStateException("A tree of strings did not serialise.", impossible);
        }
    }

    /** Removes what {@link #write} wrote. Never throws: it runs in a {@code finally}. */
    static void erase(Path directory) {
        if (directory == null) {
            return;
        }
        try (Stream<Path> files = Files.list(directory)) {
            for (Path file : files.toList()) {
                Files.deleteIfExists(file);
            }
            Files.deleteIfExists(directory);
        } catch (IOException | RuntimeException leftBehind) {
            // The workspace it sits in is deleted with the scan; nothing better can be done from here.
        }
    }

    /**
     * {@code text} with every secret of {@code auth} replaced — the password, the tokens, and the
     * base64 form the configuration file holds. A tool's words reach the scan's failures and the
     * screen; a registry or a client that quoted what it was sent must not carry it there.
     */
    static String redact(String text, AuthConfig auth) {
        if (text == null || auth == null) {
            return text;
        }
        String redacted = text;
        String password = auth.getPassword();
        if (auth.getUsername() != null && password != null) {
            redacted = replace(redacted, Base64.getEncoder().encodeToString(
                    (auth.getUsername() + ":" + password).getBytes(StandardCharsets.UTF_8)));
        }
        redacted = replace(redacted, password);
        redacted = replace(redacted, auth.getIdentitytoken());
        return replace(redacted, auth.getRegistrytoken());
    }

    private static String replace(String text, String secret) {
        return secret == null || secret.isEmpty() ? text : text.replace(secret, "[redacted]");
    }
}
