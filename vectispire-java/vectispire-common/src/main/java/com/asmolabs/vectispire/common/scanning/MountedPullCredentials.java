package com.asmolabs.vectispire.common.scanning;

import com.github.dockerjava.api.model.AuthConfig;
import com.github.dockerjava.core.DefaultDockerClientConfig;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

/**
 * Pull credentials read from a Docker configuration directory, for an executor that pulls nothing itself
 * but runs a tool that reads a registry: the Kubernetes executor, whose images the kubelet pulls, and
 * whose cosign verifies a plugin's signature in a pod of its own.
 *
 * <p><b>Why it exists.</b> That cosign read the registry anonymously, so a plugin kept in a private
 * registry — where an organisation keeps its own — was refused as {@code registry_authentication_required}
 * on every Kubernetes agent, whatever its signer, while the Docker executor handed cosign the credentials
 * of its own pulls ({@link ContainerRun#withRegistryLoginFor}). The operator now mounts a pull secret
 * into the agent's pod, and this class reads it as the Docker executor reads its daemon's configuration.
 *
 * <p><b>The pull's rule, not a copy of it.</b> {@code DockerClientImpl.pullImageCmd} takes its credentials
 * from {@code DockerClientConfig.effectiveAuthConfig(reference)} (docker-java 3.7.1); this calls that
 * method on a configuration built from the mounted directory, so which entry applies to an image is
 * decided the way {@link PullCredentials#of} decides it. What leaves is the same file: one entry, for
 * the run alone ({@link PullCredentials#write}).
 */
public final class MountedPullCredentials {

    private final AuthConfig auth;
    private final String registry;

    private MountedPullCredentials(AuthConfig auth, String registry) {
        this.auth = auth;
        this.registry = registry;
    }

    /**
     * What {@code configuration}'s {@code config.json} holds for {@code reference}'s registry; empty when
     * it holds nothing usable for it, or when {@code configuration} is null.
     *
     * @throws IllegalStateException when the file is there and cannot be read: a pull secret that is
     *     broken says so, rather than sending cosign to the registry anonymously
     */
    public static Optional<MountedPullCredentials> of(Path configuration, String reference) {
        if (configuration == null) {
            return Optional.empty();
        }
        AuthConfig auth;
        try {
            auth = DefaultDockerClientConfig.createDefaultConfigBuilder()
                    .withDockerConfig(configuration.toString())
                    .build()
                    .effectiveAuthConfig(reference);
        } catch (RuntimeException unreadable) {
            // docker-java's message names the file, never its content.
            throw new IllegalStateException("The registry credentials in " + configuration + " could not be read: "
                    + unreadable.getMessage(), unreadable);
        }
        return Optional.ofNullable(auth).filter(PullCredentials::usable)
                .map(found -> new MountedPullCredentials(found, PullCredentials.registryOf(reference)));
    }

    /** Whether {@code configuration} holds a readable {@code config.json} — what the agent checks at start. */
    public static boolean readable(Path configuration) {
        return Files.isRegularFile(configuration.resolve("config.json")) && Files.isReadable(configuration.resolve("config.json"));
    }

    /** The registry the entry is for, as the pull keys it. */
    public String registry() {
        return registry;
    }

    /**
     * Writes a Docker configuration holding this entry alone, in a directory of its own under {@code parent},
     * readable by this process's user only. Returns that directory, for {@link #erase}.
     */
    public Path writeUnder(Path parent) throws IOException {
        return PullCredentials.write(auth, registry, parent);
    }

    /** {@code text} with every secret of this entry replaced: a tool's words reach the screen. */
    public String redact(String text) {
        return PullCredentials.redact(text, auth);
    }

    /** Removes what {@link #writeUnder} wrote. Never throws: it runs in a {@code finally}. */
    public static void erase(Path directory) {
        PullCredentials.erase(directory);
    }

    @Override
    public String toString() {
        // Never the credentials, whoever logs this.
        return "MountedPullCredentials[" + registry + "]";
    }
}
