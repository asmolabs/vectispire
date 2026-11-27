package com.asmolabs.vectispire.agent.kubernetes;

import com.asmolabs.vectispire.common.scanning.ContainerRun;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * **An image target, copied into the workspace by a pinned step in a pod of its own** (decision 0045 §8) — what the
 * Docker executor's pull and save do through the daemon, on a cluster that has none.
 *
 * <p><b>crane, not the cataloguer.</b> The step that reaches the registry is the only one with network and with the
 * registry's login; syft and grype read the archive it wrote offline, as on Docker. Letting the cataloguer pull would
 * hand network and credentials to the parser of hostile metadata.
 *
 * <p><b>A Docker archive, not the OCI layout 0045 §8 first named.</b> {@code crane pull}'s default format is the
 * archive {@code docker save} writes ({@code manifest.json}, the configuration, the layers): the cataloguer reads it
 * through the same {@code docker-archive:} source, and the platform check of {@code ImagePlatform} reads it unchanged.
 * Syft's whole report on the two archives of one image is the same, file names aside (measured on
 * {@code python:3.12-slim-bookworm}, linux/amd64, 113 packages): no fingerprint can move, which the layout would have
 * had to be proved not to do.
 *
 * <p><b>The platform is asked for and then checked.</b> Normalized as containerd normalizes before crane searches an
 * index for it; and a reference naming one image rather than an index is fetched whatever the platform, crane
 * exiting 0 — so the archive goes through the same check as the daemon's save, with this step's sentence.
 *
 * <p>Held to {@code vectispire-rust/reference/kubernetes/image-copy.json}: the request, the sentences, the refusals.
 */
final class ImageCopy {

    /** crane 0.22.1, the multi-architecture index: a static binary, no shell. */
    static final String IMAGE =
            "gcr.io/go-containerregistry/crane:v0.22.1@sha256:1f968817b95790bed063f71175aa6b8ff879fa17064020415f3e18bb6e6a36e1";
    /** What the image runs, declared as every scanner's is: the wrapper that captures its streams has to name it. */
    static final List<String> ENTRYPOINT = List.of("/ko-app/crane");
    /** The step's name: its pod's, and its failures'. */
    static final String LABEL = "image copy";
    /** Where the copy's writable directory is in its pod. */
    static final String TARGET = "/image";
    /** The archive crane writes there, brought back by the executor's copy of a writable mount. */
    static final String ARCHIVE = "image.tar";
    /**
     * What the archive may hold: the work volume's size and the copy back's ceiling. Generous — an image's compressed
     * layers rarely pass a few gigabytes — since past it the step fails outright, which a ceiling too tight would make
     * of every large image.
     */
    static final long BYTES = 8L * 1024 * 1024 * 1024;

    private ImageCopy() {}

    /**
     * The copy's run: crane pulling {@code reference} for {@code platform} (normalized, absent when the task named
     * none) into {@code into}, online, handed the registry's login under {@code login} when the agent holds one.
     *
     * <p><b>{@code --} before the reference</b>: a reference is the operator's text, and one starting with a dash
     * would otherwise be read as one of crane's options ({@code --insecure}).
     */
    static ContainerRun request(String image, String reference, Optional<String> platform, Path into, Path login) {
        List<String> command = new ArrayList<>(List.of("pull"));
        platform.ifPresent(asked -> command.addAll(List.of("--platform", asked)));
        command.addAll(List.of("--", reference, TARGET + "/" + ARCHIVE));
        return ContainerRun.of(image, command, List.of(ContainerRun.Mount.writable(into.toString(), TARGET, BYTES)), LABEL)
                .withNetwork()
                .withEntrypoint(ENTRYPOINT)
                .withRegistryLoginFor(reference, login);
    }

    /**
     * Why the copy produced nothing to scan, in its own words — empty when it exited 0 and wrote its archive.
     *
     * @param stderr what crane printed, already redacted of the login by the executor
     */
    static Optional<String> failure(String reference, String platform, int exitCode, String stderr, boolean written) {
        if (exitCode != 0) {
            String asked = platform == null || platform.isBlank() ? "" : " for " + platform;
            String said = excerpt(stderr.strip());
            return Optional.of("The image copy could not fetch " + reference + asked + ": crane exited " + exitCode
                    + (said.isEmpty() ? "" : ", saying: " + said) + ". It is not scanned.");
        }
        if (!written) {
            return Optional.of("The image copy exited 0 and wrote no archive of " + reference + ". It is not scanned.");
        }
        return Optional.empty();
    }

    /** The first 500 characters, counted as code points so both agents cut at the same character. */
    static String excerpt(String text) {
        if (text.codePointCount(0, text.length()) <= 500) {
            return text;
        }
        return text.substring(0, text.offsetByCodePoints(0, 500)) + "…";
    }
}
