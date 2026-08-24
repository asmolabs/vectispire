package com.asmolabs.vectispire.common.scanning.scanners;

import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.scanning.ContainerRun;
import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import com.asmolabs.vectispire.common.scanning.ScannerFailureException;
import com.asmolabs.vectispire.common.scanning.Workspace;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.stream.StreamSupport;

/**
 * Dependency analysis, in two steps: one tool takes the inventory, the other matches it
 * against known vulnerabilities.
 *
 * <p><b>Two tools and not one</b>, because the SBOM has value of its own: it is exportable, it
 * answers "what is in this application", and it lets the vulnerability analysis be replayed
 * without walking the code again. Merging the steps would lose that artifact.
 *
 * <p><b>The network is opened for the matcher only.</b> The cataloguer, on a directory, reads
 * dependency files and has nowhere to look. The matcher downloads and refreshes its
 * vulnerability database: with no network it would work against an absent or stale one and
 * return a reassuring result without saying so.
 */
public final class DependencyScanner {

    private static final String SBOM_FILENAME = "sbom.json";

    /**
     * The exported image, at the workspace root.
     *
     * <p>At the root and not under {@code source/}: it is not material for the other steps to
     * analyse, and an image scan has no source tree anyway.
     */
    private static final String IMAGE_ARCHIVE_FILENAME = "image.tar";

    /**
     * The architecture audited by default.
     *
     * <p>Explicit, because the daemon would otherwise return the host's: an arm64 development
     * machine would produce the SBOM of an arm64 image while production deploys linux/amd64,
     * and the vulnerabilities found would not be the ones that matter.
     */
    public static final String DEFAULT_PLATFORM = "linux/amd64";

    private final ContainerRunner runner;
    private final ScannerImages images;

    public DependencyScanner(ContainerRunner runner, ScannerImages images) {
        this.runner = runner;
        this.images = images;
    }

    /**
     * A vulnerable component, reduced to what Vectispire keeps.
     *
     * @param fixVersions the versions that fix it, comma-separated; empty when none exists.
     *     <b>A string and not a list</b>, because this doubles as the "fixable" flag in the
     *     gate, where empty means "no published fix". An empty list and an absent value would
     *     behave differently depending on the path taken
     * @param purl the universal package identifier: what lets two sources be cross-referenced
     */
    public record DependencyFinding(
            String identifier,
            Severity severity,
            String packageName,
            String installedVersion,
            String fixVersions,
            String description,
            String referenceUrl,
            String purl) {}

    /**
     * Takes the inventory of a directory's dependencies.
     *
     * <p>Mounted read-only: the cataloguer has no reason to write into the tree it is
     * analysing, and forbidding it removes the question of whether it does.
     */
    public Optional<JsonNode> sbomOfDirectory(Workspace workspace, String subPath) {
        String label = "syft (directory SBOM)";

        ContainerRunner.ContainerResult result = runner.run(ContainerRun.of(
                        images.syft(),
                        List.of("dir:" + ContainerPaths.source(subPath), "-o", "json"),
                        List.of(ContainerRun.Mount.readOnly(workspace.root().toString(), ContainerPaths.MOUNT)),
                        label)
                .runningAsRoot());

        return ContainerRunner.parseJson(result, label, List.of(0));
    }

    /**
     * Takes the inventory of a <b>container image</b>.
     *
     * <p><b>Vectispire pulls it, the container does not.</b> The only process talking to the daemon
     * is this one; the cataloguer sees a file. Mounting the socket into it would be equivalent
     * to handing out root on the host, and no amount of container hardening changes that —
     * whoever reaches the socket can start a privileged container.
     *
     * <p>The platform is applied <b>at the pull</b>, so the exported archive carries only the
     * requested variant and there is nothing left to specify downstream.
     */
    public Optional<JsonNode> sbomOfImage(Workspace workspace, String reference, String platform) {
        String label = "syft (SBOM of image " + reference + ")";
        Path archive = workspace.root().resolve(IMAGE_ARCHIVE_FILENAME);

        runner.exportImage(reference, platform, archive);
        try {
            ContainerRunner.ContainerResult result = runner.run(ContainerRun.of(
                            images.syft(),
                            List.of("docker-archive:" + ContainerPaths.MOUNT + "/" + IMAGE_ARCHIVE_FILENAME, "-o", "json"),
                            List.of(ContainerRun.Mount.readOnly(workspace.root().toString(), ContainerPaths.MOUNT)),
                            label)
                    // **Neither network nor socket.** The image is already here as an archive,
                    // so there is nothing left for it to reach.
                    .runningAsRoot());

            return ContainerRunner.parseJson(result, label, List.of(0));
        } finally {
            // An image archive routinely runs to hundreds of megabytes, and the matcher does not
            // need it: it goes as soon as the SBOM is read, without waiting for the scan to end.
            try {
                Files.deleteIfExists(archive);
            } catch (IOException ignored) {
                // The workspace removal will get it; this only shortens the window.
            }
        }
    }

    /**
     * Matches an SBOM against known vulnerabilities.
     *
     * <p>The SBOM goes through a file in the workspace rather than through standard input: that
     * is what the matcher expects, and it leaves the artifact available for export.
     *
     * <p><b>Returns empty when the analysis did not happen</b>, never an empty list. An empty
     * list means "analysed, no vulnerabilities" and resolves the target's whole backlog — which,
     * after a failed database download, would be an expensive lie.
     */
    public Optional<List<DependencyFinding>> matchSbom(Workspace workspace, String sbomJson) {
        writeSbom(workspace.root(), sbomJson);
        return match(workspace.root(), "grype (SBOM analysis)");
    }

    /**
     * Matching an SBOM that does not come from a cloned tree — an image's.
     *
     * <p>The SBOM is written into a temporary directory of its own, because the matcher reads it
     * from a mount and there is no scan workspace to reuse here. Creating a full one for a single
     * file would mean preparing a clone that will not happen.
     *
     * <p>The directory is removed in every case, failure included: an image SBOM weighs several
     * megabytes, and a scan failing hourly would fill the disk without anybody making the
     * connection.
     */
    public Optional<List<DependencyFinding>> matchStandaloneSbom(String sbomJson) {
        Path directory;
        try {
            directory = Files.createTempDirectory("vectispire-sbom-");
        } catch (IOException e) {
            throw new UncheckedIOException("could not stage the SBOM for matching", e);
        }

        try {
            writeSbom(directory, sbomJson);
            return match(directory, "grype (image SBOM analysis)");
        } finally {
            deleteRecursively(directory);
        }
    }

    private Optional<List<DependencyFinding>> match(Path mounted, String label) {
        ContainerRunner.ContainerResult result = runner.run(ContainerRun.of(
                        images.grype(),
                        List.of("sbom:" + ContainerPaths.MOUNT + "/" + SBOM_FILENAME, "-o", "json"),
                        List.of(ContainerRun.Mount.readOnly(mounted.toString(), ContainerPaths.MOUNT)),
                        label)
                // The matcher downloads and refreshes its vulnerability database.
                .withNetwork()
                .runningAsRoot());

        return ContainerRunner.parseJson(result, label, List.of(0)).map(DependencyScanner::findings);
    }

    static List<DependencyFinding> findings(JsonNode payload) {
        JsonNode matches = payload.path("matches");
        if (!matches.isArray()) {
            return List.of();
        }

        List<DependencyFinding> findings = new ArrayList<>(matches.size());
        for (JsonNode match : matches) {
            JsonNode vulnerability = match.path("vulnerability");
            JsonNode artifact = match.path("artifact");

            findings.add(new DependencyFinding(
                    vulnerability.path("id").asText("unknown"),
                    // Parsed into the enum rather than kept as text. The matcher says "High";
                    // Vectispire's vocabulary is lowercase, and an unparsed "High" would match no
                    // policy threshold — the finding would be created and enter no gate.
                    Severity.of(vulnerability.path("severity").asText(null)),
                    artifact.path("name").asText("unknown"),
                    artifact.path("version").asText(""),
                    fixVersions(vulnerability),
                    text(vulnerability, "description"),
                    text(vulnerability, "dataSource"),
                    text(artifact, "purl")));
        }
        return List.copyOf(findings);
    }

    private static String fixVersions(JsonNode vulnerability) {
        JsonNode versions = vulnerability.path("fix").path("versions");
        if (!versions.isArray()) {
            return "";
        }
        return StreamSupport.stream(versions.spliterator(), false)
                .map(JsonNode::asText)
                .filter(version -> !version.isBlank())
                .reduce((a, b) -> a + ", " + b)
                .orElse("");
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.path(field);
        return value.isTextual() && !value.asText().isBlank() ? value.asText() : null;
    }

    private static void writeSbom(Path directory, String sbomJson) {
        try {
            Files.writeString(directory.resolve(SBOM_FILENAME), sbomJson);
        } catch (IOException e) {
            throw ScannerFailureException.of("grype", "The SBOM could not be staged for matching: " + e.getMessage());
        }
    }

    private static void deleteRecursively(Path root) {
        try (var paths = Files.walk(root)) {
            paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException ignored) {
                    // One undeletable file must not stop the rest from going.
                }
            });
        } catch (IOException ignored) {
            // Absent is the outcome we wanted.
        }
    }
}
