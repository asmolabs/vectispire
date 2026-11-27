package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueFingerprint;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.scanning.scanners.DependencyScanner;
import com.asmolabs.vectispire.common.scanning.scanners.DependencyScanner.DependencyFinding;
import com.asmolabs.vectispire.common.scanning.scanners.ScannerImages;
import com.asmolabs.vectispire.common.scanning.scanners.VulnerabilityDatabase;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.TreeSet;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * <b>The Java agent and the Rust agent on the real vulnerability database</b> — the same snapshot, the same
 * targets, and any difference in what the control plane would record refused.
 *
 * <p>Every other suite runs a fake matcher: the real database is some 3 GB. The nightly's {@code real-matcher}
 * job first runs the Rust agent's {@code crates/scanners/tests/real_matcher.rs}, which downloads the database
 * through the Rust agent's {@code VulnerabilityDatabase} into {@code VECTISPIRE_REAL_GRYPE_CACHE} and writes its
 * findings to {@code VECTISPIRE_REAL_MATCHER_OUT}; then this, which points this side's {@link
 * VulnerabilityDatabase} at the same cache — the one the Rust agent published, checked within the hour, so
 * mounted as it is: the two agents share one cache, as they would on one host — scans the same tree and the
 * same image, and compares: the findings as the control plane reads them off the wire, in order, and the
 * fingerprint {@code IssueSyncService} would give each, since a fingerprint that differs is every such issue
 * resolved and recreated the day the agent is swapped. The inventories are compared by package.
 *
 * <p><b>Its own task, not a skip</b> ({@code realMatcherTest}): {@code integrationTest} excludes the tag, and
 * this fails without the variables, the Rust side's answers, Docker or the network.
 */
@Tag("real-matcher")
@DisplayName("the real matcher: the Java agent's findings against the Rust agent's, on one database")
class RealMatcherIntegrationTest {

    /** {@code real_matcher.rs}'s image: alpine 3.12.0 by its multi-architecture index, exported for linux/amd64 (why there). */
    private static final String ALPINE =
            "alpine@sha256:185518070891758909c9f839cf4ca393ee977ac378609f700f60a771a2dfe321";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final ContainerRunner RUNNER = new ContainerRunner();

    private static Path variable(String name) {
        String value = System.getenv(name);
        assertThat(value).as("%s names a directory", name).isNotBlank();
        return Path.of(value);
    }

    @Test
    @DisplayName("a tree and an image: the same findings, in the same order, with the same fingerprints")
    void sameFindingsAndFingerprints() throws IOException {
        Path cache = variable("VECTISPIRE_REAL_GRYPE_CACHE");
        Path out = variable("VECTISPIRE_REAL_MATCHER_OUT");
        String published = Files.readString(cache.resolve("current")).strip();
        VulnerabilityDatabase database = new VulnerabilityDatabase(RUNNER, ScannerImages.PINNED.grype(), cache);
        DependencyScanner scanner = new DependencyScanner(RUNNER, ScannerImages.PINNED, database);

        Path tree = Files.createTempDirectory("vectispire-real-matcher-");
        try {
            Workspace workspace = new Workspace(tree, tree.resolve(Workspace.SOURCE_SUBDIR), tree.resolve(Workspace.RULES_SUBDIR));
            copyFixture(Path.of(System.getProperty("vectispire.rust.reference"), "dependencies/fixtures/polyglot"),
                    workspace.source());
            JsonNode sbom = scanner.sbomOfDirectory(workspace, null).orElseThrow();
            List<DependencyFinding> findings = scanner.matchSbom(workspace, sbom.toString()).orElseThrow();
            compare(out, "polyglot", sbom, findings, new ScanTarget.Repository(1));
        } finally {
            Directories.deleteRecursively(tree);
        }

        Path image = Files.createTempDirectory("vectispire-real-matcher-image-");
        try {
            Workspace workspace = new Workspace(image, image.resolve(Workspace.SOURCE_SUBDIR), image.resolve(Workspace.RULES_SUBDIR));
            JsonNode sbom = scanner.sbomOfImage(workspace, ALPINE, DependencyScanner.DEFAULT_PLATFORM).orElseThrow();
            List<DependencyFinding> findings = scanner.matchStandaloneSbom(sbom.toString()).orElseThrow();
            compare(out, "alpine", sbom, findings, new ScanTarget.Container(1));
        } finally {
            Directories.deleteRecursively(image);
        }

        // One snapshot for both: had this side downloaded another, the comparison would say nothing.
        assertThat(Files.readString(cache.resolve("current")).strip()).as("the generation both agents matched against")
                .isEqualTo(published);
    }

    /**
     * <b>A published copy whose checksum no longer matches is replaced</b>, where it used to be kept until the
     * publisher's next database: the matcher's {@code db check} asks the publisher and calls it current, and
     * every match on it failed meanwhile. The copy is the shared snapshot's database hard-linked into a cache of
     * this test's own, its recorded checksum zeroed. While its check is not due a match on it is absent, never
     * empty; once due, the read-back refuses it, a download replaces it — 3.5 GB — and the match answers.
     */
    @Test
    @DisplayName("a published copy whose checksum no longer matches is absent, then replaced by a download")
    void aCorruptedCopyIsReplaced() throws IOException {
        Path shared = variable("VECTISPIRE_REAL_GRYPE_CACHE");
        Path fresh = shared.resolve(VulnerabilityDatabase.GENERATIONS)
                .resolve(Files.readString(shared.resolve("current")).strip());
        // Beside the shared cache, on its file system, so the database is linked rather than copied.
        Path cache = Path.of(shared + "-java-corrupted");
        Directories.deleteRecursively(cache);
        Path tampered = cache.resolve(VulnerabilityDatabase.GENERATIONS).resolve("1790000000000-0000dddd");
        Files.createDirectories(tampered.resolve("6"));
        Files.createLink(tampered.resolve("6/vulnerability.db"), fresh.resolve("6/vulnerability.db"));
        Files.writeString(tampered.resolve("6/import.json"), Files.readString(fresh.resolve("6/import.json"))
                .replaceAll("xxh64:[0-9a-f]{16}", "xxh64:0000000000000000"));
        Files.writeString(cache.resolve("current"), tampered.getFileName().toString());
        Files.writeString(cache.resolve("checked"), java.time.Instant.now().toString());
        String sbom = Files.readString(
                Path.of(System.getProperty("vectispire.rust.reference"), "dependencies/sboms/01-polyglot.json"));
        try {
            VulnerabilityDatabase database = new VulnerabilityDatabase(RUNNER, ScannerImages.PINNED.grype(), cache);
            DependencyScanner scanner = new DependencyScanner(RUNNER, ScannerImages.PINNED, database);

            assertThatThrownBy(() -> scanner.matchStandaloneSbom(sbom))
                    .as("a match on it before the check is due fails the step")
                    .isInstanceOf(ScannerFailureException.class)
                    .hasMessageContaining("checksum");

            Files.writeString(cache.resolve("checked"), "2026-01-01T00:00:00Z");
            Path replaced = database.mountable();

            assertThat(replaced).isNotEqualTo(tampered);
            assertThat(Files.readString(cache.resolve("current"))).isEqualTo(replaced.getFileName().toString());
            assertThat(tampered).as("retired like any replaced generation, not deleted").exists();
            assertThat(scanner.matchStandaloneSbom(sbom)).get()
                    .asInstanceOf(org.assertj.core.api.InstanceOfAssertFactories.LIST).isNotEmpty();
        } finally {
            Directories.deleteRecursively(cache);
        }
    }

    private static void compare(Path out, String target, JsonNode sbom, List<DependencyFinding> java, ScanTarget scanned)
            throws IOException {
        MAPPER.writerWithDefaultPrettyPrinter().writeValue(out.resolve("java-" + target + ".json").toFile(), java);
        List<DependencyFinding> rust = MAPPER.readValue(
                out.resolve("rust-" + target + ".json").toFile(), new TypeReference<List<DependencyFinding>>() {});

        List<String> javaPrints = fingerprints(java, scanned);
        List<String> rustPrints = fingerprints(rust, scanned);
        Files.write(out.resolve("fingerprints-" + target + ".txt"),
                Stream.concat(javaPrints.stream().map(print -> "java " + print), rustPrints.stream().map(print -> "rust " + print))
                        .toList());

        assertThat(java).as("%s: the Java agent's findings", target).hasSizeGreaterThan(0);
        assertThat(rust).as("%s: the Rust agent's findings, as the control plane reads them", target)
                .containsExactlyElementsOf(java);
        assertThat(rustPrints).as("%s: the fingerprints", target).containsExactlyElementsOf(javaPrints);
        assertThat(packages(MAPPER.readTree(out.resolve("rust-" + target + ".sbom.json").toFile())))
                .as("%s: the inventory, by package", target).isEqualTo(packages(sbom));
    }

    /** What {@code IssueSyncService.fingerprintOf} computes for a dependency finding. */
    private static List<String> fingerprints(List<DependencyFinding> findings, ScanTarget target) {
        return findings.stream()
                .map(finding -> IssueFingerprint.of(new IssueFingerprint.Input(
                        target, FindingType.VULNERABILITY, finding.identifier(), finding.purl(), finding.packageName(), null)))
                .toList();
    }

    /** Each artifact's type, name, version and purl: an inventory has a timestamp and identifiers of its run. */
    private static TreeSet<String> packages(JsonNode sbom) {
        TreeSet<String> packages = new TreeSet<>();
        for (JsonNode artifact : sbom.path("artifacts")) {
            packages.add(String.join(" ", artifact.path("type").asText(), artifact.path("name").asText(),
                    artifact.path("version").asText(), artifact.path("purl").asText()));
        }
        return packages;
    }

    private static void copyFixture(Path from, Path to) throws IOException {
        List<Path> files = new ArrayList<>();
        try (Stream<Path> walked = Files.walk(from)) {
            walked.filter(Files::isRegularFile).forEach(files::add);
        }
        for (Path file : files) {
            String name = Objects.requireNonNull(file.getFileName()).toString();
            if (!name.endsWith(".fixture")) {
                continue;
            }
            Path target = to.resolve(from.relativize(file)).resolveSibling(name.substring(0, name.length() - ".fixture".length()));
            Files.createDirectories(target.getParent());
            Files.copy(file, target);
        }
    }
}
