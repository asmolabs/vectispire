package com.asmolabs.vectispire.common.scanning.scanners;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.scanning.ContainerRun;
import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import com.asmolabs.vectispire.common.scanning.ContainerRunner.ContainerResult;
import com.asmolabs.vectispire.common.scanning.ScannerFailureException;
import com.asmolabs.vectispire.common.scanning.Workspace;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * Dependency analysis, without a daemon.
 *
 * <p>The runner is replaced, so what is checked is what this class decides on its own: how the
 * matcher's report becomes findings, which of the two containers gets the network, and that the
 * large files it stages — an exported image, an image SBOM — do not outlive the call, failure
 * included. Only the return-type contract was tested before, by reflection.
 */
@DisplayName("dependency analysis")
class DependencyScannerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Nested
    @DisplayName("reading the matcher's report")
    class Findings {

        @Test
        @DisplayName("a match becomes a finding, with the severity in Vectispire's vocabulary and the fixes joined")
        void readsAMatch() throws Exception {
            var findings = DependencyScanner.findings(MAPPER.readTree("""
                    {"matches": [{
                      "vulnerability": {"id": "CVE-2026-0001", "severity": "High",
                        "fix": {"versions": ["4.17.22", "", "5.0.1"]},
                        "description": "Prototype pollution", "dataSource": "https://nvd.example/CVE-2026-0001"},
                      "artifact": {"name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"}
                    }]}
                    """));

            assertThat(findings).singleElement().isEqualTo(new DependencyScanner.DependencyFinding(
                    "CVE-2026-0001",
                    // "High" read literally would match no threshold, and the finding would
                    // enter no gate.
                    Severity.HIGH,
                    "lodash",
                    "4.17.21",
                    "4.17.22, 5.0.1",
                    "Prototype pollution",
                    "https://nvd.example/CVE-2026-0001",
                    "pkg:npm/lodash@4.17.21"));
        }

        @Test
        @DisplayName("no published fix is an empty string, the value the gate reads as not fixable")
        void noFixIsEmpty() throws Exception {
            var finding = DependencyScanner.findings(MAPPER.readTree("""
                    {"matches": [{"vulnerability": {"id": "CVE-1", "fix": {"state": "not-fixed"}},
                                  "artifact": {"name": "openssl"}}]}
                    """)).getFirst();

            assertThat(finding.fixVersions()).isEmpty();
            assertThat(finding.severity()).isEqualTo(Severity.UNKNOWN);
            assertThat(finding.installedVersion()).isEmpty();
            assertThat(finding.description()).isNull();
            assertThat(finding.purl()).isNull();
        }

        @Test
        @DisplayName("a report with no matches is a clean analysis")
        void noMatchesIsClean() throws Exception {
            assertThat(DependencyScanner.findings(MAPPER.readTree("{\"matches\": []}"))).isEmpty();
            assertThat(DependencyScanner.findings(MAPPER.readTree("{\"descriptor\": {}}"))).isEmpty();
        }
    }

    @Nested
    @DisplayName("running the two tools")
    class Running {

        private final ContainerRunner runner = mock(ContainerRunner.class);
        private final DependencyScanner scanner = new DependencyScanner(runner, ScannerImages.PINNED);

        @Test
        @DisplayName("the cataloguer runs offline on a read-only tree; only the matcher gets the network")
        void onlyTheMatcherIsOnline() {
            when(runner.run(any())).thenReturn(new ContainerResult("{\"artifacts\": []}", "", 0));

            String owner = Workspace.withWorkspace(workspace -> {
                scanner.sbomOfDirectory(workspace, null);
                scanner.matchSbom(workspace, "{}");
                return ContainerRun.ownerOf(workspace.root()).orElseThrow();
            });

            ArgumentCaptor<ContainerRun> runs = ArgumentCaptor.forClass(ContainerRun.class);
            verify(runner, org.mockito.Mockito.times(2)).run(runs.capture());
            ContainerRun syft = runs.getAllValues().get(0);
            ContainerRun grype = runs.getAllValues().get(1);

            assertThat(syft.image()).isEqualTo(ScannerImages.PINNED.syft());
            assertThat(syft.network()).isFalse();
            assertThat(syft.mounts()).allSatisfy(mount -> assertThat(mount.readOnly()).isTrue());

            assertThat(grype.image()).isEqualTo(ScannerImages.PINNED.grype());
            assertThat(grype.network()).isTrue();
            // As the workspace's owner, not root: what it writes into the database mount has to be
            // deletable by the process that removes the workspace.
            assertThat(grype.asRoot()).isFalse();
            assertThat(grype.user()).isEqualTo(owner);
            // The database cache is the one place it may write; the SBOM mount stays read-only.
            assertThat(grype.mounts()).filteredOn(ContainerRun.Mount::readOnly).hasSize(1);
            assertThat(grype.mounts()).filteredOn(mount -> !mount.readOnly())
                    .singleElement()
                    .satisfies(mount -> assertThat(mount.target()).isEqualTo(ContainerPaths.DATABASE_CACHE));
        }

        @Test
        @DisplayName("a matcher that prints nothing usable did not analyse: absent, not an empty list")
        void unusableOutputIsAbsent() {
            when(runner.run(any())).thenReturn(new ContainerResult("database does not exist", "", 0));

            assertThat(scanner.matchStandaloneSbom("{}")).isEmpty();
        }

        @Test
        @DisplayName("a matcher that fails is reported, not read as a clean analysis")
        void aFailureIsAFailure() {
            when(runner.run(any())).thenReturn(new ContainerResult("", "no space left on device", 1));

            assertThatThrownBy(() -> scanner.matchStandaloneSbom("{}")).isInstanceOf(ScannerFailureException.class);
        }

        @Test
        @DisplayName("a standalone SBOM is staged in a directory that is gone afterwards, failure included")
        void theStagingDirectoryGoes() {
            List<Path> staged = new ArrayList<>();
            when(runner.run(any())).thenAnswer(invocation -> {
                ContainerRun run = invocation.getArgument(0);
                Path mounted = Path.of(run.mounts().getFirst().source());
                assertThat(mounted.resolve("sbom.json")).hasContent("{\"artifacts\": []}");
                staged.add(mounted);
                return new ContainerResult("", "boom", 2);
            });

            assertThatThrownBy(() -> scanner.matchStandaloneSbom("{\"artifacts\": []}"))
                    .isInstanceOf(ScannerFailureException.class);

            assertThat(staged).singleElement().satisfies(directory -> assertThat(directory).doesNotExist());
        }

        @Test
        @DisplayName("an exported image is deleted as soon as its SBOM is read, even when the read fails")
        void theImageArchiveGoes() {
            doAnswer(invocation -> {
                        Files.writeString(invocation.getArgument(2), "an image several hundred megabytes long");
                        return null;
                    })
                    .when(runner)
                    .exportImage(eq("registry.example.invalid/shop:1.4.2"), eq(DependencyScanner.DEFAULT_PLATFORM), any());
            when(runner.run(any())).thenReturn(new ContainerResult("", "unexpected EOF", 1));

            Workspace.withWorkspace(workspace -> {
                assertThatThrownBy(() -> scanner.sbomOfImage(
                                workspace, "registry.example.invalid/shop:1.4.2", DependencyScanner.DEFAULT_PLATFORM))
                        .isInstanceOf(ScannerFailureException.class);
                assertThat(workspace.root().resolve("image.tar")).doesNotExist();
                return null;
            });
        }
    }
}
