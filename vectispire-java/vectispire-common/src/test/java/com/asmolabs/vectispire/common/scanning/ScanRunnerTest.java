package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.targets.ImageReference;
import com.asmolabs.vectispire.common.scanning.scanners.ScannerImages;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * A step that did not run says so.
 *
 * <p><b>This exists because it did not.</b> Every scanner reports its own failure by returning
 * an absent result rather than an empty list — that part was right, and it is what stops a
 * crashed analyser from resolving a target's whole backlog. But the call sites consumed it with
 * {@code ifPresent}, so the failure was dropped: the artifact stayed absent, {@code failures}
 * stayed empty, and the scan was recorded {@code completed} with nothing to show. An operator
 * reading an empty list saw a clean target instead of an analyser that never ran.
 *
 * <p>The image path is the one tested here because it needs no clone. The repository path shares
 * the mechanism — one helper, one failure channel — and its steps are covered against real
 * scanners by the integration campaign.
 */
@DisplayName("a scan whose scanner fails")
class ScanRunnerTest {

    private static final Clock FIXED = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);

    @Test
    @DisplayName("records the failure rather than reporting a completed scan with nothing in it")
    void aFailedStepIsReported() {
        // **Exit code zero, and nothing readable on stdout.** Deliberately not a non-zero exit:
        // that one already threw, and `step` already recorded it. The silent case is the
        // scanner that ends well and produces no usable report — a truncated stream, an empty
        // one, output that is not JSON — where `parseJson` returns an absent result and raises
        // nothing. That is the shape the old code dropped on the floor.
        ContainerRunner containers = mock(ContainerRunner.class);
        when(containers.run(any())).thenReturn(new ContainerRunner.ContainerResult("", "", 0));

        ScanArtifacts artifacts = runner(containers).run(new ScanTask(
                new ScanTask.Target.Image(new ImageReference(null, "nginx", "1.27"), "linux/amd64"),
                null,
                Set.of(ScanTask.Step.DEPENDENCIES)));

        assertThat(artifacts.dependencies())
                .describedAs("absent, not an empty list: an empty list resolves the target's backlog")
                .isEmpty();
        assertThat(artifacts.failures())
                .describedAs("the operator has to be told which scanner looked at nothing")
                .isNotEmpty();
        assertThat(artifacts.failures().getFirst().step()).isEqualTo("dependencies");
        assertThat(artifacts.observedNothing())
                .describedAs("nothing observed and something broken — the dispatcher must fail this scan")
                .isTrue();
    }

    @Test
    @DisplayName("a repository task's plugins reach the artifacts in their three states, and only the absent one is a failure")
    void pluginsAreRecorded(@org.junit.jupiter.api.io.TempDir Path root) throws java.io.IOException {
        Workspace workspace = new Workspace(root, root.resolve("source"), root.resolve("rules"));
        java.nio.file.Files.createDirectories(workspace.source());
        java.nio.file.Files.writeString(workspace.source().resolve("app.py"), "print(1)");
        ContainerRunner containers = mock(ContainerRunner.class);
        when(containers.outputBytes()).thenReturn(ScannerLimits.DEFAULT_OUTPUT_BYTES);
        when(containers.run(any())).thenReturn(new ContainerRunner.ContainerResult("", "", 0));

        var python = PluginStepsTest.manifest(Set.of(com.asmolabs.vectispire.common.domain.plugins.Language.PYTHON));
        var javaOnly = new com.asmolabs.vectispire.common.domain.plugins.PluginManifest("java-only", "J", python.image(),
                Set.of(com.asmolabs.vectispire.common.domain.plugins.Language.JAVA), java.util.List.of(), null, null,
                false, null, null);
        ScanRunner runner = new ScanRunner(containers, ScannerImages.PINNED, Path.of("unused"), hash -> java.util.List.of(),
                reference -> reference.id().equals("java-only") ? javaOnly : python, null,
                new GitClone.HostKeyPolicy.TrustEveryHost(), GitClone.WithoutKey.NONE, FIXED, Path.of("database-unused"));
        ScanTask task = new ScanTask(new ScanTask.Target.Repository("https://host/p.git", "main", null, null), null,
                Set.of(), java.util.List.of(
                        new com.asmolabs.vectispire.common.domain.plugins.PluginRef(python.id(), python.digest()),
                        new com.asmolabs.vectispire.common.domain.plugins.PluginRef(javaOnly.id(), javaOnly.digest())));

        ScanArtifacts.Builder builder = ScanArtifacts.builder();
        runner.runPlugins(task, workspace, workspace.source(), null, builder);
        ScanArtifacts artifacts = builder.build(java.time.Duration.ZERO);

        assertThat(artifacts.plugins()).extracting(step -> step.getClass().getSimpleName())
                .containsExactlyInAnyOrder("Absent", "NotApplicable");
        assertThat(artifacts.failures())
                .describedAs("the plugin that wrote no report is a failure under its name; the inapplicable one is not")
                .extracting(ScanArtifacts.Failure::step)
                .containsExactly("plugin acme-lint");
    }

    @Test
    @DisplayName("the tree's languages are kept whole, in the plugin manifests' vocabulary, and nothing is not unknown")
    void theCensusIsKept(@org.junit.jupiter.api.io.TempDir Path root) throws java.io.IOException {
        java.nio.file.Files.createDirectories(root.resolve("web/src"));
        java.nio.file.Files.writeString(root.resolve("pom.xml"), "<project/>");
        java.nio.file.Files.writeString(root.resolve("web/src/main.ts"), "export {}");
        java.nio.file.Files.writeString(root.resolve("README.md"), "#");

        ScanArtifacts.Builder builder = ScanArtifacts.builder();
        LanguageCensus.Census census = ScanRunner.census(root, builder);

        assertThat(builder.build(java.time.Duration.ZERO).languages())
                .describedAs("the wire names a manifest declares, so a screen compares the two as they are")
                .contains(Set.of("java", "typescript"));
        assertThat(census.complete()).isTrue();

        java.nio.file.Path prose = java.nio.file.Files.createDirectories(root.resolve("prose"));
        java.nio.file.Files.writeString(prose.resolve("NOTES.md"), "#");
        ScanArtifacts.Builder none = ScanArtifacts.builder();
        ScanRunner.census(prose, none);
        assertThat(none.build(java.time.Duration.ZERO).languages())
                .describedAs("a whole census that saw no language says so: recorded, and empty")
                .contains(Set.of());
    }

    @Test
    @DisplayName("a census that did not see the whole tree records nothing, which reads as unknown")
    void anIncompleteCensusIsAbsent(@org.junit.jupiter.api.io.TempDir Path root) {
        ScanArtifacts.Builder builder = ScanArtifacts.builder();
        LanguageCensus.Census census = ScanRunner.census(root.resolve("not-there"), builder);

        assertThat(census.complete()).isFalse();
        assertThat(builder.build(java.time.Duration.ZERO).languages())
                .describedAs("absent, never the partial or empty set: a screen would read it as \"no Java here\"")
                .isEmpty();
    }

    @Test
    @DisplayName("an image scan has no tree to count, and records no language")
    void anImageHasNoLanguages() {
        ContainerRunner containers = mock(ContainerRunner.class);
        when(containers.run(any())).thenReturn(new ContainerRunner.ContainerResult("", "", 0));

        ScanArtifacts artifacts = runner(containers).run(new ScanTask(
                new ScanTask.Target.Image(new ImageReference(null, "nginx", "1.27"), "linux/amd64"),
                null,
                Set.of(ScanTask.Step.DEPENDENCIES)));

        assertThat(artifacts.languages()).isEmpty();
    }

    private static ScanRunner runner(ContainerRunner containers) {
        return new ScanRunner(
                containers,
                ScannerImages.PINNED,
                Path.of("rules-unused-for-an-image-scan"),
                contentHash -> java.util.List.of(),
                new GitClone.HostKeyPolicy.TrustEveryHost(),
                GitClone.WithoutKey.NONE,
                FIXED);
    }
}
