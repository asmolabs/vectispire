package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.targets.ImageReference;
import com.asmolabs.vectispire.common.scanning.scanners.SecretsScanner.SecretFinding;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("what a scan is asked to do, and what it reports back")
class ScanTaskTest {

    @Nested
    @DisplayName("the task")
    class Task {

        @Test
        @DisplayName("a target is a repository or an image, and cannot be both")
        void targetIsExclusive() {
            // The original carried an optional image reference beside a URL and switched on
            // whichever was set, with a comment saying they are mutually exclusive. A sealed
            // interface says it instead, and the switch that dispatches on it has to handle
            // both cases or fail to compile.
            assertThat(ScanTask.Target.class.getPermittedSubclasses())
                    .extracting(Class::getSimpleName)
                    .containsExactlyInAnyOrder("Repository", "Image");
        }

        @Test
        @DisplayName("a step nobody asked for does not run")
        void stepsAreOptIn() {
            ScanTask task = new ScanTask(
                    new ScanTask.Target.Repository("https://host/p.git", "main", null, null),
                    null,
                    Set.of(ScanTask.Step.SECRETS));

            assertThat(task.runs(ScanTask.Step.SECRETS)).isTrue();
            assertThat(task.runs(ScanTask.Step.SAST)).isFalse();
            assertThat(task.runs(ScanTask.Step.DEPENDENCIES)).isFalse();
        }

        @Test
        @DisplayName("the rule set travels on the task, not read by the executor")
        void ruleSetIsCarried() {
            // An agent reading "the active set" for itself would scan with whatever it found at
            // the moment it asked, and two agents could diverge — resolving and recreating the
            // SAST backlog as they take turns.
            ScanTask task = new ScanTask(
                    new ScanTask.Target.Repository("https://host/p.git", "main", null, null),
                    "abc123",
                    Set.of(ScanTask.Step.SAST));

            assertThat(task.rulesHash()).isEqualTo("abc123");
        }

        @Test
        @DisplayName("an image target has no sub-path, because it has no tree")
        void imageHasNoSubPath() {
            ScanTask task = new ScanTask(
                    new ScanTask.Target.Image(new ImageReference(null, "nginx", "1.27"), "linux/amd64"),
                    null,
                    Set.of(ScanTask.Step.DEPENDENCIES));

            assertThat(task.subPath()).isEmpty();
        }
    }

    @Nested
    @DisplayName("the artifacts")
    class Artifacts {

        @Test
        @DisplayName("a step that did not run is absent, not empty")
        void absentIsNotEmpty() {
            // The distinction decides the fate of the backlog for each finding type. An empty
            // list means "analysed, found nothing" and resolves every existing issue; absent
            // changes nothing (decision 0007).
            ScanArtifacts nothing = ScanArtifacts.builder().build(Duration.ZERO);

            assertThat(nothing.secrets()).isEmpty();
            assertThat(nothing.sast()).isEmpty();
            assertThat(nothing.dependencies()).isEmpty();
            assertThat(nothing.sbom()).isEmpty();
        }

        @Test
        @DisplayName("a step that ran and found nothing is present and empty")
        void ranAndFoundNothing() {
            ScanArtifacts clean = ScanArtifacts.builder().secrets(List.of()).build(Duration.ZERO);

            assertThat(clean.secrets()).isPresent();
            assertThat(clean.secrets().orElseThrow()).isEmpty();
        }

        @Test
        @DisplayName("a failure is recorded by name, and leaves its artifact absent")
        void failuresAreNamed() {
            // An operator has to know what they are not seeing. A scan reporting no secrets
            // after the secrets step crashed is the failure this record exists to prevent.
            ScanArtifacts failed = ScanArtifacts.builder()
                    .secrets(List.of(new SecretFinding("aws-key", "AWS", "app.py", 3, null)))
                    .failed("SAST", "rule set abc123 could not be fetched")
                    .build(Duration.ofSeconds(12));

            assertThat(failed.sast()).isEmpty();
            assertThat(failed.secrets()).isPresent();
            assertThat(failed.failures()).singleElement().satisfies(failure -> {
                assertThat(failure.step()).isEqualTo("SAST");
                assertThat(failure.reason()).contains("abc123");
            });
            assertThat(failed.duration()).isEqualTo(Duration.ofSeconds(12));
        }

        @Test
        @DisplayName("the failure list is immutable once built")
        void failuresAreCopied() {
            ScanArtifacts.Builder builder = ScanArtifacts.builder().failed("SAST", "x");
            ScanArtifacts built = builder.build(Duration.ZERO);
            builder.failed("IaC", "y");

            assertThat(built.failures()).hasSize(1);
        }
    }
}
