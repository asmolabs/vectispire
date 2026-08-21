package com.asmolabs.zanshin.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.zanshin.common.domain.targets.ImageReference;
import com.asmolabs.zanshin.common.scanning.scanners.ScannerImages;
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
