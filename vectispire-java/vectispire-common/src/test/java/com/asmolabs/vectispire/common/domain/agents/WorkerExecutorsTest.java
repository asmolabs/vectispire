package com.asmolabs.vectispire.common.domain.agents;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("what a worker's executors let it claim")
class WorkerExecutorsTest {

    private static final List<String> BOTH = List.of("repository", "container");

    private static WorkerExecutors.Executor docker(boolean available) {
        return new WorkerExecutors.Executor("docker", available, BOTH, available ? null : "no ping");
    }

    @Test
    @DisplayName("a worker that never said claims every kind, as an agent older than the announcement did")
    void unknownClaimsEverything() {
        assertThat(WorkerExecutors.claimable(null)).isEqualTo(EnumSet.allOf(WorkerExecutors.Target.class));
    }

    @Test
    @DisplayName("an executor that cannot run anything gives no kind; an empty list gives none either")
    void unavailableClaimsNothing() {
        assertThat(new WorkerExecutors(List.of(docker(false))).claimable()).isEmpty();
        assertThat(WorkerExecutors.claimable(new WorkerExecutors(List.of()))).isEmpty();
    }

    @Test
    @DisplayName("an available executor gives the kinds it scans, and only those")
    void availableClaimsItsTargets() {
        assertThat(new WorkerExecutors(List.of(docker(true))).claimable())
                .containsExactlyInAnyOrder(WorkerExecutors.Target.REPOSITORY, WorkerExecutors.Target.CONTAINER);
        assertThat(new WorkerExecutors(List.of(
                        new WorkerExecutors.Executor("kubernetes", true, List.of("repository"), null))).claimable())
                .containsExactly(WorkerExecutors.Target.REPOSITORY);
    }

    @Test
    @DisplayName("the kinds of every available executor add up, an unavailable one's do not")
    void kindsAddUp() {
        WorkerExecutors two = new WorkerExecutors(List.of(
                new WorkerExecutors.Executor("kubernetes", true, List.of("repository"), null),
                new WorkerExecutors.Executor("docker", false, List.of("container"), "down")));
        assertThat(two.claimable()).containsExactly(WorkerExecutors.Target.REPOSITORY);
    }

    @Test
    @DisplayName("a kind this version does not know is ignored, not a reason to claim anything")
    void unknownTargetsAreIgnored() {
        WorkerExecutors later = new WorkerExecutors(List.of(
                new WorkerExecutors.Executor("wasm", true, List.of("firmware"), null)));
        assertThat(later.claimable()).isEmpty();
        assertThat(later.bounded().executors().getFirst().targets()).isEmpty();
    }

    @Test
    @DisplayName("what an agent says is clipped and cleaned, never refused")
    void bounded() {
        WorkerExecutors.Executor[] many = new WorkerExecutors.Executor[WorkerExecutors.MAX_EXECUTORS + 3];
        Arrays.fill(many, new WorkerExecutors.Executor(
                " " + "k".repeat(40) + " ", false, Arrays.asList("container", null, "repository"),
                "x".repeat(2_000)));
        WorkerExecutors bounded = new WorkerExecutors(Arrays.asList(many)).bounded();

        assertThat(bounded.executors()).hasSize(WorkerExecutors.MAX_EXECUTORS);
        WorkerExecutors.Executor first = bounded.executors().getFirst();
        assertThat(first.kind()).hasSize(WorkerExecutors.MAX_KIND_LENGTH).doesNotStartWith(" ");
        assertThat(first.detail()).hasSize(WorkerExecutors.MAX_DETAIL_LENGTH);
        assertThat(first.targets()).containsExactly("container", "repository");
        assertThat(new WorkerExecutors(List.of(new WorkerExecutors.Executor("docker", true, BOTH, "  ")))
                        .bounded().executors().getFirst().detail())
                .isNull();
        assertThat(new WorkerExecutors(Arrays.asList(docker(true), null)).executors()).hasSize(1);
    }

    @Test
    @DisplayName("the stored form reads back as it was written; nothing, or something unreadable, reads as unknown")
    void storedForm() {
        WorkerExecutors written = new WorkerExecutors(List.of(docker(false), docker(true)));
        assertThat(WorkerExecutors.read(written.write())).contains(written);
        assertThat(WorkerExecutors.read("[]")).contains(new WorkerExecutors(List.of()));
        assertThat(WorkerExecutors.read(null)).isEmpty();
        assertThat(WorkerExecutors.read(" ")).isEmpty();
        assertThat(WorkerExecutors.read("{not json")).isEmpty();
    }

    @Test
    @DisplayName("the reason is scrubbed as a failure's is: a URL's credentials do not reach the screen")
    void theDetailIsScrubbed() {
        WorkerExecutors said = new WorkerExecutors(List.of(new WorkerExecutors.Executor("kubernetes", false,
                List.of("repository"), "GET https://agent:s3cret@10.43.0.1/api answered 401\nsecond line"))).bounded();
        assertThat(said.executors().getFirst().detail()).doesNotContain("s3cret").doesNotContain("\n");
    }
}
