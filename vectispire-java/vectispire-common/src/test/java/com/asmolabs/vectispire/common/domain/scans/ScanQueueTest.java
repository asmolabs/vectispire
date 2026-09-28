package com.asmolabs.vectispire.common.domain.scans;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("scan queue")
class ScanQueueTest {

    private static final Instant NOW = Instant.parse("2026-08-13T10:00:00Z");
    private static final ScanQueue.Policy POLICY = ScanQueue.Policy.DEFAULT;

    @Test
    @DisplayName("capacity never goes negative")
    void capacityIsFloored() {
        // More running than the limit allows is a real state after the limit is lowered, and a
        // negative capacity would read as "start minus two scans" wherever it is compared.
        assertThat(ScanQueue.capacity(4, 1)).isEqualTo(3);
        assertThat(ScanQueue.capacity(4, 4)).isZero();
        assertThat(ScanQueue.capacity(4, 9)).isZero();
    }

    @Test
    @DisplayName("a lease with no expiry counts as lapsed")
    void absentLeaseIsLapsed() {
        // A lease that never expires is not a lease. Reading absence as "still held" strands
        // the row forever, and nothing on screen says why the scan never runs.
        assertThat(ScanQueue.leaseHasLapsed(null, NOW)).isTrue();
        assertThat(ScanQueue.leaseHasLapsed(NOW.minusSeconds(1), NOW)).isTrue();
        assertThat(ScanQueue.leaseHasLapsed(NOW.plusSeconds(1), NOW)).isFalse();
    }

    @Test
    @DisplayName("requeues until the attempt cap, then fails for good")
    void capsTheTakeovers() {
        // With no cap, a target that jams its worker every time circulates from agent to agent
        // indefinitely, consuming the fleet's capacity while the operator watches a scan
        // forever "about to start".
        assertThat(ScanQueue.afterLapse(0, POLICY)).isEqualTo(ScanQueue.Lapsed.REQUEUE);
        assertThat(ScanQueue.afterLapse(POLICY.maxAttempts() - 1, POLICY)).isEqualTo(ScanQueue.Lapsed.REQUEUE);
        assertThat(ScanQueue.afterLapse(POLICY.maxAttempts(), POLICY)).isEqualTo(ScanQueue.Lapsed.FAIL);
    }

    @Test
    @DisplayName("the policy is a parameter, so a test can shorten a twenty-minute lease")
    void policyIsInjectable() {
        // The original read these from the environment at class load, which no test can vary —
        // and a lease duration nobody can vary in a test is one nobody checks.
        ScanQueue.Policy quick = new ScanQueue.Policy(Duration.ofSeconds(5), 1, 3);

        assertThat(ScanQueue.leaseUntil(NOW, quick)).isEqualTo(NOW.plusSeconds(5));
        assertThat(ScanQueue.afterLapse(1, quick)).isEqualTo(ScanQueue.Lapsed.FAIL);
    }

    @Test
    @DisplayName("a permanent failure fails at once, on the first attempt as on the last")
    void aPermanentFailureFailsAtOnce() {
        assertThat(ScanQueue.afterFailure(1, FailureKind.PERMANENT, NOW, POLICY)).isEqualTo(new ScanQueue.Next.Fail(true));
        assertThat(ScanQueue.afterFailure(POLICY.maxAttempts(), FailureKind.PERMANENT, NOW, POLICY))
                .isEqualTo(new ScanQueue.Next.Fail(true));
    }

    @Test
    @DisplayName("a transient failure waits one minute, then five, and fails at the attempt limit")
    void aTransientFailureWaitsLongerEachTime() {
        assertThat(ScanQueue.afterFailure(1, FailureKind.TRANSIENT, NOW, POLICY))
                .isEqualTo(new ScanQueue.Next.Retry(NOW.plus(Duration.ofMinutes(1))));
        assertThat(ScanQueue.afterFailure(2, FailureKind.TRANSIENT, NOW, POLICY))
                .isEqualTo(new ScanQueue.Next.Retry(NOW.plus(Duration.ofMinutes(5))));
        // The third delay exists for a limit above three; at the default limit the third attempt is the last.
        assertThat(ScanQueue.afterFailure(3, FailureKind.TRANSIENT, NOW, POLICY)).isEqualTo(new ScanQueue.Next.Fail(false));
    }

    @Test
    @DisplayName("past the list the last delay repeats, and a refunded count waits the first")
    void delaysAreBoundedByTheList() {
        ScanQueue.Policy five = new ScanQueue.Policy(Duration.ofMinutes(20), 5, 12, ScanQueue.Policy.DEFAULT_RETRY_DELAYS);

        assertThat(ScanQueue.retryDelay(3, five)).isEqualTo(Duration.ofMinutes(15));
        assertThat(ScanQueue.retryDelay(4, five)).isEqualTo(Duration.ofMinutes(15));
        assertThat(ScanQueue.retryDelay(0, five)).isEqualTo(Duration.ofMinutes(1));
        assertThat(ScanQueue.afterFailure(4, FailureKind.TRANSIENT, NOW, five))
                .isEqualTo(new ScanQueue.Next.Retry(NOW.plus(Duration.ofMinutes(15))));
        assertThat(ScanQueue.afterFailure(5, FailureKind.TRANSIENT, NOW, five)).isEqualTo(new ScanQueue.Next.Fail(false));
    }

    @Test
    @DisplayName("the delays are configuration: none configured is no wait, a negative one is refused")
    void delaysAreConfigured() {
        ScanQueue.Policy none = new ScanQueue.Policy(Duration.ofMinutes(20), 3, 12, java.util.List.of());
        assertThat(ScanQueue.afterFailure(1, FailureKind.TRANSIENT, NOW, none)).isEqualTo(new ScanQueue.Next.Retry(NOW));

        ScanQueue.Policy quick = new ScanQueue.Policy(Duration.ofMinutes(20), 3, 12, java.util.List.of(Duration.ofSeconds(7)));
        assertThat(ScanQueue.afterFailure(2, FailureKind.TRANSIENT, NOW, quick))
                .isEqualTo(new ScanQueue.Next.Retry(NOW.plusSeconds(7)));

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> new ScanQueue.Policy(
                        Duration.ofMinutes(20), 3, 12, java.util.List.of(Duration.ofMinutes(-1))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("negative");
    }

    @Test
    @DisplayName("the default policy carries the decided delays")
    void theDefaultDelays() {
        assertThat(POLICY.retryDelays())
                .containsExactly(Duration.ofMinutes(1), Duration.ofMinutes(5), Duration.ofMinutes(15));
        assertThat(new ScanQueue.Policy(Duration.ofMinutes(20), 3, 12).retryDelays()).isEqualTo(POLICY.retryDelays());
    }

    @Test
    @DisplayName("the failure message tells the operator where to look")
    void messageIsActionable() {
        assertThat(ScanQueue.LEASE_EXHAUSTED_MESSAGE).contains("agent's logs").contains("run the scan again");
    }
}
