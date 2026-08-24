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
    @DisplayName("the failure message tells the operator where to look")
    void messageIsActionable() {
        assertThat(ScanQueue.LEASE_EXHAUSTED_MESSAGE).contains("agent's logs").contains("run the scan again");
    }
}
