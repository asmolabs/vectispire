package com.asmolabs.zanshin.common.domain.gate;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.zanshin.common.domain.gate.SecurityOverview.LatestScan;
import com.asmolabs.zanshin.common.domain.gate.SecurityOverview.NamedTarget;
import com.asmolabs.zanshin.common.domain.gate.SecurityOverview.Observation;
import com.asmolabs.zanshin.common.domain.issues.FindingType;
import com.asmolabs.zanshin.common.domain.issues.Severity;
import com.asmolabs.zanshin.common.domain.scans.ScanStatus;
import com.asmolabs.zanshin.common.domain.targets.ScanTarget;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("security overview")
class SecurityOverviewTest {

    private static final ScanTarget REPO = new ScanTarget.Repository(1);
    private static final ScanTarget IMAGE = new ScanTarget.Container(1);
    private static final Instant AT = Instant.parse("2026-08-10T08:00:00Z");

    private static SecurityOverview.Input input(
            Map<ScanTarget, List<GateIssue>> issues, Map<ScanTarget, LatestScan> scans) {
        return new SecurityOverview.Input(
                List.of(new NamedTarget(REPO, "api-service"), new NamedTarget(IMAGE, "api-image")),
                Map.of(),
                Optional.empty(),
                issues,
                scans);
    }

    private static GateIssue critical(long id) {
        return new GateIssue(id, true, FindingType.VULNERABILITY, Severity.CRITICAL, "CVE-" + id, "pkg", null, false, null);
    }

    private static LatestScan scan(ScanStatus status) {
        return new LatestScan(7, status, AT);
    }

    @Test
    @DisplayName("a repository and a container sharing an id are two different targets")
    void targetsWithTheSameIdDoNotShareIssues() {
        // The reason issues are keyed by a sealed target and not by a number. Keyed by id,
        // the container would inherit the repository's backlog and its verdict.
        SecurityOverview.Overview overview = SecurityOverview.build(input(
                Map.of(REPO, List.of(critical(1))),
                Map.of(REPO, scan(ScanStatus.COMPLETED), IMAGE, scan(ScanStatus.COMPLETED))));

        assertThat(overview.targets())
                .filteredOn(posture -> posture.target().equals(IMAGE))
                .singleElement()
                .satisfies(posture -> assertThat(posture.passed()).isTrue());
        assertThat(overview.failingCount()).isEqualTo(1);
    }

    @Test
    @DisplayName("a target never scanned passes, and says it was never looked at")
    void neverScannedPassesButIsNotObserved() {
        // The distinction the screen exists for. An empty backlog passes every policy, so a
        // target nobody has scanned reads as healthy — the worst posture there is, presented
        // as the best.
        SecurityOverview.Overview overview = SecurityOverview.build(input(Map.of(), Map.of()));

        assertThat(overview.targets()).allSatisfy(posture -> {
            assertThat(posture.passed()).isTrue();
            assertThat(posture.observed()).isFalse();
            assertThat(posture.observation()).isEqualTo(Observation.NEVER_SCANNED);
        });
        assertThat(overview.neverScannedCount()).isEqualTo(2);
    }

    @Test
    @DisplayName("a target whose last scan failed is not observed either")
    void failedScanIsNotObserved() {
        SecurityOverview.Overview overview = SecurityOverview.build(
                input(Map.of(), Map.of(REPO, scan(ScanStatus.FAILED), IMAGE, scan(ScanStatus.COMPLETED))));

        assertThat(overview.lastScanFailedCount()).isEqualTo(1);
        assertThat(overview.targets())
                .filteredOn(posture -> posture.target().equals(REPO))
                .singleElement()
                .satisfies(posture -> {
                    assertThat(posture.observed()).isFalse();
                    assertThat(posture.observation()).isEqualTo(Observation.LAST_SCAN_FAILED);
                });
    }

    @Test
    @DisplayName("a scan still running is neither a failure nor an observation")
    void inFlightScanIsItsOwnState() {
        SecurityOverview.Overview overview = SecurityOverview.build(
                input(Map.of(), Map.of(REPO, scan(ScanStatus.SCANNING), IMAGE, scan(ScanStatus.PENDING))));

        assertThat(overview.targets()).allSatisfy(posture -> {
            assertThat(posture.observation()).isEqualTo(Observation.IN_PROGRESS);
            assertThat(posture.observed()).isFalse();
        });
        assertThat(overview.neverScannedCount()).isZero();
        assertThat(overview.lastScanFailedCount()).isZero();
    }

    @Test
    @DisplayName("the KEV banner counts what the verdicts actually held against a target")
    void kevCountFollowsTheVerdict() {
        // Counted over evaluated issues, not the raw backlog: a KEV that a triage decision has
        // settled does not weigh on any verdict, and a banner counting it would show a number
        // that corresponds to nothing on the screen below it.
        GateIssue kev = new GateIssue(2, true, FindingType.VULNERABILITY, Severity.LOW, "CVE-2", "pkg", null, true, null);
        GateIssue settledKev = new GateIssue(3, true, FindingType.VULNERABILITY, Severity.LOW, "CVE-3", "pkg", null, true,
                com.asmolabs.zanshin.common.domain.issues.TriageStatus.NOT_AFFECTED);

        SecurityOverview.Overview overview = SecurityOverview.build(input(
                Map.of(REPO, List.of(kev, settledKev)), Map.of(REPO, scan(ScanStatus.COMPLETED))));

        assertThat(overview.kevCount()).isEqualTo(1);
    }

    @Test
    @DisplayName("a target's own policy replaces the global one rather than merging with it")
    void targetPolicyWins() {
        PolicyResolution.StoredPolicy strictGlobal =
                new PolicyResolution.StoredPolicy(new GatePolicy(Severity.LOW, true, false, false, false), 4);
        PolicyResolution.StoredPolicy lenientTarget =
                new PolicyResolution.StoredPolicy(new GatePolicy(Severity.CRITICAL, false, false, false, false), 9);

        GateIssue high = new GateIssue(1, true, FindingType.VULNERABILITY, Severity.HIGH, "CVE-1", "pkg", null, false, null);

        SecurityOverview.Overview overview = SecurityOverview.build(new SecurityOverview.Input(
                List.of(new NamedTarget(REPO, "api-service")),
                Map.of(REPO, lenientTarget),
                Optional.of(strictGlobal),
                Map.of(REPO, List.of(high)),
                Map.of(REPO, scan(ScanStatus.COMPLETED))));

        // A half-inherited policy is impossible to reason about when a build fails.
        assertThat(overview.targets()).singleElement().satisfies(posture -> {
            assertThat(posture.passed()).isTrue();
            assertThat(posture.policy().source()).isEqualTo(PolicyResolution.Source.TARGET);
            assertThat(posture.policy().describeSource()).isEqualTo("the target's policy v9");
        });
    }

    @Test
    @DisplayName("with nothing stored, the built-in policy applies and says so")
    void fallsBackToBuiltIn() {
        SecurityOverview.Overview overview = SecurityOverview.build(input(Map.of(), Map.of()));

        assertThat(overview.targets()).allSatisfy(posture -> {
            assertThat(posture.policy().source()).isEqualTo(PolicyResolution.Source.BUILT_IN);
            assertThat(posture.policy().version()).isEmpty();
            assertThat(posture.policy().describeSource()).isEqualTo("the application's default policy");
        });
    }
}
