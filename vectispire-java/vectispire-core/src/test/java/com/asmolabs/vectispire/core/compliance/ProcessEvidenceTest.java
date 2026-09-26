package com.asmolabs.vectispire.core.compliance;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.gate.RequestedPolicy;
import com.asmolabs.vectispire.common.domain.gate.SeverityRequest;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.compliance.internal.ProcessEvidenceService;
import com.asmolabs.vectispire.core.gate.GateService;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.Issues;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositories;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Clock;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The process evidence the bundle seals, as opposed to the posture it already carried.
 *
 * <h2>Why the assertions look like this</h2>
 *
 * <p>The bundle had eight sections and every one of them described <em>what the estate
 * contains</em>. An assessor who read all eight still had no answer to the question they actually
 * ask — did the control operate, throughout, and what did it produce — because the registers that
 * answer it existed only behind API routes nobody exports.
 *
 * <p>So what is asserted below is deliberately not "the numbers are right", which the register's
 * own suites cover. It is that a refusal recorded today <b>reaches the archive</b>, that the
 * archive carries the month it happened in, and that a scoped reader's copy says so on its face.
 * The last one is the failure that would be worst in the room: a partial archive read as the
 * estate's.
 */
@DisplayName("the process evidence sections")
class ProcessEvidenceTest extends VectispireContextTest {

    @Autowired
    private GateService gate;

    @Autowired
    private ProcessEvidenceService evidence;

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Issues issues;

    @Autowired
    private Clock clock;

    private ScanTarget failing;
    private ScanTarget clean;

    @BeforeEach
    void seed() {
        failing = new ScanTarget.Repository(repository("ssh://git@example.com/team/failing.git", "failing"));
        clean = new ScanTarget.Repository(repository("ssh://git@example.com/team/clean.git", "clean"));
        issue(failing, "fp-crit", Severity.CRITICAL);
    }

    @Test
    @DisplayName("carries a refusal into the archive, with the policy that produced it")
    void refusalReachesTheArchive() {
        gate.evaluateAndRecord(
                failing, tighten(Severity.HIGH), new GateService.Caller("ci-pipeline", "203.0.113.9"));

        ProcessEvidenceService.GateEvidence gateEvidence = evidence.gate(Visibility.everything());

        assertThat(gateEvidence.refused()).isEqualTo(1);
        assertThat(gateEvidence.refusals()).singleElement().satisfies(refusal -> {
            assertThat(refusal.failOnSeverity()).isEqualTo("high");
            assertThat(refusal.requestedBy())
                    .as("who asked is half the evidence — an unattributed refusal proves less")
                    .isEqualTo("ci-pipeline");
            assertThat(refusal.evaluated())
                    .as("a refusal over nothing and a refusal over four hundred issues must differ")
                    .isPositive();
        });
    }

    @Test
    @DisplayName("reports the month a verdict fell in, which is what shows the control did not lapse")
    void reportsMonthlyContinuity() {
        gate.evaluateAndRecord(clean, RequestedPolicy.none(), GateService.Caller.unattributed());
        gate.evaluateAndRecord(failing, tighten(Severity.HIGH), GateService.Caller.unattributed());

        String thisMonth = YearMonth.from(clock.instant().atZone(ZoneOffset.UTC)).toString();

        assertThat(evidence.gate(Visibility.everything()).monthly())
                .as("a total cannot show a silent August inside a busy year")
                .singleElement()
                .satisfies(month -> {
                    assertThat(month.month()).isEqualTo(thisMonth);
                    assertThat(month.total()).isEqualTo(2);
                    assertThat(month.refused()).isEqualTo(1);
                });
    }

    @Test
    @DisplayName("says on its face when the archive is one reader's slice of the estate")
    void scopedArchiveSaysSo() {
        gate.evaluateAndRecord(clean, RequestedPolicy.none(), GateService.Caller.unattributed());
        gate.evaluateAndRecord(failing, tighten(Severity.HIGH), GateService.Caller.unattributed());

        ProcessEvidenceService.GateEvidence slice = evidence.gate(Visibility.only(List.of(clean)));

        assertThat(slice.total()).as("the other repository's verdict is not this reader's").isEqualTo(1);
        assertThat(slice.refused()).isZero();
        assertThat(slice.coverage().scoped()).isTrue();
        assertThat(slice.coverage().note())
                .as("an assessor reading the file months later cannot ask whose estate this was")
                .contains("not the whole estate");
    }

    @Test
    @DisplayName("a whole-estate archive does not claim to be narrowed")
    void wholeEstateArchiveSaysSo() {
        gate.evaluateAndRecord(clean, RequestedPolicy.none(), GateService.Caller.unattributed());

        ProcessEvidenceService.Coverage coverage =
                evidence.gate(Visibility.everything()).coverage();

        assertThat(coverage.scoped()).isFalse();
        assertThat(coverage.truncated()).isFalse();
        assertThat(coverage.note()).contains("whole estate");
    }

    @Test
    @DisplayName("names what the installed rules can reach, so a zero is not read as clean")
    void coverageNamesWhatWasLookedFor() {
        ProcessEvidenceService.CoverageEvidence coverage = evidence.coverage(Visibility.everything());

        assertThat(coverage.ruleCoverage()).isNotNull();
        assertThat(coverage.ruleCoverage().state()).isNotNull();
        assertThat(coverage.freshnessDays())
                .as("the window applied to section 01, so its verdicts can be reproduced")
                .isNotNegative();
    }

    private static RequestedPolicy tighten(Severity severity) {
        return RequestedPolicy.none().with(new SeverityRequest.Threshold(severity));
    }

    private long repository(String url, String name) {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl(url);
        entity.setName(name);
        entity.setBranch("main");
        return repositories.save(entity).getId();
    }

    private void issue(ScanTarget target, String fingerprint, Severity severity) {
        IssueEntity issue = new IssueEntity();
        if (target instanceof ScanTarget.Repository repository) {
            issue.setRepoId(repository.id());
        }
        issue.setFingerprint(fingerprint);
        issue.setIdentifier(fingerprint.toUpperCase(java.util.Locale.ROOT));
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setSeverity(severity.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setIsKev(false);
        issue.setFirstSeenAt(clock.instant());
        issue.setLastSeenAt(clock.instant());
        issue.setTimesSeen(1);
        issues.save(issue);
    }
}
