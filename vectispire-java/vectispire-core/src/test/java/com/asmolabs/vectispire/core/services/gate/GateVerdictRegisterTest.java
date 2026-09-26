package com.asmolabs.vectispire.core.services.gate;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.gate.RequestedPolicy;
import com.asmolabs.vectispire.common.domain.gate.SeverityRequest;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.persistence.GateVerdictEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.GateVerdicts;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import java.time.Clock;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Limit;

/**
 * The gate writes down what it answered, and a refusal is the entry that matters.
 *
 * <h2>Why this exists</h2>
 *
 * <p>The gate stored its policies and nothing else, so "every target passes" could not be
 * distinguished from "the gate has never stopped anything". A control whose refusals cannot be
 * exhibited is not a demonstrated control — and the gap was invisible, because a gate that
 * records nothing returns exactly the same verdict as one that records everything.
 *
 * <p>So the assertions below are not about the verdict, which was already tested: they are about
 * what survives it. A pass and a refusal both leave a row; the row says which, under which
 * policy, and against how many issues.
 */
@DisplayName("the gate's register")
class GateVerdictRegisterTest extends VectispireContextTest {

    @Autowired
    private GateService gate;

    @Autowired
    private GateVerdicts verdicts;

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
        issue(failing, "fp-low", Severity.LOW);
    }

    @Test
    @DisplayName("records a refusal, which is the entry the whole register exists for")
    void records_a_refusal() {
        gate.evaluateAndRecord(
                failing, tighten(Severity.HIGH), new GateService.Caller("ci-pipeline", "203.0.113.9"));

        GateVerdictEntity row = onlyRow();

        assertThat(row.isPassed())
                .as("a critical against a policy failing on high must refuse")
                .isFalse();
        assertThat(row.getViolations()).isPositive();
        assertThat(row.getCriticalCount()).isEqualTo(1);
        assertThat(row.getEvaluated())
                .as("kept beside the violations: a pass over nothing and a pass over four hundred "
                        + "issues are the same row without it")
                .isEqualTo(2);
        assertThat(row.getFailOnSeverity()).isEqualTo("high");
        assertThat(row.getDecidedBy()).isEqualTo("ci-pipeline");
        assertThat(row.getIpAddress()).isEqualTo("203.0.113.9");
        assertThat(row.getDecidedAt()).isBeforeOrEqualTo(clock.instant());
        assertThat(row.getRepoId()).isNotNull();
        assertThat(row.getContainerId()).isNull();
    }

    @Test
    @DisplayName("records a pass too, because a register of refusals alone proves nothing")
    void records_a_pass() {
        gate.evaluateAndRecord(clean, RequestedPolicy.none(), GateService.Caller.unattributed());

        GateVerdictEntity row = onlyRow();

        assertThat(row.isPassed()).isTrue();
        assertThat(row.getEvaluated())
                .as("nothing to judge — and that is exactly what has to be visible later")
                .isZero();
        assertThat(row.getDecidedBy()).isNull();
    }

    @Test
    @DisplayName("keeps the answer when the register cannot be written")
    void keeps_the_answer_when_recording_fails() {
        // The pipeline is waiting on a verdict. A register that cannot be written is a hole to
        // investigate, never a reason to fail somebody's build — so the answer must come back
        // even against a target whose row will not persist.
        ScanTarget vanished = new ScanTarget.Repository(999_999L);

        GateService.Decision decision =
                gate.evaluateAndRecord(vanished, RequestedPolicy.none(), GateService.Caller.unattributed());

        assertThat(decision.verdict().passed()).isTrue();
        assertThat(verdicts.findAllByOrderByDecidedAtDesc(Limit.of(10)))
                .as("the foreign key refuses the row, and the caller is not told about it")
                .isEmpty();
    }

    @Test
    @DisplayName("hands the register back newest first")
    void newest_first() {
        gate.evaluateAndRecord(clean, RequestedPolicy.none(), new GateService.Caller("first", null));
        gate.evaluateAndRecord(failing, tighten(Severity.HIGH), new GateService.Caller("second", null));

        assertThat(verdicts.findAllByOrderByDecidedAtDesc(Limit.of(10)))
                .hasSize(2)
                .extracting(GateVerdictEntity::getDecidedBy)
                .containsExactly("second", "first");
    }

    @Test
    @DisplayName("drops what is older than the retention window, and nothing newer")
    void purges_by_age() {
        gate.evaluateAndRecord(clean, RequestedPolicy.none(), GateService.Caller.unattributed());
        GateVerdictEntity aged = onlyRow();
        aged.setDecidedAt(clock.instant().minusSeconds(400L * 86_400));
        verdicts.save(aged);

        gate.evaluateAndRecord(failing, RequestedPolicy.none(), new GateService.Caller("recent", null));

        int removed = verdicts.deleteBefore(clock.instant().minusSeconds(90L * 86_400));

        assertThat(removed).isEqualTo(1);
        assertThat(verdicts.findAllByOrderByDecidedAtDesc(Limit.of(10)))
                .extracting(GateVerdictEntity::getDecidedBy)
                .containsExactly("recent");
    }

    private GateVerdictEntity onlyRow() {
        List<GateVerdictEntity> rows = verdicts.findAllByOrderByDecidedAtDesc(Limit.of(10));
        assertThat(rows).as("exactly one answer was asked for").hasSize(1);
        return rows.getFirst();
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
