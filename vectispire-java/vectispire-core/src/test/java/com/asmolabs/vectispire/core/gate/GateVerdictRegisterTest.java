package com.asmolabs.vectispire.core.gate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import com.asmolabs.vectispire.common.domain.gate.RequestedPolicy;
import com.asmolabs.vectispire.common.domain.gate.SeverityRequest;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.siem.CefEvent;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.access.RowVisibility;
import com.asmolabs.vectispire.common.domain.access.VisibleTarget;
import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.core.gate.persistence.GatePolicyRepository;
import com.asmolabs.vectispire.core.gate.persistence.GateVerdictEntity;
import com.asmolabs.vectispire.core.gate.persistence.GateVerdictRepository;
import com.asmolabs.vectispire.core.issues.IssueCatalog;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.rules.RuleCoverageService;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.siem.SiemEvents;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Clock;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Limit;
import org.springframework.transaction.support.TransactionTemplate;
import org.mockito.ArgumentCaptor;

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
    private GateVerdictRepository verdicts;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private Clock clock;

    @Autowired
    private IssueCatalog issueCatalog;

    @Autowired
    private GatePolicyRepository policies;

    @Autowired
    private TargetCatalog targets;

    @Autowired
    private ScanCatalog scans;

    @Autowired
    private RuleCoverageService ruleCoverage;

    @Autowired
    private TransactionTemplate transactions;

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
                checked(failing), tighten(Severity.HIGH), new GateService.Caller("ci-pipeline", "203.0.113.9"));

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
        gate.evaluateAndRecord(checked(clean), RequestedPolicy.none(), GateService.Caller.unattributed());

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
                gate.evaluateAndRecord(checked(vanished), RequestedPolicy.none(), GateService.Caller.unattributed());

        assertThat(decision.verdict().passed()).isTrue();
        assertThat(verdicts.findAllByOrderByDecidedAtDesc(Limit.of(10)))
                .as("the foreign key refuses the row, and the caller is not told about it")
                .isEmpty();
    }

    @Test
    @DisplayName("hands the register back newest first")
    void newest_first() {
        gate.evaluateAndRecord(checked(clean), RequestedPolicy.none(), new GateService.Caller("first", null));
        gate.evaluateAndRecord(checked(failing), tighten(Severity.HIGH), new GateService.Caller("second", null));

        assertThat(verdicts.findAllByOrderByDecidedAtDesc(Limit.of(10)))
                .hasSize(2)
                .extracting(GateVerdictEntity::getDecidedBy)
                .containsExactly("second", "first");
    }

    @Test
    @DisplayName("drops what is older than the retention window, and nothing newer")
    void purges_by_age() {
        gate.evaluateAndRecord(checked(clean), RequestedPolicy.none(), GateService.Caller.unattributed());
        GateVerdictEntity aged = onlyRow();
        aged.setDecidedAt(clock.instant().minusSeconds(400L * 86_400));
        verdicts.save(aged);

        gate.evaluateAndRecord(checked(failing), RequestedPolicy.none(), new GateService.Caller("recent", null));

        int removed = verdicts.deleteBefore(clock.instant().minusSeconds(90L * 86_400));

        assertThat(removed).isEqualTo(1);
        assertThat(verdicts.findAllByOrderByDecidedAtDesc(Limit.of(10)))
                .extracting(GateVerdictEntity::getDecidedBy)
                .containsExactly("recent");
    }

    @Test
    @DisplayName("a refusal and its SIEM event are written in the verdict's transaction, not after it")
    void a_refusal_is_queued_with_its_verdict() {
        // Decision 0033: published after the verdict's own write, a stop between the two left a
        // refusal no SOC heard of. `enqueue` is MANDATORY — it can only have been called inside the
        // transaction the verdict took — and `publish`, the after-the-fact path, is not used.
        SiemEvents siem = mock(SiemEvents.class);

        gateWith(siem).evaluateAndRecord(checked(failing), tighten(Severity.HIGH), new GateService.Caller("ci", null));

        ArgumentCaptor<CefEvent> queued = ArgumentCaptor.forClass(CefEvent.class);
        verify(siem).enqueue(queued.capture());
        assertThat(queued.getValue().eventType()).isEqualTo(SecurityEventType.SECURITY_GATE_FAILED);
        verify(siem, never()).publish(any());
        assertThat(onlyRow().isPassed()).isFalse();
    }

    @Test
    @DisplayName("an event that cannot be queued costs neither the verdict nor the answer: the two are recorded apart")
    void a_failing_event_falls_back_to_apart() {
        SiemEvents siem = mock(SiemEvents.class);
        doThrow(new IllegalStateException("outbox unavailable")).when(siem).enqueue(any());

        GateService.Decision decision = gateWith(siem)
                .evaluateAndRecord(checked(failing), tighten(Severity.HIGH), new GateService.Caller("ci", null));

        assertThat(decision.verdict().passed()).as("the pipeline still gets its answer").isFalse();
        assertThat(onlyRow().getDecidedBy()).as("the verdict written once, alone").isEqualTo("ci");
        verify(siem).publish(any());
    }

    /** The gate as wired, with the SIEM stood in for — a new context would cost more than the two tests. */
    private GateService gateWith(SiemEvents siem) {
        return new GateService(issueCatalog, policies, verdicts, targets, scans, ruleCoverage, siem, clock, transactions);
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

    /** The proof the gate takes, minted by the guard as its route does, for a caller who sees all. */
    private static VisibleTarget<?> checked(ScanTarget target) {
        return RowVisibility.requireVisible(target, Visibility.everything());
    }
}
