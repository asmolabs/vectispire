package com.asmolabs.vectispire.core.issues;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.Triage;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.issues.VexJustification;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.Issues;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositories;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Clock;
import java.time.Period;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Revisiting an exception, and the register that has to show it.
 *
 * <h2>Why a review that changes nothing is the interesting call</h2>
 *
 * <p><b>Every other write in this product exists because something moved.</b> Periodic review is
 * the one control performed correctly by leaving a decision exactly as it was — so it was the one
 * activity that left no evidence precisely when it was done right. "Granted in January, expires in
 * December" reads identically whether somebody checked it every quarter or nobody has opened it
 * since, and clause 8.1 is about exactly that difference.
 *
 * <h2>And why the register had to be rewritten first</h2>
 *
 * <p>It read triage <em>events</em>, one row per decision. An exception granted, expired and
 * granted again appeared twice and was counted twice; one that had since been withdrawn kept its
 * row for ever. A register of current exceptions listing exceptions that no longer exist is the
 * one thing it must never do, and reviews — which add events without changing a decision — would
 * have made both far worse.
 */
@DisplayName("reviewing an exception")
class ExceptionReviewTest extends VectispireContextTest {

    @Autowired
    private IssueTriageService triage;

    @Autowired
    private ExceptionsRegisterService register;

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Issues issues;

    @Autowired
    private Clock clock;

    @Test
    @DisplayName("records that somebody looked, when looking changed nothing")
    void confirmationLeavesEvidence() {
        long issueId = excepted();

        assertThat(entry(issueId).lastReviewedAt())
                .as("granted and never revisited — the value an assessment asks about")
                .isNull();

        triage.review(issueId, IssueTriageService.ReviewOutcome.CONFIRMED, "Still not reachable.", "n.faure", null);

        assertThat(entry(issueId)).satisfies(entry -> {
            assertThat(entry.lastReviewedAt()).isNotNull();
            assertThat(entry.lastReviewedBy()).isEqualTo("n.faure");
            assertThat(entry.decision())
                    .as("a confirmation confirms: the exception is exactly as it was")
                    .isEqualTo(TriageStatus.NOT_AFFECTED.wireName());
        });
    }

    @Test
    @DisplayName("counts the exceptions nobody has revisited")
    void countsNeverReviewed() {
        excepted();
        long reviewed = excepted();

        assertThat(register.register(200, null, Visibility.everything()).neverReviewed()).isEqualTo(2);

        triage.review(reviewed, IssueTriageService.ReviewOutcome.CONFIRMED, null, "n.faure", null);

        assertThat(register.register(200, null, Visibility.everything()).neverReviewed()).isEqualTo(1);
    }

    @Test
    @DisplayName("drops a revoked exception from the register rather than leaving its row behind")
    void revocationLeavesTheRegister() {
        long issueId = excepted();

        triage.review(issueId, IssueTriageService.ReviewOutcome.REVOKED, "No longer true.", "n.faure", null);

        assertThat(register.register(200, null, Visibility.everything()).entries())
                .as("a register of current exceptions listing a withdrawn one is the one thing it must not do")
                .extracting(ExceptionsRegisterService.ExceptionEntry::issueId)
                .doesNotContain(issueId);
        assertThat(issues.findById(issueId).orElseThrow().getTriageStatus())
                .isEqualTo(TriageStatus.UNDER_REVIEW.wireName());
        assertThat(issues.findById(issueId).orElseThrow().getTriageExpiresAt())
                .as("an expiry surviving a revocation would bring it back through expireStale as a lapse")
                .isNull();
    }

    @Test
    @DisplayName("counts one exception once, however many times it was decided")
    void countsAnExceptionOnce() {
        long issueId = excepted();
        // Granted, withdrawn, granted again: three decision events on one issue.
        triage.review(issueId, IssueTriageService.ReviewOutcome.REVOKED, null, "n.faure", null);
        grant(issueId);

        ExceptionsRegisterService.Register current = register.register(200, null, Visibility.everything());

        assertThat(current.entries())
                .as("the register lists exceptions, not the decisions that produced them")
                .hasSize(1);
        assertThat(current.granted()).isEqualTo(1);
    }

    @Test
    @DisplayName("moves the date when an exception is extended")
    void extensionMovesTheDate() {
        long issueId = excepted();
        // Truncated to the millisecond the store keeps: SQLite holds an Instant as epoch millis,
        // so comparing against a microsecond-precision clock would fail on the storage and not on
        // the behaviour.
        var newDate = clock.instant().plusSeconds(400L * 86_400).truncatedTo(java.time.temporal.ChronoUnit.MILLIS);

        triage.review(issueId, IssueTriageService.ReviewOutcome.EXTENDED, "One more release.", "n.faure", newDate);

        assertThat(entry(issueId).expiresAt()).isEqualTo(newDate);
        assertThat(entry(issueId).lastReviewedAt()).isNotNull();
    }

    @Test
    @DisplayName("refuses to extend without the date it now runs to")
    void extensionNeedsADate() {
        long issueId = excepted();

        assertThatThrownBy(() ->
                        triage.review(issueId, IssueTriageService.ReviewOutcome.EXTENDED, null, "n.faure", null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("refuses to review an issue carrying no exception")
    void refusesAnIssueWithNoException() {
        IssueEntity plain = new IssueEntity();
        plain.setRepoId(repository());
        plain.setFingerprint("plain");
        plain.setIdentifier("PLAIN");
        plain.setType(FindingType.VULNERABILITY.wireName());
        plain.setSeverity(Severity.HIGH.wireName());
        plain.setState(IssueState.OPEN.wireName());
        plain.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        plain.setIsKev(false);
        plain.setFirstSeenAt(clock.instant());
        plain.setLastSeenAt(clock.instant());
        plain.setTimesSeen(1);
        long issueId = issues.save(plain).getId();

        assertThatThrownBy(() ->
                        triage.review(issueId, IssueTriageService.ReviewOutcome.CONFIRMED, null, "n.faure", null))
                .as("a row in the register for something nobody excepted is exactly the noise it avoids")
                .isInstanceOf(IllegalArgumentException.class);
    }

    private ExceptionsRegisterService.ExceptionEntry entry(long issueId) {
        return register.register(200, null, Visibility.everything()).entries().stream()
                .filter(candidate -> candidate.issueId() == issueId)
                .findFirst()
                .orElseThrow(() -> new AssertionError("no register entry for issue " + issueId));
    }

    private long excepted() {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repository());
        issue.setFingerprint("fp-" + System.nanoTime());
        issue.setIdentifier("CVE-2026-0001");
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setIsKev(false);
        issue.setFirstSeenAt(clock.instant());
        issue.setLastSeenAt(clock.instant());
        issue.setTimesSeen(1);
        long issueId = issues.save(issue).getId();
        grant(issueId);
        return issueId;
    }

    private void grant(long issueId) {
        triage.triage(
                issueId,
                new Triage.Request(
                        TriageStatus.NOT_AFFECTED,
                        "c.moreau",
                        VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
                        "Not on the executed path.",
                        Period.ofDays(90)),
                true);
    }

    private Long repository() {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl("ssh://git@example.com/team/app-" + System.nanoTime() + ".git");
        entity.setName("app");
        entity.setBranch("main");
        return repositories.save(entity).getId();
    }
}
