package com.asmolabs.zanshin.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.zanshin.common.domain.issues.FindingType;
import com.asmolabs.zanshin.common.domain.issues.IssueState;
import com.asmolabs.zanshin.common.domain.issues.Severity;
import com.asmolabs.zanshin.common.domain.issues.Triage;
import com.asmolabs.zanshin.common.domain.issues.TriageStatus;
import com.asmolabs.zanshin.common.domain.issues.VexJustification;
import com.asmolabs.zanshin.common.domain.settings.Setting;
import com.asmolabs.zanshin.core.ZanshinContextTest;
import com.asmolabs.zanshin.core.persistence.IssueEntity;
import com.asmolabs.zanshin.core.repositories.Issues;
import java.time.Instant;
import java.time.Period;
import java.time.temporal.ChronoUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Triage and settings against a database.
 *
 * <p>Two small services with one thing in common: their queries are the whole of them. The
 * expiry sweep selects on a timestamp and the settings write is an update-or-insert, and both
 * are the kind of statement that reads correct against a fake and is wrong in SQL.
 */
@DisplayName("triage and settings, against a database")
class TriageAndSettingsDatabaseTest extends ZanshinContextTest {

    @Autowired
    private IssueTriageService triage;

    @Autowired
    private SettingsService settings;

    @Autowired
    private Issues issues;

    @Test
    @DisplayName("a decision is written, review date included")
    void aDecisionIsStored() {
        long id = issue();

        IssueEntity triaged = triage.triage(id, new Triage.Request(
                TriageStatus.NOT_AFFECTED, "alice", VexJustification.VULNERABLE_CODE_NOT_PRESENT,
                "Not compiled in.", Period.ofDays(90)));

        assertThat(issues.findById(triaged.getId()).orElseThrow())
                .returns(TriageStatus.NOT_AFFECTED.wireName(), IssueEntity::getTriageStatus)
                .returns("alice", IssueEntity::getTriagedBy);
        assertThat(issues.findById(id).orElseThrow().getTriageExpiresAt()).isNotNull();
    }

    @Test
    @DisplayName("the expiry sweep finds what is due and leaves what is not")
    void expirySelectsOnTheDate() {
        long due = issue();
        long later = issue();
        triage.triage(due, dismissFor(Period.ofDays(1)));
        triage.triage(later, dismissFor(Period.ofDays(365)));

        // Backdate the first, as a night passing would.
        IssueEntity stored = issues.findById(due).orElseThrow();
        stored.setTriageExpiresAt(Instant.now().minus(1, ChronoUnit.HOURS));
        issues.save(stored);

        assertThat(triage.expireStale()).containsExactly(due);
        assertThat(issues.findById(due).orElseThrow().getTriageStatus())
                .isEqualTo(TriageStatus.UNDER_REVIEW.wireName());
        assertThat(issues.findById(later).orElseThrow().getTriageStatus())
                .isEqualTo(TriageStatus.NOT_AFFECTED.wireName());
    }

    @Test
    @DisplayName("an expiry keeps who decided and why")
    void expiryKeepsTheEvidence() {
        long id = issue();
        triage.triage(id, dismissFor(Period.ofDays(1)));
        IssueEntity stored = issues.findById(id).orElseThrow();
        stored.setTriageExpiresAt(Instant.now().minusSeconds(60));
        issues.save(stored);

        triage.expireStale();

        // Erasing the reason turns a scheduled review into an investigation from scratch, which
        // is how a review date becomes a field people stop filling in.
        assertThat(issues.findById(id).orElseThrow())
                .returns("alice", IssueEntity::getTriagedBy)
                .returns("Not compiled in.", IssueEntity::getTriageComment);
    }

    @Test
    @DisplayName("a setting is inserted the first time and updated the second")
    void writingASettingTwiceUpdatesIt() {
        settings.set(Setting.SAST_ENABLED, "true");
        assertThat(settings.get(Setting.SAST_ENABLED)).isEqualTo("true");

        // The second write takes the update path. Read-then-write would attempt a second insert
        // and the primary key would refuse it rather than merge.
        settings.set(Setting.SAST_ENABLED, "false");
        assertThat(settings.get(Setting.SAST_ENABLED)).isEqualTo("false");
        assertThat(settings.stored()).hasSize(1);
    }

    @Test
    @DisplayName("a value deliberately cleared reads back cleared, not as the default")
    void anEmptyValueIsNotTheDefault() {
        settings.set(Setting.NOTIFICATION_MIN_SEVERITY, "");

        assertThat(settings.get(Setting.NOTIFICATION_MIN_SEVERITY)).isEmpty();
        assertThat(settings.effective()).containsEntry(Setting.NOTIFICATION_MIN_SEVERITY.key(), "");
    }

    private static Triage.Request dismissFor(Period expiry) {
        return new Triage.Request(
                TriageStatus.NOT_AFFECTED, "alice", VexJustification.VULNERABLE_CODE_NOT_PRESENT,
                "Not compiled in.", expiry);
    }

    private long issue() {
        IssueEntity issue = new IssueEntity();
        issue.setFingerprint("f-" + System.nanoTime());
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier("CVE-" + System.nanoTime());
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        return issues.save(issue).getId();
    }
}
