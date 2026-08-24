package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.AuditLog;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The weekly posture report, wired.
 *
 * <p>What matters here is the <b>bookkeeping</b>, because it is the half that decides whether a
 * deployment gets one report a week, fifty-two at once, or none. That bookkeeping is the audit log
 * itself rather than a timestamp this service keeps, so it can only be checked against a database.
 */
@DisplayName("the weekly posture report")
class PostureDigestDatabaseTest extends VectispireContextTest {

    @Autowired
    private PostureDigestService digest;

    @Autowired
    private SettingsService settings;

    @Autowired
    private AuditLog auditLog;

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Issues issues;

    @Test
    @DisplayName("off by default, so an existing deployment's channels receive nothing new")
    void offByDefault() {
        configureAWebhook();

        // Switching this on for every deployment that upgrades would be a silent change to what
        // its channels are told, which is the one thing a notification must never be.
        assertThat(digest.runOnce()).isFalse();
        assertThat(sentCount()).isZero();
    }

    @Test
    @DisplayName("enabled with nowhere to send is not an hourly failure for a week")
    void noDestinationIsNotAFailure() {
        settings.set(Setting.DIGEST_ENABLED, "true");
        settings.set(Setting.WEBHOOK_URL, "");

        // A deployment that switched the report on and configured no destination has a
        // misconfiguration visible on the settings screen — not something to retry every hour and
        // log about until Monday.
        assertThat(digest.runOnce()).isFalse();
        assertThat(sentCount()).isZero();
    }

    @Test
    @DisplayName("one report per week, and the log is what remembers")
    void oncePerWeek() {
        settings.set(Setting.DIGEST_ENABLED, "true");
        configureAWebhook();
        repositoryWithAnIssue();

        // The send itself fails — nothing is listening on that URL — and that is deliberate here:
        // what is under test is the gating, and a failure must leave no audit entry, or a broken
        // relay on Monday would suppress the report for the rest of the week.
        digest.runOnce();
        assertThat(sentCount())
                .as("a failed send records nothing, so it can be retried")
                .isZero();
    }

    @Test
    @DisplayName("an entry already recorded this week stops a second report")
    void anExistingEntryIsRespected() {
        settings.set(Setting.DIGEST_ENABLED, "true");
        configureAWebhook();

        // Standing in for a report that went out earlier in the week: the service reads the log,
        // so this is exactly what it would see after a successful send.
        auditLog.save(entry());

        assertThat(digest.runOnce())
                .as("a report has already gone out since Monday")
                .isFalse();
        assertThat(sentCount()).isEqualTo(1);
    }

    private long sentCount() {
        return auditLog.findAllByOrderByTimestampAscIdAsc().stream()
                .filter(row -> AuditOperation.POSTURE_DIGEST_SENT.wireName().equals(row.getOperationType()))
                .count();
    }

    private com.asmolabs.vectispire.core.persistence.AuditLogEntity entry() {
        var row = new com.asmolabs.vectispire.core.persistence.AuditLogEntity();
        row.setOperationType(AuditOperation.POSTURE_DIGEST_SENT.wireName());
        row.setResourceId("earlier-this-week");
        row.setDescription("Weekly posture report sent");
        row.setTimestamp(Instant.now());
        return row;
    }

    private void configureAWebhook() {
        // `.invalid` resolves nowhere, which is what makes the send fail rather than reach
        // somebody else's server from a test suite.
        settings.set(Setting.WEBHOOK_URL, "https://hooks.invalid/weekly");
    }

    private void repositoryWithAnIssue() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/digest.git");
        repository.setBranch("main");
        long id = repositories.save(repository).getId();

        IssueEntity issue = new IssueEntity();
        issue.setRepoId(id);
        issue.setFingerprint("CVE-DIGEST-" + id);
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier("CVE-DIGEST");
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setFirstSeenAt(Instant.now().minus(Duration.ofDays(2)));
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        issues.save(issue);
    }
}
