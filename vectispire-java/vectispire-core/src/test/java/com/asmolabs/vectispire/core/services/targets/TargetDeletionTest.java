package com.asmolabs.vectispire.core.services.targets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.targets.TargetDeleted;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.TriageEventEntity;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.TriageEvents;
import java.sql.Statement;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.IllegalTransactionStateException;

/**
 * Deleting a target takes every row that names it, and nobody else's.
 *
 * <p><b>It found a defect the day it was written.</b> A repository with a single triaged finding
 * could not be deleted: the purge queued the triage events' removal, the bulk delete of the issues
 * ran first and the cascade took the events, and the commit failed on rows that were no longer
 * there. Nothing had ever deleted a target carrying history. See {@code Issues#deleteByIdIn}.
 *
 * <p><b>No probe in this context, deliberately.</b> The order of the phases is {@code
 * TargetPurgeOrderTest}'s, whose probes flush the persistence context to look between phases — and
 * a flush there is exactly what hid the defect above. The same outcome runs against PostgreSQL and
 * MySQL in {@code TargetDeletionIntegrationTest}.
 */
@DisplayName("deleting a target")
class TargetDeletionTest extends VectispireContextTest {

    @Autowired
    private TargetDeletionService deletion;

    @Autowired
    private BeanFactory beans;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private ApplicationEventPublisher events;

    @Autowired
    private Issues issues;

    @Autowired
    private TriageEvents triageEvents;

    private TargetRowsFixture fixture;

    @BeforeEach
    void fixture() {
        fixture = new TargetRowsFixture(beans, jdbc);
    }

    @Test
    @DisplayName("takes a repository's rows in every dependent table, and nobody else's")
    void repository() {
        ScanTarget doomed = fixture.repository("doomed");
        ScanTarget survivor = fixture.repository("survivor");
        fixture.populate(doomed);
        fixture.populate(survivor);
        Map<String, Integer> before = fixture.rowsNaming(survivor);
        assertThat(fixture.rowsNaming(doomed).values()).as("the fixture wrote a row everywhere").doesNotContain(0);

        long repoId = ((ScanTarget.Repository) doomed).id();
        deletion.deleteRepository(repoId);

        assertThat(fixture.rowsNaming(doomed)).as("nothing naming the deleted repository remains")
                .allSatisfy((table, rows) -> assertThat(rows).as(table).isZero());
        assertThat(fixture.rowsNaming(survivor)).as("the other repository keeps every row").isEqualTo(before);
        assertThat(jdbc.queryForObject("select count(*) from t_repository where id = ?", Integer.class, repoId))
                .isZero();
    }

    @Test
    @DisplayName("takes a container image's rows the same way")
    void container() {
        ScanTarget doomed = fixture.container("doomed");
        ScanTarget survivor = fixture.container("survivor");
        fixture.populate(doomed);
        fixture.populate(survivor);
        Map<String, Integer> before = fixture.rowsNaming(survivor);

        long containerId = ((ScanTarget.Container) doomed).id();
        deletion.deleteContainer(containerId);

        assertThat(fixture.rowsNaming(doomed)).allSatisfy((table, rows) -> assertThat(rows).as(table).isZero());
        assertThat(fixture.rowsNaming(survivor)).isEqualTo(before);
        assertThat(jdbc.queryForObject("select count(*) from t_container where id = ?", Integer.class, containerId))
                .isZero();
    }

    @Test
    @DisplayName("takes triaged issues whose scans retention already purged")
    void issuesWithHistoryAndNoScans() {
        // The shape retention leaves behind: the scans and their findings gone, the issues kept with
        // their triage history. Nothing then queries the findings table between the triage events'
        // queued removal and the bulk delete of the issues — no incidental flush — so only the bulk
        // delete's own flush keeps the cascade from taking the events first.
        long repoId = ((ScanTarget.Repository) fixture.repository("retained")).id();
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setFingerprint("retained-" + repoId);
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.NOT_AFFECTED.wireName());
        issue.setFirstSeenAt(Instant.parse("2026-01-01T00:00:00Z"));
        issue.setLastSeenAt(Instant.parse("2026-01-01T00:00:00Z"));
        issue.setTimesSeen(1);
        long issueId = issues.save(issue).getId();
        TriageEventEntity event = new TriageEventEntity();
        event.setIssueId(issueId);
        event.setFromStatus(TriageStatus.UNDER_REVIEW.wireName());
        event.setToStatus(TriageStatus.NOT_AFFECTED.wireName());
        event.setOrigin("user");
        event.setOccurredAt(Instant.parse("2026-01-02T00:00:00Z"));
        triageEvents.save(event);

        deletion.deleteRepository(repoId);

        assertThat(jdbc.queryForObject("select count(*) from t_issue_triage_event", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("select count(*) from t_issue", Integer.class)).isZero();
    }

    @Test
    @DisplayName("a purge announced outside a transaction is refused, not committed piecemeal")
    void purgeNeedsTheDeletingTransaction() {
        ScanTarget target = fixture.repository("kept");
        fixture.populate(target);
        Map<String, Integer> before = fixture.rowsNaming(target);

        // Each listener would otherwise open its own transaction and commit its deletes while the
        // target stays: grants gone, issues gone, repository still listed.
        assertThatThrownBy(() -> events.publishEvent(new TargetDeleted(target)))
                .isInstanceOf(IllegalTransactionStateException.class);
        assertThat(fixture.rowsNaming(target)).isEqualTo(before);
    }

    @Test
    @DisplayName("sweeps the issues and scans of a target that is already gone, through the same listeners")
    void orphans() {
        ScanTarget gone = fixture.repository("gone");
        ScanTarget survivor = fixture.repository("survivor");
        fixture.populate(gone);
        fixture.populate(survivor);
        Map<String, Integer> before = fixture.rowsNaming(survivor);
        long repoId = ((ScanTarget.Repository) gone).id();
        // A deletion from before the keys were enforced: the target went, its rows stayed. On one
        // connection, since the pragma is per connection and the pool would hand out another.
        jdbc.execute((ConnectionCallback<Void>) connection -> {
            try (Statement statement = connection.createStatement()) {
                statement.execute("pragma foreign_keys = off");
                try {
                    statement.executeUpdate("delete from t_repository where id = " + repoId);
                } finally {
                    statement.execute("pragma foreign_keys = on");
                }
            }
            return null;
        });

        try {
            deletion.purgeOrphanedTargetData();

            Map<String, Integer> left = fixture.rowsNaming(gone);
            // Grants and gate policies have no parent to be orphaned from, and the sweep never took
            // them; the verdicts are the schema's cascade, which the pragma was off for.
            for (String table : List.of("t_scan", "t_issue", "t_issue_triage_event", "t_issue_ticket", "t_finding",
                    "t_component", "t_ai_review_result")) {
                assertThat(left.get(table)).as(table).isZero();
            }
            assertThat(fixture.rowsNaming(survivor)).as("a target that exists is not an orphan").isEqualTo(before);
        } finally {
            // The suite empties its tables by deleting the repositories and letting verdicts cascade;
            // this one's repository is already gone, so its verdict would outlive the test and be
            // counted by the next one to read the gate register.
            jdbc.update("delete from t_gate_verdict where repo_id = ?", repoId);
        }
    }
}
