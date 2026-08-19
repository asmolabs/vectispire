package com.asmolabs.zanshin.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.zanshin.common.domain.issues.FindingType;
import com.asmolabs.zanshin.common.domain.issues.IssueState;
import com.asmolabs.zanshin.common.domain.issues.Severity;
import com.asmolabs.zanshin.common.domain.issues.TriageStatus;
import com.asmolabs.zanshin.core.persistence.IssueEntity;
import com.asmolabs.zanshin.core.persistence.RepositoryEntity;
import com.asmolabs.zanshin.core.repositories.GitRepositories;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The backlog opens on what matters most.
 *
 * <p><b>Severity is a text column, so the obvious ordering is wrong and looks right.</b> Sorted
 * as text it reads {@code critical, high, low, medium, negligible} — mediums buried under lows,
 * on a screen whose entire purpose is to say what to do first. The list was in fact ordered by
 * {@code lastSeenAt}, which is worse still: a negligible finding seen this morning outranked a
 * critical from yesterday.
 *
 * <p>This runs through HTTP against a real database because the ordering is an SQL expression
 * built at runtime by {@code JpaSort.unsafe}. A unit test on the string would assert that the
 * string is what it is; only the database can say the query is valid and orders as intended.
 */
@DisplayName("the order a backlog is read in")
class IssueOrderingTest extends ApiTestBase {

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private com.asmolabs.zanshin.core.repositories.Issues issues;

    @Test
    @DisplayName("is most severe first, whatever order they arrived in")
    void mostSevereFirst() throws Exception {
        long repository = seedRepository();

        // Inserted in a deliberately unhelpful order: the least severe is both first by id and
        // the most recently seen, so it wins under either of the two orderings this replaces.
        seedIssue(repository, Severity.NEGLIGIBLE, Instant.parse("2026-08-19T10:00:00Z"));
        seedIssue(repository, Severity.MEDIUM, Instant.parse("2026-08-17T10:00:00Z"));
        seedIssue(repository, Severity.CRITICAL, Instant.parse("2026-08-15T10:00:00Z"));
        seedIssue(repository, Severity.LOW, Instant.parse("2026-08-18T10:00:00Z"));
        seedIssue(repository, Severity.HIGH, Instant.parse("2026-08-16T10:00:00Z"));

        mvc.perform(authenticated(get("/api/v1/issues"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items[0].severity").value("critical"))
                .andExpect(jsonPath("$.items[1].severity").value("high"))
                // The one a text sort gets wrong: `low` sorts before `medium` alphabetically.
                .andExpect(jsonPath("$.items[2].severity").value("medium"))
                .andExpect(jsonPath("$.items[3].severity").value("low"))
                .andExpect(jsonPath("$.items[4].severity").value("negligible"));
    }

    @Test
    @DisplayName("breaks ties by most recently seen, so a page boundary is stable")
    void tiesAreBrokenByRecency() throws Exception {
        long repository = seedRepository();

        seedIssue(repository, Severity.HIGH, Instant.parse("2026-08-15T10:00:00Z"));
        seedIssue(repository, Severity.HIGH, Instant.parse("2026-08-19T10:00:00Z"));

        // Without a total order, two rows of equal severity can swap between two page loads —
        // which shows one issue twice and hides another, at the page boundary.
        mvc.perform(authenticated(get("/api/v1/issues"), asAdmin()))
                .andExpect(jsonPath("$.items[0].lastSeenAt").value(org.hamcrest.Matchers.startsWith("2026-08-19")));
    }

    private void seedIssue(long repositoryId, Severity severity, Instant lastSeen) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repositoryId);
        issue.setFingerprint("fp-" + severity + "-" + lastSeen);
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier("CVE-2026-" + severity.ordinal());
        issue.setSeverity(severity.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setFirstSeenAt(lastSeen);
        issue.setLastSeenAt(lastSeen);
        issue.setTimesSeen(1);
        issues.save(issue);
    }

    private long seedRepository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/ordering.git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }
}
