package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The per-target figures in the compliance summary, against a database that has issues in it.
 *
 * <p><b>Why this suite exists.</b> The summary used to ask nine count queries per target inside
 * its loop — the shape {@code TriageEvents.findForIssues} documents as "the difference between a
 * screen and a timeout on a real backlog". Collapsing that into one grouped query changes how
 * every number on the page is derived, and the existing route tests could not tell: they run
 * against an empty database, so they pass under any aggregation, right or wrong.
 *
 * <p>What is pinned here is the arithmetic, not the query count: each target keeps its own
 * issues, and a target with none reports none rather than inheriting its neighbour's.
 */
@DisplayName("compliance summary, per-target counts")
class ComplianceTargetCountsTest extends ApiTestBase {

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Issues issues;

    private long repository(String url) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl(url);
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private void issue(long repoId, String identifier, Severity severity, FindingType type, boolean kev) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setFingerprint(identifier + "-" + repoId);
        issue.setType(type.wireName());
        issue.setIdentifier(identifier);
        issue.setSeverity(severity.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setIsKev(kev);
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        issues.save(issue);
    }

    private JsonNode summary() throws Exception {
        String body = mvc.perform(authenticated(get("/api/v1/compliance/summary"), asAdmin()))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        return json.readTree(body);
    }

    private static JsonNode targetNamed(JsonNode summary, long repoId) {
        for (JsonNode target : summary.get("targets")) {
            if (("repo:" + repoId).equals(target.get("targetId").asText())) {
                return target;
            }
        }
        throw new AssertionError("no target repo:" + repoId + " in the summary");
    }

    @Test
    @DisplayName("each target is counted from its own issues, and an empty one stays empty")
    void countsDoNotLeakBetweenTargets() throws Exception {
        long busy = repository("https://example.invalid/busy.git");
        long quiet = repository("https://example.invalid/quiet.git");

        // Four open issues on one target, spread across severities and types so that a row
        // contributing to several axes at once is exercised: the grouped query returns one row
        // per (severity, type, kev) combination, and each has to land in every tally it belongs
        // to rather than only the first.
        issue(busy, "CVE-COUNT-1", Severity.CRITICAL, FindingType.VULNERABILITY, true);
        issue(busy, "CVE-COUNT-2", Severity.HIGH, FindingType.VULNERABILITY, false);
        issue(busy, "SECRET-COUNT-1", Severity.HIGH, FindingType.SECRET, false);
        issue(busy, "IAC-COUNT-1", Severity.LOW, FindingType.IAC, false);

        JsonNode summary = summary();

        assertThat(targetNamed(summary, busy).get("openIssuesCount").asLong())
                .as("the four open issues of this target, and only those")
                .isEqualTo(4);

        assertThat(targetNamed(summary, quiet).get("openIssuesCount").asLong())
                .as("a target with no issue must not inherit its neighbour's grouped row")
                .isZero();
    }

    @Test
    @DisplayName("a resolved issue counts for no target")
    void resolvedIssuesAreExcluded() throws Exception {
        long target = repository("https://example.invalid/resolved.git");

        issue(target, "CVE-OPEN", Severity.HIGH, FindingType.VULNERABILITY, false);

        IssueEntity settled = new IssueEntity();
        settled.setRepoId(target);
        settled.setFingerprint("CVE-RESOLVED-" + target);
        settled.setType(FindingType.VULNERABILITY.wireName());
        settled.setIdentifier("CVE-RESOLVED");
        settled.setSeverity(Severity.CRITICAL.wireName());
        settled.setState(IssueState.RESOLVED.wireName());
        settled.setTriageStatus(TriageStatus.FIXED.wireName());
        settled.setFirstSeenAt(Instant.now());
        settled.setLastSeenAt(Instant.now());
        settled.setTimesSeen(1);
        issues.save(settled);

        // The grouped query filters on state; a refactor that dropped that filter would show up
        // here as two, and nowhere else.
        assertThat(targetNamed(summary(), target).get("openIssuesCount").asLong()).isEqualTo(1);
    }
}
