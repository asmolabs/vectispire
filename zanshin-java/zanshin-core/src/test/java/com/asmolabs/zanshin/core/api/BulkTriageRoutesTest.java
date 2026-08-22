package com.asmolabs.zanshin.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.zanshin.common.domain.access.VisibilityMode;
import com.asmolabs.zanshin.common.domain.issues.FindingType;
import com.asmolabs.zanshin.common.domain.issues.IssueState;
import com.asmolabs.zanshin.common.domain.issues.Severity;
import com.asmolabs.zanshin.common.domain.issues.TriageStatus;
import com.asmolabs.zanshin.common.domain.settings.Setting;
import com.asmolabs.zanshin.core.persistence.IssueEntity;
import com.asmolabs.zanshin.core.persistence.RepositoryEntity;
import com.asmolabs.zanshin.core.repositories.GitRepositories;
import com.asmolabs.zanshin.core.repositories.Issues;
import com.asmolabs.zanshin.core.repositories.TriageEvents;
import com.asmolabs.zanshin.core.services.SettingsService;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.LongStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * Deciding one thing about many issues.
 *
 * <p>One CVE across forty repositories is one judgement about one context, and deciding it forty
 * times is how a backlog stops being triaged at all. What is under test is almost entirely the
 * failure modes: a batch that half-applied, a batch that reached past what the caller may see, and
 * a batch that changed rows without leaving the history a compliance reader is handed.
 */
@DisplayName("triaging many issues at once")
class BulkTriageRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Issues issues;

    @Autowired
    private TriageEvents events;

    @Autowired
    private SettingsService settings;

    @Test
    @DisplayName("one decision reaches every issue, and each one records its own transition")
    void appliesToAllAndRecordsEach() throws Exception {
        long target = repository("https://example.invalid/bulk.git");
        long first = issue(target, "CVE-BULK-1");
        long second = issue(target, "CVE-BULK-2");
        long third = issue(target, "CVE-BULK-3");

        mvc.perform(authenticated(
                        post("/api/v1/issues/triage")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(write(Map.of(
                                        "ids", List.of(first, second, third),
                                        "status", "not_affected",
                                        "justification", "vulnerable_code_not_in_execute_path",
                                        "comment", "Not reachable in our configuration"))),
                        asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(3));

        assertThat(issues.findAllById(List.of(first, second, third)))
                .allSatisfy(issue ->
                        assertThat(issue.getTriageStatus()).isEqualTo(TriageStatus.NOT_AFFECTED.wireName()));

        // **The history, not just the rows.** This is the whole reason the route loops instead of
        // issuing one `update … where id in (…)`: a bulk decision that left three issues changed
        // with no recorded transition would be indistinguishable from three rows somebody edited
        // by hand, and the triage history is the document a compliance reader receives.
        for (long id : List.of(first, second, third)) {
            assertThat(events.findByIssueIdOrderByOccurredAtAscIdAsc(id))
                    .as("triage history of issue %s", id)
                    .isNotEmpty();
        }
    }

    @Test
    @DisplayName("one bad identifier refuses the whole batch rather than half-applying it")
    void isAllOrNothing() throws Exception {
        long target = repository("https://example.invalid/partial.git");
        long good = issue(target, "CVE-GOOD");

        mvc.perform(authenticated(
                        post("/api/v1/issues/triage")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(write(Map.of(
                                        "ids", List.of(good, 999_999L),
                                        "status", "fixed"))),
                        asAdmin()))
                .andExpect(status().isNotFound());

        // The property that matters: a partial success would leave the caller holding a decision
        // that applied to an unknown subset, and sending it again would re-triage what already
        // succeeded and move every `triagedAt` it touched.
        assertThat(issues.findById(good))
                .get()
                .satisfies(issue -> assertThat(issue.getTriageStatus())
                        .isEqualTo(TriageStatus.UNDER_REVIEW.wireName()));
    }

    @Test
    @DisplayName("an issue the caller cannot see is a 404, and takes the batch with it")
    void visibilityIsCheckedOnEveryIdentifier() throws Exception {
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        try {
            long target = repository("https://example.invalid/somebody-elses.git");
            long mine = issue(target, "CVE-HIDDEN-1");
            long alsoMine = issue(target, "CVE-HIDDEN-2");

            // A reader with no assignment sees nothing, so both identifiers are invisible — and a
            // 404 rather than a 403, because a refusal that says "this exists and is not yours"
            // answers the question the caller was probing with.
            mvc.perform(authenticated(
                            post("/api/v1/issues/triage")
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .content(write(Map.of("ids", List.of(mine, alsoMine), "status", "fixed"))),
                            asReader()))
                    .andExpect(status().isNotFound());

            // Checked before the first write, not as it goes: the other order would triage the
            // visible ones and then answer 404 — a partial write reported as a failure, which is
            // the worst of the two.
            assertThat(issues.findById(mine))
                    .get()
                    .satisfies(issue -> assertThat(issue.getTriageStatus())
                            .isEqualTo(TriageStatus.UNDER_REVIEW.wireName()));
        } finally {
            settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.EVERYONE.wireName());
        }
    }

    @Test
    @DisplayName("more than the list can return is refused, not silently truncated")
    void refusesAnOversizedBatch() throws Exception {
        // Silently triaging the first 500 of 501 would report success for a decision that did not
        // reach the last one, and the caller has no way to see which.
        List<Long> tooMany = LongStream.rangeClosed(1, IssuesController.MAX_PAGE_SIZE + 1).boxed().toList();

        mvc.perform(authenticated(
                        post("/api/v1/issues/triage")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(write(Map.of("ids", tooMany, "status", "fixed"))),
                        asAdmin()))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("an empty selection is refused rather than reported as a successful no-op")
    void refusesAnEmptySelection() throws Exception {
        // "0 issues triaged" with a 200 reads as success to a script, which would then move on
        // believing a decision was recorded.
        mvc.perform(authenticated(
                        post("/api/v1/issues/triage")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(write(Map.of("ids", List.of(), "status", "fixed"))),
                        asAdmin()))
                .andExpect(status().isBadRequest());
    }

    private long repository(String url) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl(url);
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private long issue(long repoId, String identifier) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setFingerprint(identifier + "-" + repoId);
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier(identifier);
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        return issues.save(issue).getId();
    }
}
