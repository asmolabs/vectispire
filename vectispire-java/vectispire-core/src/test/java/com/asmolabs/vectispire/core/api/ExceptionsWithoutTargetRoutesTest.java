package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.paging.RegisterCursor;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * An exception on an issue that names no target.
 *
 * <p><b>The whole register answered 500 for one such row.</b> Its entry built the row's target as
 * {@code new ScanTarget.Container(containerId)} whenever the repository was absent, and a null container
 * id unboxed into a {@code long} throws. The register is read by the screen, by the response of every
 * review, and by the evidence bundle, so one row took all three down. The application creates no such
 * issue — the sync files every issue under the scan's target, and deleting a target deletes its issues —
 * but nothing in the schema forbids one (both columns are nullable, there is no check), and a row written
 * by hand or restored from elsewhere is enough.
 *
 * <p>Such a row is listed with no target for a reader who sees the whole estate, and is nobody else's:
 * {@code Visibility.permits} refuses a restricted reader a row without a target, as every other
 * register does, and the restricted read selects by target in SQL, so its cursor cannot name the row.
 */
@DisplayName("an exception whose issue names no target")
class ExceptionsWithoutTargetRoutesTest extends ApiTestBase {

    @Autowired
    private IssueRepository issues;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private SettingsService settings;

    @Test
    @DisplayName("is listed with no target for a reader of the whole estate, and the register answers")
    void listedWithNoTarget() throws Exception {
        long orphan = accepted(null, "CVE-ORPHAN-" + System.nanoTime(), Instant.now());

        JsonNode entry = entryOf(mvc.perform(authenticated(get("/api/v1/exceptions"), asAdmin()))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(), orphan);

        assertThat(entry).as("the row is listed").isNotNull();
        assertThat(entry.path("target_kind").isNull()).isTrue();
        assertThat(entry.path("target_id").isNull()).isTrue();
        assertThat(entry.path("target_name").isNull()).isTrue();
        assertThat(entry.path("decision").asText()).isEqualTo(TriageStatus.NOT_AFFECTED.wireName());
    }

    @Test
    @DisplayName("does not break the answer to a review of another exception")
    void aReviewStillAnswers() throws Exception {
        accepted(null, "CVE-ORPHAN-" + System.nanoTime(), Instant.now());
        long reviewed = accepted(repository("reviewed"), "CVE-REVIEWED-" + System.nanoTime(), Instant.now());

        mvc.perform(authenticated(post("/api/v1/exceptions/" + reviewed + "/reviews"), asCiso())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("outcome", "CONFIRMED", "comment", "still not reachable"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.entries").isArray());
    }

    @Test
    @DisplayName("is shown to no restricted reader, and their cursor never names it")
    void hiddenFromARestrictedReader() throws Exception {
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        long mine = repository("mine");
        String reader = assignedReader(mine);
        long own = accepted(mine, "CVE-MINE-" + System.nanoTime(), Instant.now().minusSeconds(60));
        // The newest in the register: read unfiltered, a page of one would hold it.
        long orphan = accepted(null, "CVE-ORPHAN-" + System.nanoTime(), Instant.now().plusSeconds(3_600));

        String first = mvc.perform(authenticated(get("/api/v1/exceptions").param("limit", "1"), reader))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.entries.length()").value(1))
                .andExpect(jsonPath("$.entries[0].issue_id").value(own))
                .andReturn().getResponse().getContentAsString();
        String cursor = json.readTree(first).path("next_cursor").asText();
        assertThat(RegisterCursor.parse(cursor))
                .hasValueSatisfying(at -> assertThat(at.id()).isNotEqualTo(String.valueOf(orphan)));

        mvc.perform(authenticated(get("/api/v1/exceptions").param("limit", "1").param("cursor", cursor), reader))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.entries.length()").value(0));
    }

    /** The register's row for {@code issueId}, or null when it is not listed. */
    private JsonNode entryOf(String register, long issueId) throws Exception {
        for (JsonNode entry : json.readTree(register).path("entries")) {
            if (entry.path("issue_id").asLong() == issueId) {
                return entry;
            }
        }
        return null;
    }

    /** An issue carrying an accepted exception, on {@code repoId} or — null — on no target at all. */
    private long accepted(Long repoId, String identifier, Instant at) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setFingerprint(identifier + "-" + repoId);
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier(identifier);
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.NOT_AFFECTED.wireName());
        issue.setTriageJustification("vulnerable_code_not_present");
        issue.setTriagedAt(at);
        issue.setTriagedBy("admin");
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        return issues.save(issue).getId();
    }

    private long repository(String name) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/" + name + "-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    /** A reader with one repository assigned, through the administration route it really uses. */
    private String assignedReader(long repositoryId) throws Exception {
        String reader = asReader();
        long readerId = -1;
        for (JsonNode user : json.readTree(mvc.perform(authenticated(get("/api/v1/users"), asAdmin()))
                .andReturn().getResponse().getContentAsString()).path("users")) {
            if (user.path("username").asText("").startsWith("reader-")) {
                readerId = user.path("id").asLong();
            }
        }
        mvc.perform(authenticated(put("/api/v1/users/" + readerId + "/targets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(List.of(Map.of("kind", "repository", "id", repositoryId)))))
                .andExpect(status().isOk());
        return reader;
    }
}
