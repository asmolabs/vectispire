package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
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
import java.util.stream.StreamSupport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * {@code GET /api/v1/issues?project_id=…} and {@code solution_id=…}: a project's backlog, within what
 * the caller sees.
 *
 * <p>The rule the cases pin is the list's own: the filter narrows and is intersected with the
 * visibility, like {@code repository_id}. A project seen in part answers the part; one hidden entirely
 * answers exactly what one that does not exist answers, and what a hidden repository answers — an empty
 * page, never a 404 that only this filter could tell apart.
 */
@DisplayName("the issues list, filtered by project or solution")
class ProjectIssuesFilterRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private SettingsService settings;

    @Test
    @DisplayName("a project's issues and no others, alone and with a severity; a solution's over its projects")
    void theProjectsIssues() throws Exception {
        long solution = solution();
        long project = project(solution, "API");
        long sibling = project(solution, "Web");
        long filed = repository();
        long alsoFiled = repository();
        long inSibling = repository();
        long unfiled = repository();
        file(project, filed);
        file(project, alsoFiled);
        file(sibling, inSibling);
        issue(filed, "CVE-FILED-HIGH", Severity.HIGH);
        issue(alsoFiled, "CVE-ALSO-CRITICAL", Severity.CRITICAL);
        issue(inSibling, "CVE-SIBLING", Severity.HIGH);
        issue(unfiled, "CVE-UNFILED", Severity.HIGH);

        assertThat(identifiers(list("project_id=" + project, asAdmin())))
                .containsExactlyInAnyOrder("CVE-FILED-HIGH", "CVE-ALSO-CRITICAL");
        assertThat(identifiers(list("project_id=" + project + "&severity=high", asAdmin())))
                .containsExactly("CVE-FILED-HIGH");
        assertThat(list("project_id=" + project, asAdmin()).path("total").asLong())
                .as("the count shares the page's filters").isEqualTo(2);
        assertThat(identifiers(list("solution_id=" + solution, asAdmin())))
                .containsExactlyInAnyOrder("CVE-FILED-HIGH", "CVE-ALSO-CRITICAL", "CVE-SIBLING");
        assertThat(identifiers(list("solution_id=" + solution + "&project_id=" + sibling, asAdmin())))
                .as("both narrow").containsExactly("CVE-SIBLING");
    }

    @Test
    @DisplayName("a project holding no repository has no issue — not the whole backlog")
    void anEmptyProjectHasNoIssue() throws Exception {
        long solution = solution();
        long empty = project(solution, "Later");
        issue(repository(), "CVE-ELSEWHERE", Severity.HIGH);

        JsonNode page = list("project_id=" + empty, asAdmin());
        assertThat(page.path("total").asLong()).isZero();
        assertThat(identifiers(list("solution_id=" + solution, asAdmin()))).isEmpty();
        assertThat(identifiers(list("project_id=" + project(solution(), "Elsewhere")
                + "&solution_id=" + solution, asAdmin())))
                .as("a project outside the solution named beside it").isEmpty();
    }

    @Test
    @DisplayName("a project seen in part answers the issues of the part the reader sees")
    void aPartlyVisibleProjectAnswersItsVisiblePart() throws Exception {
        restrict();
        long solution = solution();
        long project = project(solution, "Mobile");
        long mine = repository();
        long hidden = repository();
        file(project, mine);
        file(project, hidden);
        issue(mine, "CVE-MINE", Severity.MEDIUM);
        issue(hidden, "CVE-HIDDEN", Severity.CRITICAL);
        String reader = asReader();
        grant(readerId(), "repository", mine);

        assertThat(identifiers(list("project_id=" + project, reader))).containsExactly("CVE-MINE");
        assertThat(identifiers(list("solution_id=" + solution, reader))).containsExactly("CVE-MINE");
    }

    @Test
    @DisplayName("a project hidden entirely answers what one that does not exist answers, and what a hidden repository answers")
    void aHiddenProjectReadsAsAnAbsentOne() throws Exception {
        restrict();
        long solution = solution();
        long project = project(solution, "Secret");
        long secret = repository();
        file(project, secret);
        issue(secret, "CVE-SECRET", Severity.CRITICAL);
        long mine = repository();
        issue(mine, "CVE-MINE", Severity.LOW);
        String reader = asReader();
        grant(readerId(), "repository", mine);

        String hidden = mvc.perform(authenticated(get("/api/v1/issues?project_id=" + project), reader))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String absent = mvc.perform(authenticated(get("/api/v1/issues?project_id=" + Long.MAX_VALUE), reader))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String hiddenRepository = mvc.perform(authenticated(get("/api/v1/issues?repository_id=" + secret), reader))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        assertThat(json.readTree(hidden).path("total").asLong()).isZero();
        assertThat(hidden).isEqualTo(absent).isEqualTo(hiddenRepository);
        assertThat(identifiers(list("solution_id=" + solution, reader))).isEmpty();
        assertThat(identifiers(list("solution_id=" + Long.MAX_VALUE, reader))).isEmpty();
    }

    @Test
    @DisplayName("a key restricted to one repository of the project sees that repository's issues, even an administrator's key")
    void aRestrictedKeySeesItsRepositoryOfTheProject() throws Exception {
        long project = project(solution(), "Keyed");
        long keyed = repository();
        long other = repository();
        file(project, keyed);
        file(project, other);
        issue(keyed, "CVE-KEYED", Severity.HIGH);
        issue(other, "CVE-OTHER", Severity.HIGH);
        String key = key(Map.of("name", "ci-" + System.nanoTime(), "scopes", List.of("read"),
                "target_kind", "repository", "target_id", keyed));

        assertThat(identifiers(list("project_id=" + project, key))).containsExactly("CVE-KEYED");
    }

    // ------------------------------------------------------------------------------ helpers

    private JsonNode list(String query, String token) throws Exception {
        return json.readTree(mvc.perform(authenticated(get("/api/v1/issues?limit=500&" + query), token))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
    }

    private static List<String> identifiers(JsonNode page) {
        return StreamSupport.stream(page.path("items").spliterator(), false)
                .map(item -> item.path("identifier").asText())
                .toList();
    }

    private void restrict() {
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
    }

    private long solution() throws Exception {
        return idOf(mvc.perform(authenticated(post("/api/v1/solutions"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "solution-" + System.nanoTime()))))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString());
    }

    private long project(long solution, String name) throws Exception {
        return idOf(mvc.perform(authenticated(post("/api/v1/solutions/" + solution + "/projects"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", name))))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString());
    }

    private void file(long project, long repository) throws Exception {
        mvc.perform(authenticated(put("/api/v1/projects/" + project + "/repositories/" + repository), asAdmin()))
                .andExpect(status().isNoContent());
    }

    private void grant(long userId, String kind, long id) throws Exception {
        mvc.perform(authenticated(put("/api/v1/users/" + userId + "/targets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(List.of(Map.of("kind", kind, "id", id)))))
                .andExpect(status().isOk());
    }

    private String key(Map<String, Object> body) throws Exception {
        String response = mvc.perform(authenticated(post("/api/v1/api-keys"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(body)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return json.readTree(response).get("secret").asText();
    }

    private long idOf(String body) throws Exception {
        return json.readTree(body).path("id").asLong();
    }

    /** The reader account's identifier, read back through the administration listing. */
    private long readerId() throws Exception {
        String body = mvc.perform(authenticated(get("/api/v1/users"), asAdmin()))
                .andReturn().getResponse().getContentAsString();
        for (JsonNode node : json.readTree(body).path("users")) {
            if (node.path("username").asText("").startsWith("reader-")) {
                return node.path("id").asLong();
            }
        }
        throw new IllegalStateException("no reader account in the listing");
    }

    private long repository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/project-filter-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private void issue(long repoId, String identifier, Severity severity) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setFingerprint("fp-" + System.nanoTime());
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier(identifier);
        issue.setSeverity(severity.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        issues.save(issue);
    }
}
