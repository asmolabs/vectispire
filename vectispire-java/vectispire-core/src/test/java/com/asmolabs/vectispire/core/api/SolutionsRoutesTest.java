package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.services.AuditLogService;
import com.asmolabs.vectispire.core.services.RequestActor;
import com.asmolabs.vectispire.core.services.shared.SettingsService;
import com.asmolabs.vectispire.core.services.SolutionAdministrationService;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.stream.StreamSupport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * Solutions, projects and grants on a project (decision 0023), through the routes.
 *
 * <p>The cases worth a suite are the ones the decision turns on: a project grant resolved at each
 * request — so a repository filed <em>after</em> the grant is visible to its holder — a partial
 * grant that sees a partial project and says so, a reader with no grant for whom the project does
 * not exist, and the two deletions, one refused and one that detaches without deleting anything.
 */
@DisplayName("solutions, projects and project grants")
class SolutionsRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Issues issues;

    @Autowired
    private SettingsService settings;

    @Autowired
    private AuditLogService audit;

    @Autowired
    private SolutionAdministrationService administration;

    // ------------------------------------------------------------------------------ the tree

    @Test
    @DisplayName("an administrator sees every solution, empty ones included, and \"no project\" as its own group")
    void anAdministratorSeesTheWholeTree() throws Exception {
        long empty = solution(unique("empty"));
        long filled = solution(unique("filled"));
        long project = project(filled, "API");
        long filedRepo = repository("https://example.invalid/filed.git");
        long unfiledRepo = repository("https://example.invalid/unfiled.git");
        file(project, filedRepo);
        issue(filedRepo, Severity.CRITICAL, TriageStatus.UNDER_REVIEW);
        issue(filedRepo, Severity.HIGH, TriageStatus.AFFECTED);
        // Settled triage is left out of a figure of risk, like everywhere else.
        issue(filedRepo, Severity.HIGH, TriageStatus.NOT_AFFECTED);
        issue(unfiledRepo, Severity.LOW, TriageStatus.UNDER_REVIEW);

        JsonNode tree = tree(asAdmin());

        assertThat(solutionIds(tree)).contains(empty, filled);
        JsonNode node = projectNode(tree, project);
        assertThat(node.path("partial").asBoolean()).isFalse();
        assertThat(node.path("repositoryCount").asInt()).isEqualTo(1);
        assertThat(node.path("openIssues").path("critical").asLong()).isEqualTo(1);
        assertThat(node.path("openIssues").path("high").asLong()).isEqualTo(1);
        assertThat(node.path("openIssues").path("total").asLong()).isEqualTo(2);
        assertThat(repositoryIds(node)).containsExactly(filedRepo);
        assertThat(solutionNode(tree, filled).path("openIssues").path("total").asLong()).isEqualTo(2);

        assertThat(repositoryIds(tree.path("unfiled"))).contains(unfiledRepo).doesNotContain(filedRepo);
        assertThat(tree.path("unfiled").path("openIssues").path("low").asLong()).isGreaterThanOrEqualTo(1);
    }

    @Test
    @DisplayName("a project grant shows every repository of the project, one filed after the grant included")
    void aProjectGrantIsResolvedAtEachRequest() throws Exception {
        restrict();
        long project = project(solution(unique("granted")), "Web");
        long before = repository("https://example.invalid/before.git");
        file(project, before);
        String reader = asReader();
        grantDirectly(readerId(), "project", project);

        long after = repository("https://example.invalid/after.git");
        file(project, after);
        issue(after, Severity.HIGH, TriageStatus.UNDER_REVIEW);

        JsonNode node = projectNode(tree(reader), project);
        assertThat(repositoryIds(node)).containsExactlyInAnyOrder(before, after);
        assertThat(node.path("partial").asBoolean()).isFalse();
        assertThat(node.path("openIssues").path("high").asLong()).isEqualTo(1);

        // And through every route that narrows by visibility, unchanged: the backlog and the
        // inventory see the late repository too, which is the point of resolving before querying.
        mvc.perform(authenticated(get("/api/v1/issues"), reader))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(1));
        mvc.perform(authenticated(get("/api/v1/repositories"), reader))
                .andExpect(jsonPath("$.length()").value(2));
    }

    @Test
    @DisplayName("a repository grant alone shows its project partially, and says so")
    void aPartialGrantSeesAPartialProject() throws Exception {
        restrict();
        long solution = solution(unique("partial"));
        long project = project(solution, "Mobile");
        long mine = repository("https://example.invalid/mine.git");
        long hidden = repository("https://example.invalid/hidden.git");
        file(project, mine);
        file(project, hidden);
        issue(mine, Severity.MEDIUM, TriageStatus.UNDER_REVIEW);
        issue(hidden, Severity.CRITICAL, TriageStatus.UNDER_REVIEW);
        String reader = asReader();
        grantDirectly(readerId(), "repository", mine);

        JsonNode tree = tree(reader);
        JsonNode node = projectNode(tree, project);
        assertThat(repositoryIds(node)).containsExactly(mine);
        assertThat(node.path("partial").asBoolean()).as("the project holds a repository this reader cannot see").isTrue();
        assertThat(node.path("openIssues").path("critical").asLong())
                .as("the hidden repository's issues are not counted")
                .isZero();
        assertThat(node.path("openIssues").path("medium").asLong()).isEqualTo(1);
        assertThat(solutionNode(tree, solution).path("partial").asBoolean()).isTrue();
    }

    @Test
    @DisplayName("a reader with no grant does not see the project, nor its solution")
    void noGrantNoProject() throws Exception {
        restrict();
        long solution = solution(unique("hidden"));
        long project = project(solution, "Secret");
        file(project, repository("https://example.invalid/secret.git"));

        JsonNode tree = tree(asReader());

        assertThat(solutionIds(tree)).doesNotContain(solution);
        assertThat(allProjectIds(tree)).doesNotContain(project);
        assertThat(tree.path("unfiled").path("repositoryCount").asInt()).isZero();
    }

    @Test
    @DisplayName("a granted project holding no repository yet still appears to its holder")
    void aGrantedEmptyProjectAppears() throws Exception {
        restrict();
        long project = project(solution(unique("empty-grant")), "Later");
        String reader = asReader();
        grantDirectly(readerId(), "project", project);

        JsonNode node = projectNode(tree(reader), project);
        assertThat(node.path("repositoryCount").asInt()).isZero();
        assertThat(node.path("partial").asBoolean()).isFalse();
    }

    @Test
    @DisplayName("a project grant held through a team works like one held directly")
    void aTeamProjectGrantWorks() throws Exception {
        restrict();
        long project = project(solution(unique("team")), "Backend");
        long repo = repository("https://example.invalid/team-project.git");
        file(project, repo);
        issue(repo, Severity.HIGH, TriageStatus.UNDER_REVIEW);
        String reader = asReader();

        long team = team(unique("team"));
        mvc.perform(authenticated(put("/api/v1/teams/" + team + "/targets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(List.of(Map.of("kind", "project", "id", project)))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].kind").value("project"))
                .andExpect(jsonPath("$[0].name", containsString("Backend")));
        mvc.perform(authenticated(put("/api/v1/teams/" + team + "/members"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(List.of(readerId()))))
                .andExpect(status().isOk());

        assertThat(repositoryIds(projectNode(tree(reader), project))).containsExactly(repo);
        mvc.perform(authenticated(get("/api/v1/issues"), reader)).andExpect(jsonPath("$.total").value(1));
    }

    @Test
    @DisplayName("moving a repository to another project moves its visibility for both projects' grantees")
    void movingMovesVisibility() throws Exception {
        restrict();
        long solution = solution(unique("move"));
        long from = project(solution, "From");
        long to = project(solution, "To");
        long repo = repository("https://example.invalid/moving.git");
        file(from, repo);
        String reader = asReader();
        grantDirectly(readerId(), "project", from);
        mvc.perform(authenticated(get("/api/v1/repositories"), reader)).andExpect(jsonPath("$.length()").value(1));

        file(to, repo);

        mvc.perform(authenticated(get("/api/v1/repositories"), reader)).andExpect(jsonPath("$.length()").value(0));
        assertThat(audit.recent(20))
                .as("the move's entry says that visibility moves with it")
                .anySatisfy(entry -> {
                    assertThat(entry.getOperationType()).isEqualTo(AuditOperation.PROJECT_REPOSITORIES_CHANGED.wireName());
                    assertThat(entry.getDescription()).contains("moved from project From to To", "visibility moves");
                });
    }

    // ------------------------------------------------------------------------------- writes

    @Test
    @DisplayName("a repository that does not exist cannot be filed: 404, in the words a hidden one gets")
    void anAbsentRepositoryIsNotFiled() throws Exception {
        long project = project(solution(unique("absent")), "P");

        mvc.perform(authenticated(put("/api/v1/projects/" + project + "/repositories/987654"), asAdmin()))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.detail").value("Repository not found."));
    }

    @Test
    @DisplayName("a repository hidden from the caller cannot be filed or removed, and reads as absent")
    void aHiddenRepositoryIsNotFiled() throws Exception {
        // Every administrator sees the whole estate today, so no session can be hidden from a
        // repository; the rule is asserted on the service the route calls, with a narrow
        // visibility, and must refuse in the sentence the absent repository above gets.
        long project = project(solution(unique("hidden-file")), "P");
        long visible = repository("https://example.invalid/visible.git");
        long hidden = repository("https://example.invalid/not-yours.git");
        Visibility narrow = Visibility.only(List.of(new ScanTarget.Repository(visible)));
        RequestActor actor = new RequestActor("test", "127.0.0.1", null);

        assertThatThrownBy(() -> administration.fileRepository(project, hidden, narrow, actor))
                .isInstanceOf(NoSuchElementException.class)
                .hasMessage("Repository not found.");
        assertThat(repositories.findById(hidden).orElseThrow().getProjectId()).isNull();

        file(project, hidden);
        assertThatThrownBy(() -> administration.removeRepository(project, hidden, narrow, actor))
                .isInstanceOf(NoSuchElementException.class)
                .hasMessage("Repository not found.");
        assertThat(repositories.findById(hidden).orElseThrow().getProjectId()).isEqualTo(project);
    }

    @Test
    @DisplayName("a solution holding a project cannot be deleted; an empty one can")
    void aSolutionIsDeletedOnlyEmpty() throws Exception {
        long solution = solution(unique("full"));
        long project = project(solution, "Kept");

        mvc.perform(authenticated(delete("/api/v1/solutions/" + solution), asAdmin()))
                .andExpect(status().isConflict());
        assertThat(solutionIds(tree(asAdmin()))).contains(solution);

        mvc.perform(authenticated(delete("/api/v1/projects/" + project), asAdmin())).andExpect(status().isNoContent());
        mvc.perform(authenticated(delete("/api/v1/solutions/" + solution), asAdmin())).andExpect(status().isNoContent());
        assertThat(solutionIds(tree(asAdmin()))).doesNotContain(solution);
    }

    @Test
    @DisplayName("deleting a project detaches its repositories, revokes its grants, and deletes no repository")
    void deletingAProjectDetaches() throws Exception {
        long project = project(solution(unique("doomed")), "Doomed");
        long repo = repository("https://example.invalid/survivor.git");
        file(project, repo);
        issue(repo, Severity.HIGH, TriageStatus.UNDER_REVIEW);
        asReader();
        long reader = readerId();
        grantDirectly(reader, "project", project);

        mvc.perform(authenticated(delete("/api/v1/projects/" + project), asAdmin())).andExpect(status().isNoContent());

        RepositoryEntity survivor = repositories.findById(repo).orElseThrow();
        assertThat(survivor.getProjectId()).as("back to no project").isNull();
        assertThat(issues.findAll()).anySatisfy(issue -> assertThat(issue.getRepoId()).isEqualTo(repo));
        assertThat(repositoryIds(tree(asAdmin()).path("unfiled"))).contains(repo);
        mvc.perform(authenticated(get("/api/v1/users/" + reader + "/targets"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(0));
        // The detach is explicit rather than left to the key's `set null`, which this fixture
        // enforces too — so the entry's count is what shows the service did it.
        assertThat(audit.recent(20)).anySatisfy(entry -> assertThat(entry.getDescription())
                .contains("Project deleted: Doomed (1 repository(ies) returned to no project, 1 grant(s) revoked)"));
    }

    @Test
    @DisplayName("a repository is removed from its project, and only from its own")
    void removingFromAProject() throws Exception {
        long solution = solution(unique("remove"));
        long project = project(solution, "Here");
        long other = project(solution, "Elsewhere");
        long repo = repository("https://example.invalid/removed.git");
        file(project, repo);

        mvc.perform(authenticated(delete("/api/v1/projects/" + other + "/repositories/" + repo), asAdmin()))
                .andExpect(status().isNotFound());
        mvc.perform(authenticated(delete("/api/v1/projects/" + project + "/repositories/" + repo), asAdmin()))
                .andExpect(status().isNoContent());
        assertThat(repositories.findById(repo).orElseThrow().getProjectId()).isNull();
    }

    @Test
    @DisplayName("a grant naming a project that does not exist is refused, for an account and for a team")
    void aGrantOnAMissingProjectIsRefused() throws Exception {
        asReader();
        mvc.perform(authenticated(put("/api/v1/users/" + readerId() + "/targets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(List.of(Map.of("kind", "project", "id", 987654)))))
                .andExpect(status().isBadRequest());
        mvc.perform(authenticated(put("/api/v1/teams/" + team(unique("missing")) + "/targets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(List.of(Map.of("kind", "project", "id", 987654)))))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("a project grant is listed as the project, named after its solution")
    void aProjectGrantIsListedByName() throws Exception {
        String solutionName = unique("named");
        long project = project(solution(solutionName), "Portal");
        asReader();
        long reader = readerId();
        grantDirectly(reader, "project", project);

        mvc.perform(authenticated(get("/api/v1/users/" + reader + "/targets"), asAdmin()))
                .andExpect(jsonPath("$[0].kind").value("project"))
                .andExpect(jsonPath("$[0].id").value(project))
                .andExpect(jsonPath("$[0].name").value(solutionName + " / Portal"));
    }

    @Test
    @DisplayName("the repository list says which project each repository is in")
    void theInventoryNamesTheProject() throws Exception {
        String solutionName = unique("inventory");
        long project = project(solution(solutionName), "Core");
        long repo = repository("https://example.invalid/inventoried.git");
        file(project, repo);

        String body = mvc.perform(authenticated(get("/api/v1/repositories"), asAdmin()))
                .andReturn().getResponse().getContentAsString();
        JsonNode row = StreamSupport.stream(json.readTree(body).spliterator(), false)
                .filter(node -> node.path("id").asLong() == repo)
                .findFirst()
                .orElseThrow();
        assertThat(row.path("projectId").asLong()).isEqualTo(project);
        assertThat(row.path("projectName").asText()).isEqualTo(solutionName + " / Core");
    }

    @Test
    @DisplayName("names are unique case-insensitively, a solution's and a project's within its solution")
    void namesAreUnique() throws Exception {
        String name = unique("dup");
        long solution = solution(name);
        mvc.perform(authenticated(post("/api/v1/solutions"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", name.toUpperCase(java.util.Locale.ROOT)))))
                .andExpect(status().isBadRequest());

        project(solution, "Same");
        mvc.perform(authenticated(post("/api/v1/solutions/" + solution + "/projects"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "SAME"))))
                .andExpect(status().isBadRequest());
        // Another solution may hold its own "Same".
        project(solution(unique("other")), "Same");
    }

    @Test
    @DisplayName("a name longer than its column is a 400, not the 500 the insert would answer on MySQL")
    void namesAreBoundedByTheirColumn() throws Exception {
        mvc.perform(authenticated(post("/api/v1/solutions"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "s".repeat(101)))))
                .andExpect(status().isBadRequest());
        long solution = solution(unique("bounded"));
        mvc.perform(authenticated(post("/api/v1/solutions/" + solution + "/projects"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "p", "description", "d".repeat(256)))))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("a rename keeps what was not sent")
    void aRenameKeepsTheRest() throws Exception {
        long solution = solution(unique("rename"));
        long project = project(solution, "Old");
        mvc.perform(authenticated(patch("/api/v1/projects/" + project), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("description", "what it does"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("Old"))
                .andExpect(jsonPath("$.description").value("what it does"));
        mvc.perform(authenticated(patch("/api/v1/projects/" + project), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "New"))))
                .andExpect(jsonPath("$.name").value("New"))
                .andExpect(jsonPath("$.description").value("what it does"))
                .andExpect(jsonPath("$.solutionId").value(solution));
    }

    @Test
    @DisplayName("a reader reads the tree and changes nothing")
    void readersCannotAdminister() throws Exception {
        long solution = solution(unique("readonly"));
        long project = project(solution, "P");
        long repo = repository("https://example.invalid/readonly.git");
        String reader = asReader();

        mvc.perform(authenticated(get("/api/v1/solutions"), reader)).andExpect(status().isOk());
        mvc.perform(authenticated(post("/api/v1/solutions"), reader)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "nope"))))
                .andExpect(status().isForbidden());
        mvc.perform(authenticated(delete("/api/v1/solutions/" + solution), reader)).andExpect(status().isForbidden());
        mvc.perform(authenticated(put("/api/v1/projects/" + project + "/repositories/" + repo), reader))
                .andExpect(status().isForbidden());
        mvc.perform(authenticated(delete("/api/v1/projects/" + project), reader)).andExpect(status().isForbidden());
    }

    // ------------------------------------------------------------------------------ helpers

    private static String unique(String prefix) {
        return prefix + "-" + System.nanoTime();
    }

    private void restrict() {
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
    }

    private long solution(String name) throws Exception {
        return idOf(mvc.perform(authenticated(post("/api/v1/solutions"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", name))))
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

    private long team(String name) throws Exception {
        return idOf(mvc.perform(authenticated(post("/api/v1/teams"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", name))))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString());
    }

    private void file(long project, long repository) throws Exception {
        mvc.perform(authenticated(put("/api/v1/projects/" + project + "/repositories/" + repository), asAdmin()))
                .andExpect(status().isNoContent());
    }

    private void grantDirectly(long userId, String kind, long id) throws Exception {
        mvc.perform(authenticated(put("/api/v1/users/" + userId + "/targets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(List.of(Map.of("kind", kind, "id", id)))))
                .andExpect(status().isOk());
    }

    private JsonNode tree(String token) throws Exception {
        return json.readTree(mvc.perform(authenticated(get("/api/v1/solutions"), token))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
    }

    private long idOf(String body) throws Exception {
        return json.readTree(body).path("id").asLong();
    }

    private static List<Long> solutionIds(JsonNode tree) {
        return StreamSupport.stream(tree.path("solutions").spliterator(), false)
                .map(node -> node.path("id").asLong())
                .toList();
    }

    private static List<Long> allProjectIds(JsonNode tree) {
        return StreamSupport.stream(tree.path("solutions").spliterator(), false)
                .flatMap(solution -> StreamSupport.stream(solution.path("projects").spliterator(), false))
                .map(node -> node.path("id").asLong())
                .toList();
    }

    private static JsonNode solutionNode(JsonNode tree, long id) {
        return StreamSupport.stream(tree.path("solutions").spliterator(), false)
                .filter(node -> node.path("id").asLong() == id)
                .findFirst()
                .orElseThrow(() -> new AssertionError("solution " + id + " is not in the tree"));
    }

    private static JsonNode projectNode(JsonNode tree, long id) {
        return StreamSupport.stream(tree.path("solutions").spliterator(), false)
                .flatMap(solution -> StreamSupport.stream(solution.path("projects").spliterator(), false))
                .filter(node -> node.path("id").asLong() == id)
                .findFirst()
                .orElseThrow(() -> new AssertionError("project " + id + " is not in the tree"));
    }

    private static List<Long> repositoryIds(JsonNode node) {
        return StreamSupport.stream(node.path("repositories").spliterator(), false)
                .map(repository -> repository.path("id").asLong())
                .toList();
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

    private long repository(String url) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl(url);
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private void issue(long repoId, Severity severity, TriageStatus triage) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setFingerprint("fp-" + System.nanoTime());
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier("CVE-" + System.nanoTime());
        issue.setSeverity(severity.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(triage.wireName());
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        issues.save(issue);
    }
}
