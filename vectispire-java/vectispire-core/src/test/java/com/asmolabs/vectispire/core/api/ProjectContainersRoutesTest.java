package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
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
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.SolutionAdministrationService;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.stream.StreamSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

/**
 * Container images filed in projects (decision 0023, amendment of 2026-09-30), through the routes.
 *
 * <p>The cases the amendment turns on: an image is filed and taken out like a repository, the tree and
 * its figures count it, the backlog's project and solution filters include its issues, a project grant
 * shows it — and stops showing it the moment it leaves the project or moves to another — and the two
 * gestures on a whole project, a move and a deletion, carry or release it.
 */
@DisplayName("container images filed in projects")
class ProjectContainersRoutesTest extends ApiTestBase {

    @Autowired
    private ContainerRepository containers;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private UserRepository users;

    @Autowired
    private SettingsService settings;

    @Autowired
    private AuditLogService audit;

    @Autowired
    private SolutionAdministrationService administration;

    private String visibilityBefore;

    @BeforeEach
    void rememberVisibility() {
        visibilityBefore = settings.get(Setting.TARGET_VISIBILITY);
    }

    @AfterEach
    void restoreVisibility() {
        settings.set(Setting.TARGET_VISIBILITY, visibilityBefore);
    }

    // ---------------------------------------------------------------------- filing and the tree

    @Test
    @DisplayName("an image is filed, listed under its project with its issues counted, and taken out again")
    void fileListAndRemove() throws Exception {
        long solution = solution(unique("images"));
        long project = project(solution, "Shop");
        long repo = repository();
        file("repositories", project, repo);
        issue(repo, null, Severity.HIGH, TriageStatus.UNDER_REVIEW);
        long image = container(unique("shop"));
        long unfiled = container(unique("loose"));
        issue(null, image, Severity.CRITICAL, TriageStatus.UNDER_REVIEW);
        issue(null, image, Severity.CRITICAL, TriageStatus.NOT_AFFECTED);
        issue(null, unfiled, Severity.LOW, TriageStatus.UNDER_REVIEW);

        file("containers", project, image);

        JsonNode tree = tree(asAdmin());
        JsonNode node = projectNode(tree, project);
        assertThat(ids(node, "containers")).containsExactly(image);
        assertThat(node.path("containerCount").asInt()).isEqualTo(1);
        assertThat(node.path("repositoryCount").asInt()).as("repositories alone").isEqualTo(1);
        assertThat(node.path("containers").get(0).path("name").asText()).contains("shop");
        assertThat(node.path("openIssues").path("critical").asLong())
                .as("the image's open issue, its settled one left out")
                .isEqualTo(1);
        assertThat(node.path("openIssues").path("total").asLong()).isEqualTo(2);
        assertThat(node.path("partial").asBoolean()).isFalse();
        JsonNode solutionNode = solutionNode(tree, solution);
        assertThat(solutionNode.path("openIssues").path("total").asLong()).isEqualTo(2);
        assertThat(solutionNode.path("containerCount").asInt()).isEqualTo(1);
        assertThat(ids(tree.path("unfiled"), "containers")).contains(unfiled).doesNotContain(image);
        assertThat(tree.path("unfiled").path("containerCount").asInt()).isGreaterThanOrEqualTo(1);
        assertThat(tree.path("unfiled").path("openIssues").path("low").asLong()).isGreaterThanOrEqualTo(1);

        // The inventory names the project beside the image, as it does beside a repository.
        JsonNode row = containerRow(asAdmin(), image);
        assertThat(row.path("projectId").asLong()).isEqualTo(project);
        assertThat(row.path("projectName").asText()).endsWith(" / Shop");

        // Filing it where it is changes and records nothing.
        long entriesBefore = entriesFor(image);
        file("containers", project, image);
        assertThat(entriesFor(image)).isEqualTo(entriesBefore);

        mvc.perform(authenticated(delete("/api/v1/projects/" + project + "/containers/" + image), asAdmin()))
                .andExpect(status().isNoContent());
        assertThat(containers.findById(image).orElseThrow().getProjectId()).isNull();
        JsonNode after = tree(asAdmin());
        assertThat(ids(projectNode(after, project), "containers")).isEmpty();
        assertThat(projectNode(after, project).path("openIssues").path("total").asLong()).isEqualTo(1);
        assertThat(ids(after.path("unfiled"), "containers")).contains(image);
        assertThat(containerRow(asAdmin(), image).path("projectId").isNull()).isTrue();

        assertThat(audit.recent(20)).anySatisfy(entry -> {
            assertThat(entry.getOperationType()).isEqualTo(AuditOperation.PROJECT_CONTAINERS_CHANGED.wireName());
            assertThat(entry.getResourceId()).isEqualTo(String.valueOf(image));
            assertThat(entry.getDescription()).contains("filed into project Shop", "now see it");
        });
    }

    @Test
    @DisplayName("an image is removed only from its own project; an absent one is not filed; a hidden one reads as absent")
    void refusals() throws Exception {
        long solution = solution(unique("refused"));
        long project = project(solution, "Here");
        long other = project(solution, "Elsewhere");
        long image = container(unique("here"));
        file("containers", project, image);

        MvcResult notHere = mvc.perform(authenticated(delete("/api/v1/projects/" + other + "/containers/" + image), asAdmin()))
                .andExpect(status().isNotFound())
                .andReturn();
        assertThat(detailOf(notHere)).isEqualTo("This image is not in that project.");
        MvcResult absent = mvc.perform(authenticated(put("/api/v1/projects/" + project + "/containers/987654"), asAdmin()))
                .andExpect(status().isNotFound())
                .andReturn();
        assertThat(detailOf(absent)).isEqualTo("Target not found.");
        mvc.perform(authenticated(put("/api/v1/projects/987654/containers/" + image), asAdmin()))
                .andExpect(status().isNotFound());

        // Every administrator sees everything today; the rule is asserted on the service the route calls.
        long hidden = container(unique("hidden"));
        Visibility narrow = Visibility.only(List.of(new ScanTarget.Container(image)));
        RequestActor actor = new RequestActor("test", "127.0.0.1", null);
        assertThatThrownBy(() -> administration.fileContainer(project, hidden, narrow, actor))
                .isInstanceOf(NoSuchElementException.class)
                .hasMessage("Target not found.");
        assertThat(containers.findById(hidden).orElseThrow().getProjectId()).isNull();
        file("containers", project, hidden);
        assertThatThrownBy(() -> administration.removeContainer(project, hidden, narrow, actor))
                .isInstanceOf(NoSuchElementException.class)
                .hasMessage("Target not found.");
        assertThat(containers.findById(hidden).orElseThrow().getProjectId()).isEqualTo(project);
    }

    @Test
    @DisplayName("a reader files and removes no image")
    void readersCannotFile() throws Exception {
        long project = project(solution(unique("readonly")), "P");
        long image = container(unique("readonly"));
        String reader = asReader();

        mvc.perform(authenticated(put("/api/v1/projects/" + project + "/containers/" + image), reader))
                .andExpect(status().isForbidden());
        mvc.perform(authenticated(delete("/api/v1/projects/" + project + "/containers/" + image), reader))
                .andExpect(status().isForbidden());
        assertThat(containers.findById(image).orElseThrow().getProjectId()).isNull();
    }

    // ------------------------------------------------------------------------------- access

    @Test
    @DisplayName("a project grant shows the project's image; taking it out of the project takes the access away")
    void aProjectGrantGivesAndRemovesImageAccess() throws Exception {
        restrict();
        long project = project(solution(unique("granted")), "Granted");
        long image = container(unique("granted"));
        issue(null, image, Severity.HIGH, TriageStatus.UNDER_REVIEW);
        Reader reader = reader();
        grantDirectly(reader.id(), "project", project);

        assertThat(visibleContainers(reader.token())).doesNotContain(image);
        issuesOfImage(reader.token(), image, 0);

        file("containers", project, image);

        assertThat(visibleContainers(reader.token())).contains(image);
        issuesOfImage(reader.token(), image, 1);
        JsonNode granted = projectNode(tree(reader.token()), project);
        assertThat(ids(granted, "containers")).containsExactly(image);
        // A restricted reader's figures are counted over the targets it sees, the image among them.
        assertThat(granted.path("openIssues").path("high").asLong()).isEqualTo(1);

        mvc.perform(authenticated(delete("/api/v1/projects/" + project + "/containers/" + image), asAdmin()))
                .andExpect(status().isNoContent());

        assertThat(visibleContainers(reader.token())).doesNotContain(image);
        issuesOfImage(reader.token(), image, 0);
        assertThat(ids(projectNode(tree(reader.token()), project), "containers")).isEmpty();
        assertThat(tree(reader.token()).path("unfiled").path("containerCount").asInt())
                .as("an unfiled image the reader holds no grant on is not in their unfiled group either")
                .isZero();
    }

    @Test
    @DisplayName("an image moving to another project moves its visibility for both projects' grantees")
    void aMoveMovesImageAccess() throws Exception {
        restrict();
        long solution = solution(unique("move"));
        long from = project(solution, "From");
        long to = project(solution, "To");
        long image = container(unique("moving"));
        file("containers", from, image);
        Reader first = reader();
        grantDirectly(first.id(), "project", from);
        Reader second = reader();
        grantDirectly(second.id(), "project", to);
        assertThat(visibleContainers(first.token())).contains(image);
        assertThat(visibleContainers(second.token())).doesNotContain(image);

        file("containers", to, image);

        assertThat(visibleContainers(first.token())).doesNotContain(image);
        assertThat(visibleContainers(second.token())).contains(image);
        assertThat(audit.recent(20)).anySatisfy(entry -> {
            assertThat(entry.getOperationType()).isEqualTo(AuditOperation.PROJECT_CONTAINERS_CHANGED.wireName());
            assertThat(entry.getDescription()).contains("moved from project From to To", "visibility moves");
        });
    }

    @Test
    @DisplayName("a project grant partially covered: an image the reader does not see makes the project partial")
    void aHiddenImageMakesTheProjectPartial() throws Exception {
        restrict();
        long solution = solution(unique("partial"));
        long project = project(solution, "Mixed");
        long repo = repository();
        long image = container(unique("partial"));
        file("repositories", project, repo);
        file("containers", project, image);
        issue(null, image, Severity.CRITICAL, TriageStatus.UNDER_REVIEW);
        Reader reader = reader();
        grantDirectly(reader.id(), "repository", repo);

        JsonNode tree = tree(reader.token());
        JsonNode node = projectNode(tree, project);
        assertThat(ids(node, "containers")).isEmpty();
        assertThat(node.path("partial").asBoolean()).as("the project holds an image this reader cannot see").isTrue();
        assertThat(node.path("openIssues").path("critical").asLong()).isZero();
        assertThat(solutionNode(tree, solution).path("partial").asBoolean()).isTrue();
    }

    // ------------------------------------------------------------------------------ filters

    @Test
    @DisplayName("the backlog's project_id and solution_id include the project's images' issues, and no other image's")
    void theBacklogFiltersIncludeImages() throws Exception {
        long solution = solution(unique("filters"));
        long project = project(solution, "Filtered");
        long repo = repository();
        long image = container(unique("filtered"));
        long elsewhere = container(unique("elsewhere"));
        file("repositories", project, repo);
        file("containers", project, image);
        issue(repo, null, Severity.HIGH, TriageStatus.UNDER_REVIEW);
        issue(null, image, Severity.HIGH, TriageStatus.UNDER_REVIEW);
        issue(null, elsewhere, Severity.HIGH, TriageStatus.UNDER_REVIEW);

        mvc.perform(authenticated(get("/api/v1/issues?project_id=" + project), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(2));
        mvc.perform(authenticated(get("/api/v1/issues?solution_id=" + solution), asAdmin()))
                .andExpect(jsonPath("$.total").value(2));
        mvc.perform(authenticated(get("/api/v1/issues?project_id=" + project + "&container_id=" + image), asAdmin()))
                .andExpect(jsonPath("$.total").value(1));
        mvc.perform(authenticated(get("/api/v1/issues?project_id=" + project + "&container_id=" + elsewhere), asAdmin()))
                .andExpect(jsonPath("$.total").value(0));
    }

    // --------------------------------------------------------------------- the whole project

    @Test
    @DisplayName("a project moving to another solution carries its images, and the solution filter follows")
    void aMoveCarriesImages() throws Exception {
        long from = solution(unique("from"));
        long to = solution(unique("to"));
        long project = project(from, "Moving");
        long image = container(unique("carried"));
        file("containers", project, image);
        issue(null, image, Severity.HIGH, TriageStatus.UNDER_REVIEW);

        mvc.perform(authenticated(patch("/api/v1/projects/" + project), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("solutionId", to))))
                .andExpect(status().isOk());

        JsonNode tree = tree(asAdmin());
        assertThat(ids(projectNode(tree, project), "containers")).containsExactly(image);
        assertThat(solutionNode(tree, to).path("containerCount").asInt()).isEqualTo(1);
        assertThat(solutionNode(tree, from).path("containerCount").asInt()).isZero();
        assertThat(containers.findById(image).orElseThrow().getProjectId()).isEqualTo(project);
        mvc.perform(authenticated(get("/api/v1/issues?solution_id=" + to), asAdmin()))
                .andExpect(jsonPath("$.total").value(1));
        mvc.perform(authenticated(get("/api/v1/issues?solution_id=" + from), asAdmin()))
                .andExpect(jsonPath("$.total").value(0));
    }

    @Test
    @DisplayName("deleting a project returns its images to no project, deletes none, and says how many")
    void deletingAProjectUnfilesImages() throws Exception {
        restrict();
        long project = project(solution(unique("doomed")), "Doomed");
        long image = container(unique("survivor"));
        file("containers", project, image);
        issue(null, image, Severity.HIGH, TriageStatus.UNDER_REVIEW);
        Reader reader = reader();
        grantDirectly(reader.id(), "project", project);
        assertThat(visibleContainers(reader.token())).contains(image);

        mvc.perform(authenticated(delete("/api/v1/projects/" + project), asAdmin())).andExpect(status().isNoContent());

        assertThat(containers.findById(image).orElseThrow().getProjectId()).as("back to no project").isNull();
        assertThat(issues.findAll()).anySatisfy(issue -> assertThat(issue.getContainerId()).isEqualTo(image));
        assertThat(ids(tree(asAdmin()).path("unfiled"), "containers")).contains(image);
        assertThat(visibleContainers(reader.token())).doesNotContain(image);
        assertThat(audit.recent(20)).anySatisfy(entry -> assertThat(entry.getDescription())
                .contains("Project deleted: Doomed (0 repository(ies) and 1 image(s) returned to no project, 1 grant(s) revoked)"));
    }

    // ------------------------------------------------------------------------------ helpers

    private record Reader(long id, String token) {}

    private Reader reader() {
        String name = "reader-" + System.nanoTime();
        String token = tokenFor(name, Role.USER, false);
        return new Reader(users.findByUsername(name).orElseThrow().getId(), token);
    }

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

    private void file(String kind, long project, long target) throws Exception {
        mvc.perform(authenticated(put("/api/v1/projects/" + project + "/" + kind + "/" + target), asAdmin()))
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

    private List<Long> visibleContainers(String token) throws Exception {
        JsonNode list = json.readTree(mvc.perform(authenticated(get("/api/v1/containers"), token))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
        return StreamSupport.stream(list.spliterator(), false).map(node -> node.path("id").asLong()).toList();
    }

    private JsonNode containerRow(String token, long id) throws Exception {
        JsonNode list = json.readTree(mvc.perform(authenticated(get("/api/v1/containers"), token))
                .andReturn().getResponse().getContentAsString());
        return StreamSupport.stream(list.spliterator(), false)
                .filter(node -> node.path("id").asLong() == id)
                .findFirst()
                .orElseThrow(() -> new AssertionError("image " + id + " is not listed"));
    }

    private void issuesOfImage(String token, long image, int expected) throws Exception {
        mvc.perform(authenticated(get("/api/v1/issues?container_id=" + image), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(expected));
    }

    private long entriesFor(long image) {
        return audit.recent(200).stream()
                .filter(entry -> AuditOperation.PROJECT_CONTAINERS_CHANGED.wireName().equals(entry.getOperationType()))
                .filter(entry -> String.valueOf(image).equals(entry.getResourceId()))
                .count();
    }

    private long idOf(String body) throws Exception {
        return json.readTree(body).path("id").asLong();
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

    private static List<Long> ids(JsonNode node, String field) {
        return StreamSupport.stream(node.path(field).spliterator(), false)
                .map(target -> target.path("id").asLong())
                .toList();
    }

    private long repository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/" + System.nanoTime() + ".git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private long container(String name) {
        ContainerEntity container = new ContainerEntity();
        container.setImageName(name);
        container.setTag("1.0");
        return containers.save(container).getId();
    }

    private void issue(Long repoId, Long containerId, Severity severity, TriageStatus triage) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setContainerId(containerId);
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
