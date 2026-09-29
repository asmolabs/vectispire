package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
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
 * The languages a repository's newest completed scan found, on the repository list and on its
 * project's node of the tree — where the plugin screen puts them beside a plugin's languages.
 *
 * <p>What the suite turns on: unknown is {@code null} (a repository) or named (a project), never an
 * empty list (decision 0007); and a project's union is taken over what its reader sees, a hidden
 * repository's languages being as much its own as its findings.
 */
@DisplayName("the languages detected in repositories and projects")
class DetectedLanguagesRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private SettingsService settings;

    @Test
    @DisplayName("a repository answers its newest completed scan's languages, sorted; unknown is null, none is []")
    void theRepositoryList() throws Exception {
        long current = repository();
        scan(current, ScanStatus.COMPLETED, "java");
        scan(current, ScanStatus.COMPLETED, "typescript,java");
        scan(current, ScanStatus.FAILED, "go");
        long forgotten = repository();
        scan(forgotten, ScanStatus.COMPLETED, "python");
        scan(forgotten, ScanStatus.COMPLETED, null);
        long empty = repository();
        scan(empty, ScanStatus.COMPLETED, "");
        long never = repository();

        JsonNode rows = json.readTree(mvc.perform(authenticated(get("/api/v1/repositories"), asAdmin()))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());

        assertThat(languages(row(rows, current))).containsExactly("java", "typescript");
        assertThat(row(rows, forgotten).has("detectedLanguages"))
                .describedAs("sent, as null — not omitted")
                .isTrue();
        assertThat(row(rows, forgotten).path("detectedLanguages").isNull()).isTrue();
        assertThat(row(rows, never).path("detectedLanguages").isNull()).isTrue();
        assertThat(row(rows, empty).path("detectedLanguages").isArray()).isTrue();
        assertThat(row(rows, empty).path("detectedLanguages")).isEmpty();
    }

    @Test
    @DisplayName("a project's node carries the union over the repositories its reader sees, and names the unknown ones")
    void theProjectNode() throws Exception {
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        long solution = created(post("/api/v1/solutions"), Map.of("name", "languages-" + System.nanoTime()));
        long project = created(post("/api/v1/solutions/" + solution + "/projects"), Map.of("name", "Core"));
        long java = repository();
        scan(java, ScanStatus.COMPLETED, "java,typescript");
        long kotlin = repository();
        scan(kotlin, ScanStatus.COMPLETED, "kotlin,java");
        long unscanned = repository();
        long hidden = repository();
        scan(hidden, ScanStatus.COMPLETED, "rust");
        for (long repository : List.of(java, kotlin, unscanned, hidden)) {
            mvc.perform(authenticated(put("/api/v1/projects/" + project + "/repositories/" + repository), asAdmin()))
                    .andExpect(status().isNoContent());
        }

        JsonNode whole = projectNode(tree(asAdmin()), project);
        assertThat(languages(whole)).containsExactly("java", "kotlin", "rust", "typescript");
        assertThat(ids(whole.path("languagesUnknownFor"))).containsExactly(unscanned);

        String reader = asReader();
        long readerId = readerId();
        mvc.perform(authenticated(put("/api/v1/users/" + readerId + "/targets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(List.of(
                                Map.of("kind", "repository", "id", java),
                                Map.of("kind", "repository", "id", unscanned)))))
                .andExpect(status().isOk());

        JsonNode partial = projectNode(tree(reader), project);
        assertThat(languages(partial))
                .describedAs("the repositories this reader cannot see say nothing of the project to them")
                .containsExactly("java", "typescript");
        assertThat(ids(partial.path("languagesUnknownFor"))).containsExactly(unscanned);
    }

    private long repository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/detected-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private void scan(long repositoryId, ScanStatus status, String languages) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositoryId);
        scan.setBranch("main");
        scan.setStatus(status.wireName());
        scan.setCreatedAt(Instant.now());
        scan.setFindingsCount(0);
        scan.setNewIssuesCount(0);
        scan.setResolvedIssuesCount(0);
        scan.setDetectedLanguages(languages);
        scans.save(scan);
    }

    private long created(org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder request,
            Map<String, Object> body) throws Exception {
        return json.readTree(mvc.perform(authenticated(request, asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(body)))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString()).path("id").asLong();
    }

    private JsonNode tree(String token) throws Exception {
        return json.readTree(mvc.perform(authenticated(get("/api/v1/solutions"), token))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
    }

    private static JsonNode projectNode(JsonNode tree, long id) {
        return StreamSupport.stream(tree.path("solutions").spliterator(), false)
                .flatMap(solution -> StreamSupport.stream(solution.path("projects").spliterator(), false))
                .filter(node -> node.path("id").asLong() == id)
                .findFirst()
                .orElseThrow(() -> new AssertionError("project " + id + " is not in the tree"));
    }

    private static JsonNode row(JsonNode rows, long id) {
        return StreamSupport.stream(rows.spliterator(), false)
                .filter(node -> node.path("id").asLong() == id)
                .findFirst()
                .orElseThrow(() -> new AssertionError("repository " + id + " is not listed"));
    }

    private static List<String> languages(JsonNode node) {
        return StreamSupport.stream(node.path("detectedLanguages").spliterator(), false).map(JsonNode::asText).toList();
    }

    private static List<Long> ids(JsonNode array) {
        return StreamSupport.stream(array.spliterator(), false).map(JsonNode::asLong).toList();
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
}
