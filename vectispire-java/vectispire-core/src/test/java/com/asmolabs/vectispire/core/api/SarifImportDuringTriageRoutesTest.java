package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mockingDetails;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.issues.Triage;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.issues.IssueTriageService;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.ProjectEntity;
import com.asmolabs.vectispire.core.targets.persistence.ProjectRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.targets.persistence.SolutionEntity;
import com.asmolabs.vectispire.core.targets.persistence.SolutionRepository;
import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

/**
 * A SARIF import and a triage writing one issue at once.
 *
 * <p>The import folds the report into the backlog as a scan does — it reads the repository's issues, then
 * saves them — and a triage committed between the two was put back to what the import had read. The
 * issue's revision (V89) refuses that save now, and the import folds again from what is committed rather
 * than failing the pipeline that sent it. The interleaving is forced: the lookup of the issues is let
 * through, then held while the person's decision commits on another thread.
 */
@DisplayName("a SARIF import during a triage")
class SarifImportDuringTriageRoutesTest extends ApiTestBase {

    @MockitoSpyBean
    private IssueRepository issues;

    @Autowired
    private IssueTriageService triage;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private SolutionRepository solutions;

    @Autowired
    private ProjectRepository projects;

    private final ExecutorService person = Executors.newSingleThreadExecutor();

    @AfterEach
    void release() {
        person.shutdownNow();
    }

    @Test
    @DisplayName("keeps the decision committed meanwhile, and the import is accepted, folded once more")
    void foldsAgain() throws Exception {
        long repositoryId = repositoryInAProject();
        String bearer = declaredSource();
        String report = SarifImportRoutesTest.sarif("Semgrep OSS", "1.90.0", "python.eval", "src/app.py");
        upload(bearer, repositoryId, report).andExpect(status().isCreated());
        long issueId = issues.findAll().stream()
                .filter(issue -> Long.valueOf(repositoryId).equals(issue.getRepoId()))
                .findFirst().orElseThrow().getId();

        AtomicReference<Runnable> once = new AtomicReference<>(() -> {
            try {
                person.submit(() -> triage.triage(issueId, new Triage.Request(
                        TriageStatus.AFFECTED, "alice", null, "Reachable.", null))).get(1, TimeUnit.MINUTES);
            } catch (Exception failed) {
                throw new IllegalStateException("The triage beside the import failed.", failed);
            }
        });
        // A repository is a proxy, whose methods a spy cannot call as real ones: the spy's own answer —
        // the delegation to the repository — reads the issues.
        org.mockito.stubbing.Answer<?> repository = mockingDetails(issues).getMockCreationSettings().getDefaultAnswer();
        doAnswer(invocation -> {
            Object read = repository.answer(invocation);
            Runnable hold = once.getAndSet(null);
            if (hold != null) {
                hold.run();
            }
            return read;
        }).when(issues).findByFingerprintIn(any());

        upload(bearer, repositoryId, report)
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.createdCount").value(0));

        IssueEntity issue = issues.findById(issueId).orElseThrow();
        assertThat(once.get()).as("the hold ran").isNull();
        assertThat(issue.getTriageStatus()).as("the person's decision").isEqualTo(TriageStatus.AFFECTED.wireName());
        assertThat(issue.getTimesSeen()).as("counted once, by the fold that committed").isEqualTo(2);
    }

    private org.springframework.test.web.servlet.ResultActions upload(String bearer, long repositoryId, String document)
            throws Exception {
        return mvc.perform(post("/api/v1/repositories/" + repositoryId + "/sarif-imports")
                .header("Authorization", "Bearer " + bearer)
                .contentType("application/sarif+json")
                .content(document.getBytes(StandardCharsets.UTF_8)));
    }

    private long repositoryInAProject() throws Exception {
        SolutionEntity solution = new SolutionEntity();
        solution.setName("solution-" + System.nanoTime());
        solution.setCreatedAt(Instant.now());
        ProjectEntity project = new ProjectEntity();
        project.setSolutionId(solutions.save(solution).getId());
        project.setName("payments");
        project.setCreatedAt(Instant.now());
        projectId = projects.save(project).getId();
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/r-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        long id = repositories.save(repository).getId();
        mvc.perform(authenticated(put("/api/v1/projects/" + projectId + "/repositories/" + id), asAdmin()))
                .andExpect(status().isNoContent());
        return id;
    }

    private long projectId;

    /** A key holding {@code sarif_import}, declared by the governor as a source for the project; answers its secret. */
    private String declaredSource() throws Exception {
        JsonNode key = json.readTree(mvc.perform(authenticated(post("/api/v1/api-keys"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "ci-" + System.nanoTime(), "scopes", List.of("sarif_import")))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        Map<String, Object> source = new LinkedHashMap<>();
        source.put("slug", "team-ci");
        source.put("name", "Team CI");
        source.put("api_key_id", key.path("key").path("id").asText());
        source.put("project_id", projectId);
        source.put("tools", List.of("Semgrep OSS"));
        mvc.perform(authenticated(post("/api/v1/sarif-sources"), tokenFor("governor-" + System.nanoTime(), Role.SUPERUSER, false))
                        .contentType(MediaType.APPLICATION_JSON).content(write(source)))
                .andExpect(status().isCreated());
        return key.path("secret").asText();
    }
}
