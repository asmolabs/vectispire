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
import com.asmolabs.vectispire.common.domain.rules.RuleSet;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.rules.RuleSetService;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

/**
 * {@code GET /api/v1/owasp/coverage} narrowed to a project or a solution.
 *
 * <p>What the screen depends on: a project's grid counts its own targets' evidence and no other
 * project's — the findings, the code findings by declared category, and whether anything was scanned at
 * all, which decides "unmeasured" — the scope is stated beside the grid, a hidden scope reads as an
 * absent one, and a request naming no scope answers the reader's estate as it always has. The scope's
 * rules are the weekly route's: these cases ask the same refusals of the grid.
 */
@DisplayName("the OWASP coverage grid, over a project or a solution")
class OwaspCoverageScopeRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private SettingsService settings;

    @Autowired
    private RuleSetService ruleSets;

    @BeforeEach
    void codeAnalysisReachesTheEstate() {
        settings.set(Setting.SAST_ENABLED, "true");
        ruleSets.deactivateAll(null);
        installRulesDeclaring("A03");
    }

    /**
     * Three projects of one solution: api holds alpha (scanned: a vulnerability, an injection); web holds
     * beta (scanned: two vulnerabilities, a misconfiguration, two injections); dormant holds gamma, never
     * scanned, with a vulnerability.
     */
    private record Estate(long solution, long api, long web, long dormant, long alpha, long beta, long gamma) {}

    private Estate anEstate() throws Exception {
        long solution = solution();
        long api = project(solution, "api");
        long web = project(solution, "web");
        long dormant = project(solution, "dormant");
        long alpha = repository();
        long beta = repository();
        long gamma = repository();
        file(api, alpha);
        file(web, beta);
        file(dormant, gamma);
        scan(alpha);
        scan(beta);
        issue(alpha, FindingType.VULNERABILITY, null);
        issue(alpha, FindingType.SAST, "A03");
        issue(beta, FindingType.VULNERABILITY, null);
        issue(beta, FindingType.VULNERABILITY, null);
        issue(beta, FindingType.IAC, null);
        issue(beta, FindingType.SAST, "A03");
        issue(beta, FindingType.SAST, "A03");
        issue(gamma, FindingType.VULNERABILITY, null);
        return new Estate(solution, api, web, dormant, alpha, beta, gamma);
    }

    @Test
    @DisplayName("two projects' grids count their own findings — by type and by declared category — and say which scope they are")
    void aProjectCountsItsOwnEvidence() throws Exception {
        Estate estate = anEstate();

        JsonNode api = grid("project_id=" + estate.api(), asAdmin());
        assertThat(findings(api, "A06")).as("alpha's vulnerability alone").isEqualTo(1);
        assertThat(findings(api, "A03")).as("alpha's injection alone").isEqualTo(1);
        assertThat(findings(api, "A05")).as("beta's misconfiguration is web's").isZero();
        assertThat(api.path("scope").path("kind").asText()).isEqualTo("project");
        assertThat(api.path("scope").path("id").asLong()).isEqualTo(estate.api());
        assertThat(api.path("scope").path("name").asText()).isEqualTo("api");
        assertThat(api.path("scope").path("partial").asBoolean()).isFalse();
        assertThat(api.path("scope").path("targetCount").asInt()).isEqualTo(1);

        JsonNode web = grid("project_id=" + estate.web(), asAdmin());
        assertThat(findings(web, "A06")).isEqualTo(2);
        assertThat(findings(web, "A03")).isEqualTo(2);
        assertThat(findings(web, "A05")).isEqualTo(1);

        JsonNode solution = grid("solution_id=" + estate.solution(), asAdmin());
        assertThat(solution.path("scope").path("kind").asText()).isEqualTo("solution");
        assertThat(solution.path("scope").path("targetCount").asInt()).isEqualTo(3);
        assertThat(findings(solution, "A06")).as("the three projects', gamma's beside scanned ones").isEqualTo(4);
        assertThat(findings(solution, "A03")).isEqualTo(3);
    }

    @Test
    @DisplayName("a project nothing scanned reads unmeasured, however covered its neighbours are")
    void scannedIsAskedOfTheScope() throws Exception {
        Estate estate = anEstate();

        JsonNode dormant = grid("project_id=" + estate.dormant(), asAdmin());
        assertThat(state(dormant, "A06")).as("gamma was never scanned").isEqualTo("NOT_MEASURED");
        assertThat(findings(dormant, "A06")).as("its vulnerability is not a measurement").isZero();
        assertThat(state(grid("", asAdmin()), "A06")).as("the estate beside it is measured").isEqualTo("FINDINGS");
    }

    @Test
    @DisplayName("naming no scope answers the reader's estate, as before, with no scope stated")
    void noScopeIsTheEstate() throws Exception {
        Estate estate = anEstate();
        long unfiled = repository();
        scan(unfiled);
        issue(unfiled, FindingType.VULNERABILITY, null);

        JsonNode estateGrid = grid("", asAdmin());
        assertThat(estateGrid.path("scope").isNull()).isTrue();
        assertThat(findings(estateGrid, "A06")).as("every project's and the unfiled repository's").isEqualTo(5);
        assertThat(findings(estateGrid, "A03")).isEqualTo(3);
        assertThat(estateGrid.path("lines")).hasSize(10);

        restrict();
        String reader = asReader();
        grant(readerId(), List.of(estate.beta()));
        JsonNode mine = grid("", reader);
        assertThat(findings(mine, "A06")).as("a restricted reader's estate is still theirs alone").isEqualTo(2);
    }

    @Test
    @DisplayName("a project seen in part is computed over its visible targets, and says partial")
    void aPartialProjectCountsWhatTheReaderSees() throws Exception {
        Estate estate = anEstate();
        long hidden = repository();
        file(estate.web(), hidden);
        scan(hidden);
        issue(hidden, FindingType.VULNERABILITY, null);
        issue(hidden, FindingType.SAST, "A03");
        restrict();
        String reader = asReader();
        grant(readerId(), List.of(estate.beta()));

        JsonNode web = grid("project_id=" + estate.web(), reader);
        assertThat(web.path("scope").path("partial").asBoolean()).isTrue();
        assertThat(web.path("scope").path("targetCount").asInt()).isEqualTo(1);
        assertThat(findings(web, "A06")).as("beta's two, not the hidden repository's").isEqualTo(2);
        assertThat(findings(web, "A03")).isEqualTo(2);

        assertThat(findings(grid("project_id=" + estate.web(), asAdmin()), "A06")).isEqualTo(3);
    }

    @Test
    @DisplayName("a project or a solution the reader sees nothing of answers 404, in the words an absent one does")
    void aHiddenScopeIsAnAbsentOne() throws Exception {
        Estate estate = anEstate();
        long elsewhere = solution();
        long secret = project(elsewhere, "secret");
        long secretRepository = repository();
        file(secret, secretRepository);
        restrict();
        String reader = asReader();
        grant(readerId(), List.of(estate.alpha()));

        MvcResult hidden = notFound("project_id=" + secret, reader);
        MvcResult absent = notFound("project_id=" + Long.MAX_VALUE, reader);
        assertThat(detailOf(hidden)).isEqualTo(detailOf(absent)).isEqualTo("Project not found.");
        assertThat(detailOf(notFound("solution_id=" + elsewhere, reader)))
                .isEqualTo(detailOf(notFound("solution_id=" + Long.MAX_VALUE, reader)))
                .isEqualTo("Solution not found.");
        assertThat(detailOf(notFound("project_id=" + Long.MAX_VALUE, asAdmin())))
                .as("absent for an administrator too").isEqualTo("Project not found.");

        assertThat(grid("project_id=" + estate.api(), reader).path("scope").path("name").asText())
                .as("the project holding the reader's repository is theirs").isEqualTo("api");
    }

    @Test
    @DisplayName("a project and a solution at once answer 400")
    void twoScopesAreRefused() throws Exception {
        Estate estate = anEstate();
        String detail = detailOf(mvc.perform(authenticated(
                        get("/api/v1/owasp/coverage?project_id=" + estate.api() + "&solution_id=" + estate.solution()),
                        asAdmin()))
                .andExpect(status().isBadRequest())
                .andReturn());
        assertThat(detail).isEqualTo("Name a project or a solution, not both.");
    }

    // ------------------------------------------------------------------------------ fixtures

    private static long findings(JsonNode grid, String id) {
        return line(grid, id).path("findings").asLong();
    }

    private static String state(JsonNode grid, String id) {
        return line(grid, id).path("state").asText();
    }

    private static JsonNode line(JsonNode grid, String id) {
        return StreamSupport.stream(grid.path("lines").spliterator(), false)
                .filter(line -> line.path("id").asText().equals(id))
                .findFirst()
                .orElseThrow();
    }

    private JsonNode grid(String query, String token) throws Exception {
        return json.readTree(mvc.perform(authenticated(get("/api/v1/owasp/coverage?" + query), token))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
    }

    private MvcResult notFound(String query, String token) throws Exception {
        return mvc.perform(authenticated(get("/api/v1/owasp/coverage?" + query), token))
                .andExpect(status().isNotFound())
                .andReturn();
    }

    /** An uploaded rule set declaring the category: with the shipped rules alone, code analysis reads unconfigured. */
    private void installRulesDeclaring(String category) {
        String rule = """
                rules:
                  - id: team.injection
                    languages: [java]
                    severity: ERROR
                    metadata:
                      category: security
                      owasp:
                        - %s:2021 - Injection
                    message: an injection
                    patterns:
                      - pattern: exec(...)
                """.formatted(category);
        ruleSets.activate(ruleSets.store(
                List.of(new RuleSet.UploadedFile("java/injection.yaml", rule)), "team rules", "tester").getId(),
                "installed by a test", null);
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

    private void grant(long userId, List<Long> repositories) throws Exception {
        mvc.perform(authenticated(put("/api/v1/users/" + userId + "/targets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(repositories.stream().map(id -> Map.of("kind", "repository", "id", id)).toList())))
                .andExpect(status().isOk());
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
        repository.setUrl("https://example.invalid/owasp-scope-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private void scan(long repoId) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repoId);
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setBranch("main");
        scan.setCreatedAt(Instant.now().minusSeconds(7200));
        scans.save(scan);
    }

    private void issue(long repoId, FindingType type, String owaspCategory) {
        Instant seen = Instant.now().minusSeconds(3600);
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setFingerprint("fp-" + System.nanoTime());
        issue.setType(type.wireName());
        issue.setIdentifier("rule-" + System.nanoTime());
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setOwaspCategory(owaspCategory);
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setFirstSeenAt(seen);
        issue.setLastSeenAt(seen);
        issue.setTimesSeen(1);
        issues.save(issue);
    }
}
