package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.scorecard.SecurityGrade;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.posture.ScoreSimulationService;
import com.asmolabs.vectispire.core.posture.ScoreSimulationService.ScoreSimulationTarget;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import com.fasterxml.jackson.databind.JsonNode;

/**
 * The experimental score simulation: administrators only, narrowed to the caller's allowance, and
 * the two formulas side by side over seeded estates whose current grades are the backlog item's
 * complaint — fifty and five hundred mediums both A+, twenty-seven highs and four exploited
 * criticals both 0.
 */
@DisplayName("the score simulation route (experimental)")
class ScoreSimulationRoutesTest extends ApiTestBase {

    private static final String ROUTE = "/api/v1/scorecards/simulation";

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private ScoreSimulationService simulations;

    @Test
    @DisplayName("lists every target under both formulas, with the grade distribution under each")
    void bothFormulasSideBySide() throws Exception {
        Map<String, Long> ids = seedEstates();

        JsonNode body = read(mvc.perform(authenticated(get(ROUTE), asAdmin()))
                .andExpect(status().isOk())
                .andReturn());

        Map<String, JsonNode> byName = new HashMap<>();
        body.path("targets").forEach(row -> byName.put(row.path("targetName").asText(), row));
        assertThat(byName).containsKeys(ids.keySet().toArray(String[]::new));

        // name -> current score, current grade, candidate score, candidate grade
        assertRow(byName.get("estate/clean"), 100, "A_PLUS", 100, "A_PLUS");
        assertRow(byName.get("estate/one-critical"), 97, "A_PLUS", 83, "B");
        assertRow(byName.get("estate/one-exploited-critical"), 72, "B", 54, "D");
        assertRow(byName.get("estate/fifty-mediums"), 100, "A_PLUS", 40, "D");
        assertRow(byName.get("estate/five-hundred-mediums"), 100, "A_PLUS", 1, "F");
        assertRow(byName.get("estate/twenty-seven-highs"), 0, "F", 14, "F");
        assertRow(byName.get("estate/four-exploited-criticals"), 0, "F", 16, "F");
        assertThat(byName.get("estate/never-scanned").path("currentGrade").asText()).isEqualTo("NO_DATA");
        assertThat(byName.get("estate/never-scanned").path("candidateGrade").asText()).isEqualTo("NO_DATA");
        assertThat(byName.get("estate/never-scanned").path("candidateScore").isNull()).isTrue();

        // An exploited issue is its own class, counted under no severity.
        JsonNode exploited = byName.get("estate/one-exploited-critical");
        assertThat(exploited.path("exploited").asLong()).isEqualTo(1);
        assertThat(exploited.path("critical").asLong()).isZero();

        assertThat(body.path("weights").path("k").asDouble()).isEqualTo(55);
        Map<String, long[]> grades = new HashMap<>();
        body.path("grades").forEach(g -> grades.put(
                g.path("grade").asText(), new long[] {g.path("current").asLong(), g.path("candidate").asLong()}));
        assertThat(grades).containsOnlyKeys(
                java.util.Arrays.stream(SecurityGrade.values()).map(Enum::name).toArray(String[]::new));
        assertThat(grades.get("A_PLUS")).containsExactly(4, 1);
        assertThat(grades.get("F")).containsExactly(2, 4);

        printTable(body);
    }

    @Test
    @DisplayName("a parameter overrides its weight, and one it cannot use is refused in words")
    void parametersOverride() throws Exception {
        seedEstates();

        JsonNode halfMedium = read(mvc.perform(authenticated(get(ROUTE).param("medium", "0.5"), asAdmin()))
                .andExpect(status().isOk())
                .andReturn());
        JsonNode fifty = null;
        for (JsonNode row : halfMedium.path("targets")) {
            if (row.path("targetName").asText().equals("estate/fifty-mediums")) {
                fifty = row;
            }
        }
        assertThat(fifty).isNotNull();
        assertThat(fifty.path("candidateGrade").asText()).isEqualTo("C");
        assertThat(halfMedium.path("weights").path("medium").asDouble()).isEqualTo(0.5);

        MvcResult refused = mvc.perform(authenticated(get(ROUTE).param("k", "0"), asAdmin()))
                .andExpect(status().isBadRequest())
                .andReturn();
        assertThat(detailOf(refused)).isEqualTo("k must be greater than zero.");
    }

    @Test
    @DisplayName("an account without an administrative role is refused, and so is an administrator's key")
    void administratorsOnly() throws Exception {
        seedEstates();
        mvc.perform(authenticated(get(ROUTE), asReader())).andExpect(status().isForbidden());
        mvc.perform(authenticated(get(ROUTE), asCiso())).andExpect(status().isForbidden());
        mvc.perform(get(ROUTE)).andExpect(status().isUnauthorized());

        // An integration key acts for its account, narrowed to its target — and this route accepts
        // none, so not even an administrator's key reaches the whole estate's figures through it.
        String keyResponse = mvc.perform(authenticated(post("/api/v1/api-keys"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "ci", "scopes", List.of("read")))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String key = json.readTree(keyResponse).get("secret").asText();
        int status = mvc.perform(get(ROUTE).header("X-API-Key", key)).andReturn().getResponse().getStatus();
        assertThat(status).isIn(401, 403);
    }

    /**
     * The narrowing is the service's, not the marker's: called with an allowance of one target, it
     * lists that target and grades the distribution over it alone.
     */
    @Test
    @DisplayName("lists only what the caller's allowance holds")
    void narrowedToTheAllowance() {
        Map<String, Long> ids = seedEstates();
        long only = ids.get("estate/fifty-mediums");

        ScoreSimulationService.ScoreSimulation narrowed = simulations.simulate(
                Visibility.only(List.of(new ScanTarget.Repository(only))), null, null, null, null, null, null);

        assertThat(narrowed.targets()).extracting(ScoreSimulationTarget::targetId).containsExactly(only);
        assertThat(narrowed.grades().stream().mapToLong(ScoreSimulationService.ScoreSimulationGrade::current).sum())
                .isEqualTo(1);
    }

    private static void assertRow(JsonNode row, int current, String currentGrade, int candidate, String candidateGrade) {
        assertThat(row).as("row").isNotNull();
        String name = row.path("targetName").asText();
        assertThat(row.path("currentScore").asInt()).as(name + " current").isEqualTo(current);
        assertThat(row.path("currentGrade").asText()).as(name + " current grade").isEqualTo(currentGrade);
        assertThat(row.path("candidateScore").asInt()).as(name + " candidate").isEqualTo(candidate);
        assertThat(row.path("candidateGrade").asText()).as(name + " candidate grade").isEqualTo(candidateGrade);
    }

    /**
     * The estates the backlog item names, each a scanned repository, plus one nobody scanned that
     * holds an open issue — a target with neither is not graded, so not listed. The
     * production score adds 5 for a completed scan, so a clean scanned target is 100 and one
     * critical 97.
     */
    private Map<String, Long> seedEstates() {
        Map<String, Long> ids = new HashMap<>();
        ids.put("estate/clean", repository("estate/clean", true));
        ids.put("estate/one-critical", seed("estate/one-critical", 0, 1, 0, 0, 0));
        ids.put("estate/one-exploited-critical", seed("estate/one-exploited-critical", 1, 0, 0, 0, 0));
        ids.put("estate/fifty-mediums", seed("estate/fifty-mediums", 0, 0, 0, 50, 0));
        ids.put("estate/five-hundred-mediums", seed("estate/five-hundred-mediums", 0, 0, 0, 500, 0));
        ids.put("estate/twenty-seven-highs", seed("estate/twenty-seven-highs", 0, 0, 27, 0, 0));
        ids.put("estate/four-exploited-criticals", seed("estate/four-exploited-criticals", 4, 0, 0, 0, 0));
        ids.put("estate/mixed", seed("estate/mixed", 0, 2, 6, 40, 120));
        // Listed for its open issue (an import alone, say), never scanned: no data under either formula.
        long neverScanned = repository("estate/never-scanned", false);
        List<IssueEntity> imported = new ArrayList<>();
        add(imported, neverScanned, 1, "high", false);
        issues.saveAll(imported);
        ids.put("estate/never-scanned", neverScanned);
        return ids;
    }

    private long seed(String name, int exploitedCriticals, int criticals, int highs, int mediums, int lows) {
        long repo = repository(name, true);
        List<IssueEntity> rows = new ArrayList<>();
        add(rows, repo, exploitedCriticals, "critical", true);
        add(rows, repo, criticals, "critical", false);
        add(rows, repo, highs, "high", false);
        add(rows, repo, mediums, "medium", false);
        add(rows, repo, lows, "low", false);
        issues.saveAll(rows);
        return repo;
    }

    private static void add(List<IssueEntity> rows, long repo, int count, String severity, boolean kev) {
        for (int i = 0; i < count; i++) {
            IssueEntity issue = new IssueEntity();
            issue.setRepoId(repo);
            issue.setType("cve");
            issue.setSource("trivy");
            issue.setSeverity(severity);
            issue.setState("open");
            issue.setFingerprint("fp-" + repo + "-" + severity + "-" + kev + "-" + i);
            issue.setKev(kev);
            issue.setTriageStatus("untriaged");
            issue.setFirstSeenAt(Instant.now());
            issue.setLastSeenAt(Instant.now());
            rows.add(issue);
        }
    }

    private long repository(String name, boolean scanned) {
        RepositoryEntity repo = new RepositoryEntity();
        repo.setName(name);
        repo.setUrl("https://git.example.test/" + name + ".git");
        repo.setBranch("main");
        repo = repositories.save(repo);
        if (scanned) {
            ScanEntity scan = new ScanEntity();
            scan.setRepoId(repo.getId());
            scan.setBranch("main");
            scan.setStatus("completed");
            scan.setCreatedAt(Instant.now());
            scans.save(scan);
        }
        return repo.getId();
    }

    private JsonNode read(MvcResult result) throws Exception {
        return json.readTree(result.getResponse().getContentAsString());
    }

    /** The comparison, in the test's output — what the backlog item's decision is taken on. */
    private static void printTable(JsonNode body) {
        StringBuilder table = new StringBuilder("\n| target | exploited | critical | high | medium | low | current | candidate |\n");
        body.path("targets").forEach(row -> table.append("| %s | %d | %d | %d | %d | %d | %s %s | %s %s |%n".formatted(
                row.path("targetName").asText(), row.path("exploited").asLong(), row.path("critical").asLong(),
                row.path("high").asLong(), row.path("medium").asLong(), row.path("low").asLong(),
                row.path("currentScore").asText(), row.path("currentGrade").asText(),
                row.path("candidateScore").asText(), row.path("candidateGrade").asText())));
        System.out.println(table);
    }
}
