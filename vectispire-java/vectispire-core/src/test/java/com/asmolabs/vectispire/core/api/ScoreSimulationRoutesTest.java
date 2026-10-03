package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.licenses.LicensePolicy;
import com.asmolabs.vectispire.common.domain.scorecard.SecurityGrade;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.inventory.LicenseGovernanceService;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.posture.ScoreSimulationService;
import com.asmolabs.vectispire.core.posture.ScoreSimulationService.ScoreSimulationScope;
import com.asmolabs.vectispire.core.posture.ScoreSimulationService.ScoreSimulationTarget;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MvcResult;
import com.fasterxml.jackson.databind.JsonNode;

/**
 * The experimental score simulation: administrators only, narrowed to the caller's allowance, and
 * the two formulas side by side over seeded estates whose current grades are the backlog item's
 * complaint — fifty and five hundred mediums both A+, twenty-seven highs and four exploited
 * criticals both 0 — and estates holding disallowed licences, which the candidate weighs as highs.
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

    @Autowired
    private LicenseGovernanceService licences;

    @Autowired
    private ContainerRepository containers;

    @Autowired
    private JdbcTemplate jdbc;

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

        // name -> current score, current grade, candidate score, candidate grade, risk points
        assertRow(byName.get("estate/clean"), 100, "A_PLUS", 100, "A_PLUS", 0);
        assertRow(byName.get("estate/one-critical"), 97, "A_PLUS", 83, "B", 10);
        assertRow(byName.get("estate/one-exploited-critical"), 72, "B", 54, "D", 25);
        assertRow(byName.get("estate/fifty-mediums"), 100, "A_PLUS", 63, "C", 25);
        assertRow(byName.get("estate/five-hundred-mediums"), 100, "A_PLUS", 1, "F", 250);
        assertRow(byName.get("estate/twenty-seven-highs"), 0, "F", 14, "F", 108);
        assertRow(byName.get("estate/four-exploited-criticals"), 0, "F", 16, "F", 100);
        assertRow(byName.get("estate/mixed"), 65, "C", 24, "F", 79);
        // The licence term: the card's own count, weighing a high's 4 — and no +5 for the scan.
        assertRow(byName.get("estate/one-disallowed-licence"), 100, "A_PLUS", 93, "A", 4);
        assertRow(byName.get("estate/one-critical-one-licence"), 92, "A", 78, "B", 14);
        assertRow(byName.get("estate/ten-disallowed-licences"), 55, "C", 48, "D", 40);
        assertThat(byName.get("estate/ten-disallowed-licences").path("licences").asLong()).isEqualTo(10);
        assertThat(byName.get("estate/never-scanned").path("currentGrade").asText()).isEqualTo("NO_DATA");
        assertThat(byName.get("estate/never-scanned").path("candidateGrade").asText()).isEqualTo("NO_DATA");
        assertThat(byName.get("estate/never-scanned").path("candidateScore").isNull()).isTrue();
        assertThat(byName.get("estate/never-scanned").path("candidateRiskPoints").isNull()).isTrue();

        // An exploited issue is its own class, counted under no severity.
        JsonNode exploited = byName.get("estate/one-exploited-critical");
        assertThat(exploited.path("exploited").asLong()).isEqualTo(1);
        assertThat(exploited.path("critical").asLong()).isZero();

        assertThat(body.path("weights").path("k").asDouble()).isEqualTo(55);
        assertThat(body.path("weights").path("medium").asDouble()).isEqualTo(0.5);
        assertThat(body.path("weights").path("licence").asDouble()).isEqualTo(4);
        Map<String, long[]> grades = new HashMap<>();
        body.path("grades").forEach(g -> grades.put(
                g.path("grade").asText(), new long[] {g.path("current").asLong(), g.path("candidate").asLong()}));
        assertThat(grades).containsOnlyKeys(
                java.util.Arrays.stream(SecurityGrade.values()).map(Enum::name).toArray(String[]::new));
        // grade -> {current, candidate}
        assertThat(grades.get("A_PLUS")).containsExactly(5, 1);
        assertThat(grades.get("A")).containsExactly(1, 1);
        assertThat(grades.get("B")).containsExactly(1, 2);
        assertThat(grades.get("C")).containsExactly(2, 1);
        assertThat(grades.get("D")).containsExactly(0, 2);
        assertThat(grades.get("F")).containsExactly(2, 4);
        assertThat(grades.get("NO_DATA")).containsExactly(1, 1);

        printTable(body);
    }

    @Test
    @DisplayName("a parameter overrides its weight, and one it cannot use is refused in words")
    void parametersOverride() throws Exception {
        seedEstates();

        JsonNode fullMedium = read(mvc.perform(authenticated(get(ROUTE).param("medium", "1"), asAdmin()))
                .andExpect(status().isOk())
                .andReturn());
        assertThat(rowOf(fullMedium, "estate/fifty-mediums").path("candidateGrade").asText()).isEqualTo("D");
        assertThat(fullMedium.path("weights").path("medium").asDouble()).isEqualTo(1);

        // A licence weighing nothing: the candidate reads the licence estate as clean.
        JsonNode freeLicences = read(mvc.perform(authenticated(get(ROUTE).param("licence", "0"), asAdmin()))
                .andExpect(status().isOk())
                .andReturn());
        JsonNode ten = rowOf(freeLicences, "estate/ten-disallowed-licences");
        assertThat(ten.path("candidateScore").asInt()).isEqualTo(100);
        assertThat(ten.path("candidateRiskPoints").asDouble()).isZero();
        assertThat(freeLicences.path("weights").path("licence").asDouble()).isZero();

        MvcResult refusedLicence = mvc.perform(authenticated(get(ROUTE).param("licence", "-1"), asAdmin()))
                .andExpect(status().isBadRequest())
                .andReturn();
        assertThat(detailOf(refusedLicence)).startsWith("licence must be");

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
                allowanceOf(new ScanTarget.Repository(only)), null, null, null, null, null, null, null);

        assertThat(narrowed.targets()).extracting(ScoreSimulationTarget::targetId).containsExactly(only);
        assertThat(narrowed.grades().stream().mapToLong(ScoreSimulationService.ScoreSimulationGrade::current).sum())
                .isEqualTo(1);
    }

    /**
     * The scopes are the tree's for the caller: a reader of one repository of a project sees that
     * project, partial and scored over that repository, and its solution likewise — nothing of the
     * projects holding nothing they were given.
     */
    @Test
    @DisplayName("lists only the projects and solutions the caller's allowance shows, scored over what it sees")
    void scopesNarrowedToTheAllowance() throws Exception {
        Scopes seeded = seedScopes();

        ScoreSimulationService.ScoreSimulation narrowed = simulations.simulate(
                allowanceOf(new ScanTarget.Repository(seeded.criticalRepository())), null, null, null, null, null, null, null);

        assertThat(narrowed.scopes()).extracting(ScoreSimulationScope::name)
                .containsExactly("critical-and-mediums", "group");
        for (ScoreSimulationScope scope : narrowed.scopes()) {
            assertThat(scope.partial()).as(scope.name()).isTrue();
            assertThat(scope.targetCount()).as(scope.name()).isEqualTo(1);
            // The critical-heavy repository alone: 3 criticals and a high, none of its neighbour's mediums.
            assertThat(scope.medium()).as(scope.name()).isZero();
            assertThat(scope.candidateRiskPoints()).as(scope.name()).isEqualTo(34);
        }
    }

    /**
     * Every project and solution under both formulas — and the double count the scope card makes
     * today, which the candidate does not.
     *
     * <p><b>The double count.</b> A scope card sums its targets' inventories, and an image's inventory
     * holds the components and licence findings of every scan naming it <em>and</em> a repository,
     * keyed to the repository, whose inventory holds them as well. {@code repo-and-image} files both
     * targets of such a scan, carrying three disallowed licences: the card — its project's compliance
     * route, the production path — counts six, the candidate three, which is what each target's own
     * card adds up to (three on the repository, none on the image). The issue that scan raised names
     * both targets and is counted once by both formulas.
     */
    @Test
    @DisplayName("lists every project and solution under both formulas, each licence counted once by the candidate")
    void scopesUnderBothFormulas() throws Exception {
        Scopes seeded = seedScopes();

        JsonNode body = read(mvc.perform(authenticated(get(ROUTE), asAdmin()))
                .andExpect(status().isOk())
                .andReturn());
        Map<String, JsonNode> byName = new HashMap<>();
        body.path("scopes").forEach(row -> byName.put(row.path("name").asText(), row));
        List<String> order = new ArrayList<>();
        body.path("scopes").forEach(row -> order.add(row.path("kind").asText() + ":" + row.path("name").asText()));
        assertThat(order).containsExactly(
                "project:critical-and-mediums", "project:empty", "project:half-scanned", "project:one-clean-repo",
                "project:repo-and-image", "solution:group", "solution:half", "solution:shared");

        // name -> current score, current grade, candidate score, candidate grade, risk points
        assertScope(byName.get("one-clean-repo"), 100, "A_PLUS", 100, "A_PLUS", 0);
        assertScope(byName.get("critical-and-mediums"), 77, "B", 30, "F", 66.5);
        assertScope(byName.get("group"), 77, "B", 30, "F", 66.5);
        // The coverage cap, the card's own: one target of two observed holds both formulas at 50.
        assertScope(byName.get("half-scanned"), 50, "D", 50, "D", 0);
        assertScope(byName.get("half"), 50, "D", 50, "D", 0);
        assertThat(byName.get("half-scanned").path("observedTargets").asInt()).isEqualTo(1);
        assertThat(byName.get("half-scanned").path("targetCount").asInt()).isEqualTo(2);
        JsonNode empty = byName.get("empty");
        assertThat(empty.path("currentGrade").asText()).isEqualTo("NO_DATA");
        assertThat(empty.path("candidateGrade").asText()).isEqualTo("NO_DATA");
        assertThat(empty.path("candidateScore").isNull()).isTrue();
        assertThat(empty.path("candidateRiskPoints").isNull()).isTrue();

        // The double count: six licences on the card, three under the candidate — the high once in both.
        // Current: 100 − 4 (high) − 6 × 5 + 5 = 71, B. Candidate: 4 + 3 × 4 = 16 points, 75, B; with the
        // card's six it would read 28 points, 60, C.
        for (String name : List.of("repo-and-image", "shared")) {
            JsonNode shared = byName.get(name);
            assertScope(shared, 71, "B", 75, "B", 16);
            assertThat(shared.path("currentLicences").asLong()).as(name).isEqualTo(6);
            assertThat(shared.path("licences").asLong()).as(name).isEqualTo(3);
            assertThat(shared.path("currentDoubleCounted").asBoolean()).as(name).isTrue();
            assertThat(shared.path("high").asLong()).as(name).isEqualTo(1);
        }
        for (String name : List.of("one-clean-repo", "critical-and-mediums", "group", "half-scanned", "half", "empty")) {
            assertThat(byName.get(name).path("currentDoubleCounted").asBoolean()).as(name).isFalse();
        }

        // The production path itself, as the project's page reads it: six.
        JsonNode card = read(mvc.perform(authenticated(get("/api/v1/projects/" + seeded.sharedProject() + "/compliance"), asAdmin()))
                .andExpect(status().isOk())
                .andReturn());
        assertThat(card.at("/scorecard/licenseViolationCount").asLong()).isEqualTo(6);
        assertThat(card.at("/scorecard/score").asInt()).isEqualTo(71);
        // And each target's own card: three on the repository, none on the image — the candidate's sum.
        Map<Long, JsonNode> targets = new HashMap<>();
        body.path("targets").forEach(row -> targets.put(row.path("targetId").asLong() * 2
                + ("container".equals(row.path("targetKind").asText()) ? 1 : 0), row));
        assertThat(targets.get(seeded.sharedRepository() * 2).path("licences").asLong()).isEqualTo(3);
        JsonNode image = targets.get(seeded.sharedImage() * 2 + 1);
        assertThat(image == null ? 0 : image.path("licences").asLong()).isZero();
        assertThat(read(mvc.perform(authenticated(get("/api/v1/scorecards/repositories/" + seeded.sharedRepository()), asAdmin()))
                .andExpect(status().isOk()).andReturn()).path("licenseViolationCount").asLong()).isEqualTo(3);
        assertThat(read(mvc.perform(authenticated(get("/api/v1/scorecards/containers/" + seeded.sharedImage()), asAdmin()))
                .andExpect(status().isOk()).andReturn()).path("licenseViolationCount").asLong()).isZero();

        printScopes(body);
    }

    /** An allowance of these targets alone, granting no project as such. */
    private static VisibilityService.Allowance allowanceOf(ScanTarget... targets) {
        return new VisibilityService.Allowance(Visibility.only(List.of(targets)), Set.of());
    }

    /** What the scope tests name afterwards. */
    private record Scopes(long sharedProject, long sharedRepository, long sharedImage, long criticalRepository) {}

    /**
     * Three solutions: {@code group} holding {@code one-clean-repo} and {@code critical-and-mediums} (a
     * repository of three criticals and a high beside one of sixty mediums and twenty lows); {@code
     * shared} holding {@code repo-and-image}, a repository and an image each scanned, plus a scan naming
     * both that carries one high and three disallowed licence findings; {@code half} holding an empty
     * project and {@code half-scanned}, a clean scanned repository beside one never scanned.
     */
    private Scopes seedScopes() throws Exception {
        licences.updatePolicy(LicensePolicy.defaultPolicy());
        long group = solution("group");
        long cleanProject = project(group, "one-clean-repo");
        file("repositories", cleanProject, repository("scopes/clean", true));
        long mixedProject = project(group, "critical-and-mediums");
        long criticalRepository = seed("scopes/criticals", 0, 3, 1, 0, 0);
        file("repositories", mixedProject, criticalRepository);
        file("repositories", mixedProject, seed("scopes/mediums", 0, 0, 0, 60, 20));

        long shared = solution("shared");
        long sharedProject = project(shared, "repo-and-image");
        long sharedRepository = repository("scopes/shared", true);
        ContainerEntity container = new ContainerEntity();
        container.setImageName("registry.example.test/scopes/shared");
        container.setTag("1.0");
        long sharedImage = containers.save(container).getId();
        ScanEntity ofImage = new ScanEntity();
        ofImage.setContainerId(sharedImage);
        ofImage.setBranch("main");
        ofImage.setStatus("completed");
        ofImage.setCreatedAt(Instant.now());
        scans.save(ofImage);
        ScanEntity both = new ScanEntity();
        both.setRepoId(sharedRepository);
        both.setContainerId(sharedImage);
        both.setBranch("main");
        both.setStatus("completed");
        both.setCreatedAt(Instant.now());
        long bothId = scans.save(both).getId();
        for (int i = 0; i < 3; i++) {
            jdbc.update("insert into t_finding (scan_id, type, source, package_name, package_version, identifier, is_kev, created_at, reachability)"
                    + " values (?, 'license', 'trivy', ?, '1.0', 'GPL-3.0-only', false, ?, 'UNKNOWN')",
                    bothId, "gpl-" + i, Timestamp.from(Instant.now()));
        }
        List<IssueEntity> raised = new ArrayList<>();
        add(raised, sharedRepository, 1, "high", false);
        raised.forEach(issue -> issue.setContainerId(sharedImage));
        issues.saveAll(raised);
        file("repositories", sharedProject, sharedRepository);
        file("containers", sharedProject, sharedImage);

        long half = solution("half");
        project(half, "empty");
        long halfProject = project(half, "half-scanned");
        file("repositories", halfProject, repository("scopes/half-clean", true));
        file("repositories", halfProject, repository("scopes/half-never", false));
        return new Scopes(sharedProject, sharedRepository, sharedImage, criticalRepository);
    }

    private long solution(String name) throws Exception {
        return json.readTree(mvc.perform(authenticated(post("/api/v1/solutions"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", name))))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString()).path("id").asLong();
    }

    private long project(long solution, String name) throws Exception {
        return json.readTree(mvc.perform(authenticated(post("/api/v1/solutions/" + solution + "/projects"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", name))))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString()).path("id").asLong();
    }

    private void file(String kind, long project, long target) throws Exception {
        mvc.perform(authenticated(put("/api/v1/projects/" + project + "/" + kind + "/" + target), asAdmin()))
                .andExpect(status().isNoContent());
    }

    private static void assertScope(
            JsonNode row, int current, String currentGrade, int candidate, String candidateGrade, double riskPoints) {
        assertThat(row).as("scope row").isNotNull();
        String name = row.path("name").asText();
        assertThat(row.path("currentScore").asInt()).as(name + " current").isEqualTo(current);
        assertThat(row.path("currentGrade").asText()).as(name + " current grade").isEqualTo(currentGrade);
        assertThat(row.path("candidateScore").asInt()).as(name + " candidate").isEqualTo(candidate);
        assertThat(row.path("candidateGrade").asText()).as(name + " candidate grade").isEqualTo(candidateGrade);
        assertThat(row.path("candidateRiskPoints").asDouble()).as(name + " risk points").isEqualTo(riskPoints);
    }

    /** The scopes' comparison, in the test's output. */
    private static void printScopes(JsonNode body) {
        StringBuilder table = new StringBuilder("\n| scope | targets | exploited | critical | high | medium | low"
                + " | licences (card) | current | candidate | risk points |\n");
        body.path("scopes").forEach(row -> table.append("| %s %s | %d/%d | %d | %d | %d | %d | %d | %d (%d) | %s %s | %s %s | %s |%n".formatted(
                row.path("kind").asText(), row.path("name").asText(),
                row.path("observedTargets").asInt(), row.path("targetCount").asInt(),
                row.path("exploited").asLong(), row.path("critical").asLong(), row.path("high").asLong(),
                row.path("medium").asLong(), row.path("low").asLong(),
                row.path("licences").asLong(), row.path("currentLicences").asLong(),
                row.path("currentScore").asText(), row.path("currentGrade").asText(),
                row.path("candidateScore").asText(), row.path("candidateGrade").asText(),
                row.path("candidateRiskPoints").asText())));
        System.out.println(table);
    }

    private static void assertRow(
            JsonNode row, int current, String currentGrade, int candidate, String candidateGrade, double riskPoints) {
        assertThat(row).as("row").isNotNull();
        String name = row.path("targetName").asText();
        assertThat(row.path("currentScore").asInt()).as(name + " current").isEqualTo(current);
        assertThat(row.path("currentGrade").asText()).as(name + " current grade").isEqualTo(currentGrade);
        assertThat(row.path("candidateScore").asInt()).as(name + " candidate").isEqualTo(candidate);
        assertThat(row.path("candidateGrade").asText()).as(name + " candidate grade").isEqualTo(candidateGrade);
        assertThat(row.path("candidateRiskPoints").asDouble()).as(name + " risk points").isEqualTo(riskPoints);
    }

    private static JsonNode rowOf(JsonNode body, String name) {
        for (JsonNode row : body.path("targets")) {
            if (row.path("targetName").asText().equals(name)) {
                return row;
            }
        }
        throw new AssertionError("no row for " + name);
    }

    /**
     * The estates the backlog item names, each a scanned repository, plus one nobody scanned that
     * holds an open issue — a target with neither is not graded, so not listed. The
     * production score adds 5 for a completed scan, so a clean scanned target is 100 and one
     * critical 97. The licence estates carry an SBOM listing GPL-3.0-only components, which the
     * default policy refuses: the inventory's tally is what both formulas read.
     */
    private Map<String, Long> seedEstates() {
        // Stated, not assumed: the policy is a singleton row the between-test cleanup does not empty,
        // and a class that relaxed it earlier in the run left GPL-3.0-only allowed — the licence
        // estates then read clean under both formulas.
        licences.updatePolicy(LicensePolicy.defaultPolicy());
        Map<String, Long> ids = new HashMap<>();
        ids.put("estate/clean", repository("estate/clean", true));
        ids.put("estate/one-critical", seed("estate/one-critical", 0, 1, 0, 0, 0));
        ids.put("estate/one-exploited-critical", seed("estate/one-exploited-critical", 1, 0, 0, 0, 0));
        ids.put("estate/fifty-mediums", seed("estate/fifty-mediums", 0, 0, 0, 50, 0));
        ids.put("estate/five-hundred-mediums", seed("estate/five-hundred-mediums", 0, 0, 0, 500, 0));
        ids.put("estate/twenty-seven-highs", seed("estate/twenty-seven-highs", 0, 0, 27, 0, 0));
        ids.put("estate/four-exploited-criticals", seed("estate/four-exploited-criticals", 4, 0, 0, 0, 0));
        ids.put("estate/mixed", seed("estate/mixed", 0, 2, 6, 40, 120));
        ids.put("estate/one-disallowed-licence", withLicences("estate/one-disallowed-licence", 1, 0));
        ids.put("estate/one-critical-one-licence", withLicences("estate/one-critical-one-licence", 1, 1));
        ids.put("estate/ten-disallowed-licences", withLicences("estate/ten-disallowed-licences", 10, 0));
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

    /** A scanned repository whose SBOM lists {@code disallowed} GPL-3.0-only components and one MIT. */
    private long withLicences(String name, int disallowed, int criticals) {
        StringBuilder sbom = new StringBuilder("{\"artifacts\":[");
        for (int i = 0; i <= disallowed; i++) {
            String licence = i < disallowed ? "GPL-3.0-only" : "MIT";
            sbom.append(i > 0 ? "," : "").append("{\"name\":\"pkg").append(i).append("\",\"version\":\"1.0\",")
                    .append("\"licenses\":[{\"value\":\"").append(licence).append("\"}]}");
        }
        long repo = repository(name, sbom.append("]}").toString());
        List<IssueEntity> rows = new ArrayList<>();
        add(rows, repo, criticals, "critical", false);
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
        return scanned ? repository(name, (String) null) : unscanned(name);
    }

    private long unscanned(String name) {
        RepositoryEntity repo = new RepositoryEntity();
        repo.setName(name);
        repo.setUrl("https://git.example.test/" + name + ".git");
        repo.setBranch("main");
        return repositories.save(repo).getId();
    }

    /** A repository holding one completed scan, carrying {@code sbom} when it is not null. */
    private long repository(String name, String sbom) {
        long repo = unscanned(name);
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repo);
        scan.setBranch("main");
        scan.setStatus("completed");
        scan.setCreatedAt(Instant.now());
        scan.setSbom(sbom);
        scans.save(scan);
        return repo;
    }

    private JsonNode read(MvcResult result) throws Exception {
        return json.readTree(result.getResponse().getContentAsString());
    }

    /** The comparison, in the test's output — what the backlog item's decision is taken on. */
    private static void printTable(JsonNode body) {
        StringBuilder table = new StringBuilder(
                "\n| target | exploited | critical | high | medium | low | licences | current | candidate | risk points |\n");
        body.path("targets").forEach(row -> table.append("| %s | %d | %d | %d | %d | %d | %d | %s %s | %s %s | %s |%n".formatted(
                row.path("targetName").asText(), row.path("exploited").asLong(), row.path("critical").asLong(),
                row.path("high").asLong(), row.path("medium").asLong(), row.path("low").asLong(),
                row.path("licences").asLong(),
                row.path("currentScore").asText(), row.path("currentGrade").asText(),
                row.path("candidateScore").asText(), row.path("candidateGrade").asText(),
                row.path("candidateRiskPoints").asText())));
        table.append("\n| grade | current | candidate |\n");
        body.path("grades").forEach(g -> table.append("| %s | %d | %d |%n".formatted(
                g.path("grade").asText(), g.path("current").asLong(), g.path("candidate").asLong())));
        System.out.println(table);
    }
}
