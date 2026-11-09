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
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.ReasonCode;
import com.asmolabs.vectispire.common.domain.rules.RuleSet;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.rules.RuleSetService;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.StreamSupport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * {@code GET /api/v1/owasp/coverage}: every line's reason as a code and its values, beside the English
 * sentence (decision 0019).
 *
 * <p><b>Why a route test and not only the domain's.</b> The screen translates what the JSON carries: a
 * field the serializer drops, a count it writes as a string, a code a scope of this route never produces
 * — each is invisible to a test of the rule and visible here. The codes are enumerated from {@link
 * ReasonCode} itself, so a code added to the rule and never produced by this route, or never listed here
 * as unreachable with its reason, fails.
 */
@DisplayName("the OWASP coverage grid's reasons, as the route sends them")
class OwaspCoverageReasonsRoutesTest extends ApiTestBase {

    /**
     * The codes this route cannot produce, each with why. A target's own line is the weekly record's and
     * the model's, never this grid's; and no category is placed by switchable types alone — end of life
     * shares A06 with the vulnerabilities — so "detection is off" answers a switch that does not exist yet.
     */
    private static final Set<ReasonCode> NOT_ON_THIS_ROUTE = EnumSet.of(
            ReasonCode.TARGET_KIND_NOT_EXAMINED,
            ReasonCode.CODE_ANALYSIS_READS_REPOSITORIES_ONLY,
            ReasonCode.DETECTION_OFF,
            ReasonCode.DETECTION_AND_CODE_ANALYSIS_OFF);

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ContainerRepository containers;

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

    @Test
    @DisplayName("every code a scope's grid can produce comes with its values, and with the English sentence beside it")
    void everyReasonTheRouteProduces() throws Exception {
        long solution = solution();

        long examined = project(solution, "examined");
        long scanned = repository();
        file(examined, scanned);
        scan(scanned, ScanStatus.COMPLETED);
        issue(scanned, FindingType.VULNERABILITY);
        JsonNode examinedGrid = grid("project_id=" + examined, asAdmin());

        long partly = project(solution, "partly");
        long never = repository();
        long failed = repository();
        file(partly, never);
        file(partly, failed);
        scan(failed, ScanStatus.FAILED);
        JsonNode partlyGrid = grid("project_id=" + partly, asAdmin());

        long images = project(solution, "images");
        long image = container();
        fileContainer(images, image);
        JsonNode imagesGrid = grid("project_id=" + images, asAdmin());

        // A restricted reader granted nothing reads a grid over no target at all.
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        JsonNode nothingGrid = grid("", asReader());
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.EVERYONE.wireName());

        settings.set(Setting.SAST_ENABLED, "false");
        JsonNode codeOffGrid = grid("", asAdmin());

        // Each line carries the sentence it always did, and the code beside it — additive, never instead.
        Set<ReasonCode> produced = EnumSet.noneOf(ReasonCode.class);
        for (JsonNode grid : List.of(examinedGrid, partlyGrid, imagesGrid, nothingGrid, codeOffGrid)) {
            for (JsonNode line : grid.path("lines")) {
                assertThat(line.path("because").asText()).as(line.path("id").asText()).isNotBlank();
                JsonNode reason = line.path("reason");
                assertThat(reason.path("types").isArray()).as("types is always a list").isTrue();
                assertThat(reason.path("gaps").isArray()).as("gaps is always a list").isTrue();
                produced.add(ReasonCode.valueOf(reason.path("code").asText()));
            }
        }
        assertThat(produced).isEqualTo(EnumSet.complementOf(EnumSet.copyOf(NOT_ON_THIS_ROUTE)));

        assertThat(code(examinedGrid, "A01")).isEqualTo("NO_SCANNER");
        assertThat(code(examinedGrid, "A06")).isEqualTo("OPEN_FINDINGS");
        assertThat(reason(examinedGrid, "A07").path("code").asText()).isEqualTo("EXAMINED_NOTHING_OPEN");
        assertThat(texts(reason(examinedGrid, "A07").path("types"))).containsExactly("secret");
        assertThat(reason(examinedGrid, "A07").path("missing").isNull()).isTrue();
        assertThat(code(examinedGrid, "A03")).isEqualTo("CODE_EXAMINED_NOTHING_OPEN");

        JsonNode unexamined = reason(partlyGrid, "A07");
        assertThat(unexamined.path("code").asText()).isEqualTo("TARGETS_NOT_EXAMINED");
        assertThat(texts(unexamined.path("types"))).containsExactly("secret");
        assertThat(unexamined.path("missing").isIntegralNumber()).isTrue();
        assertThat(unexamined.path("missing").asLong()).isEqualTo(2);
        assertThat(unexamined.path("applicable").asLong()).isEqualTo(2);
        assertThat(gaps(unexamined)).containsExactly(Map.entry("NEVER_SCANNED", 1L), Map.entry("LAST_SCAN_FAILED", 1L));
        assertThat(line(partlyGrid, "A07").path("because").asText())
                .isEqualTo("2 of 2 targets this category applies to were not examined for it by secret (1 never "
                        + "finished a scan, 1 whose latest scan failed), so a zero here would not be a result.");
        JsonNode code = reason(partlyGrid, "A03");
        assertThat(code.path("code").asText()).isEqualTo("REPOSITORIES_NOT_EXAMINED");
        assertThat(texts(code.path("types"))).isEmpty();
        assertThat(code.path("missing").asLong()).isEqualTo(2);
        assertThat(code.path("applicable").asLong()).isEqualTo(2);

        assertThat(reason(imagesGrid, "A07").path("code").asText()).isEqualTo("NO_EXAMINABLE_TARGET_IN_SCOPE");
        assertThat(texts(reason(imagesGrid, "A07").path("types"))).containsExactly("secret");
        assertThat(code(imagesGrid, "A03")).isEqualTo("NO_REPOSITORY_IN_SCOPE");
        assertThat(code(nothingGrid, "A07")).isEqualTo("NOTHING_SCANNED");
        assertThat(code(codeOffGrid, "A03")).isEqualTo("CODE_ANALYSIS_OFF");
    }

    // ------------------------------------------------------------------------------ fixtures

    private static String code(JsonNode grid, String id) {
        return reason(grid, id).path("code").asText();
    }

    private static JsonNode reason(JsonNode grid, String id) {
        return line(grid, id).path("reason");
    }

    private static List<String> texts(JsonNode array) {
        return StreamSupport.stream(array.spliterator(), false).map(JsonNode::asText).toList();
    }

    private static List<Map.Entry<String, Long>> gaps(JsonNode reason) {
        return StreamSupport.stream(reason.path("gaps").spliterator(), false)
                .map(gap -> Map.entry(gap.path("gap").asText(), gap.path("targets").asLong()))
                .toList();
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

    private void fileContainer(long project, long container) throws Exception {
        mvc.perform(authenticated(put("/api/v1/projects/" + project + "/containers/" + container), asAdmin()))
                .andExpect(status().isNoContent());
    }

    private long idOf(String body) throws Exception {
        return json.readTree(body).path("id").asLong();
    }

    private long repository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/owasp-reasons-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private long container() {
        ContainerEntity container = new ContainerEntity();
        container.setRegistry("registry.example.invalid");
        container.setImageName("owasp-reasons-" + System.nanoTime());
        container.setTag("1.0");
        return containers.save(container).getId();
    }

    private void scan(long repoId, ScanStatus status) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repoId);
        scan.setStatus(status.wireName());
        // Every step produced: a category reads clean only on what the latest scan recorded examining.
        if (status == ScanStatus.COMPLETED) {
            scan.setExaminedTypes("vulnerability,secret,iac,license,eol,sast");
            scan.setDetectedLanguages("java");
            scan.setSastLanguages("java");
        }
        scan.setBranch("main");
        scan.setCreatedAt(Instant.now().minusSeconds(7200));
        scans.save(scan);
    }

    private void issue(long repoId, FindingType type) {
        Instant seen = Instant.now().minusSeconds(3600);
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setFingerprint("fp-" + System.nanoTime());
        issue.setType(type.wireName());
        issue.setIdentifier("rule-" + System.nanoTime());
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setFirstSeenAt(seen);
        issue.setLastSeenAt(seen);
        issue.setTimesSeen(1);
        issues.save(issue);
    }
}
