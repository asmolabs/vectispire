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
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentEntity;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentRepository;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.StreamSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

/**
 * The aggregates over one project or one solution (decision 0023): the project read on its own, its and
 * a solution's compliance and score, the project's consolidated SBOM and its CycloneDX document.
 *
 * <p>Each route is held to the tree's visibility rule on the wire — whole, partial, none (404 in the
 * words of an absence) — and each figure to the scope's targets: a clean project in a dirty estate is
 * compliant, one nobody scanned is no data, and a partial reader's figures leave the hidden targets out.
 */
@DisplayName("a project's and a solution's aggregates")
class ProjectAggregatesRoutesTest extends ApiTestBase {

    private static final String VULNERABILITIES = "ISO-A.8.8";

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ContainerRepository containers;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private ComponentRepository components;

    @Autowired
    private UserRepository users;

    @Autowired
    private SettingsService settings;

    private String visibilityBefore;

    @BeforeEach
    void rememberVisibility() {
        visibilityBefore = settings.get(Setting.TARGET_VISIBILITY);
    }

    @AfterEach
    void restoreVisibility() {
        settings.set(Setting.TARGET_VISIBILITY, visibilityBefore);
    }

    // ------------------------------------------------------------------------ the project read

    @Nested
    @DisplayName("GET /api/v1/projects/{id}")
    class Read {

        @Test
        @DisplayName("reads the project as its tree node does, with its solution named")
        void whole() throws Exception {
            String solutionName = unique("Shop");
            long solution = solution(solutionName);
            long project = project(solution, "Storefront");
            long repo = repository("storefront");
            long image = container("storefront");
            file("repositories", project, repo);
            file("containers", project, image);
            issue(repo, null, Severity.HIGH, TriageStatus.UNDER_REVIEW);
            issue(null, image, Severity.CRITICAL, TriageStatus.UNDER_REVIEW);
            issue(null, image, Severity.CRITICAL, TriageStatus.NOT_AFFECTED);

            JsonNode read = read(get("/api/v1/projects/" + project), asAdmin());

            assertThat(read.path("id").asLong()).isEqualTo(project);
            assertThat(read.path("name").asText()).isEqualTo("Storefront");
            assertThat(read.path("solution").path("id").asLong()).isEqualTo(solution);
            assertThat(read.path("solution").path("name").asText()).isEqualTo(solutionName);
            assertThat(read.path("solutionId").asLong()).isEqualTo(solution);
            assertThat(ids(read, "repositories")).containsExactly(repo);
            assertThat(ids(read, "containers")).containsExactly(image);
            assertThat(read.path("openIssues").path("critical").asLong()).as("the settled one left out").isEqualTo(1);
            assertThat(read.path("openIssues").path("total").asLong()).isEqualTo(2);
            assertThat(read.path("partial").asBoolean()).isFalse();
            assertThat(read.path("checklistsVisible").asBoolean()).isTrue();
            assertThat(read.path("detectedLanguages").isArray()).isTrue();
            assertThat(read.path("languagesUnknownFor").isArray()).isTrue();

            // Field for field what the tree's node says: the two cannot disagree.
            JsonNode node = projectNode(read(get("/api/v1/solutions"), asAdmin()), project);
            for (String field : List.of("partial", "checklistsVisible", "repositoryCount", "containerCount",
                    "openIssues", "repositories", "containers", "detectedLanguages", "languagesUnknownFor")) {
                assertThat(read.path(field)).as(field).isEqualTo(node.path(field));
            }
        }

        @Test
        @DisplayName("a reader who sees part of it reads that part, partial; one who sees none of it, and an absent id, read 404 alike")
        void partialAndNone() throws Exception {
            restrict();
            long project = project(solution(unique("split")), "Split");
            long seen = repository("seen");
            long hidden = repository("hidden");
            file("repositories", project, seen);
            file("repositories", project, hidden);
            issue(seen, null, Severity.LOW, TriageStatus.UNDER_REVIEW);
            issue(hidden, null, Severity.CRITICAL, TriageStatus.UNDER_REVIEW);
            Reader partial = reader();
            grant(partial.id(), "repository", seen);
            Reader outsider = reader();
            grant(outsider.id(), "repository", repository("elsewhere"));

            JsonNode read = read(get("/api/v1/projects/" + project), partial.token());
            assertThat(read.path("partial").asBoolean()).isTrue();
            assertThat(ids(read, "repositories")).containsExactly(seen);
            assertThat(read.path("openIssues").path("critical").asLong()).as("the hidden repository's").isZero();
            assertThat(read.path("openIssues").path("low").asLong()).isEqualTo(1);
            assertThat(read.path("checklistsVisible").asBoolean()).isFalse();

            MvcResult none = mvc.perform(authenticated(get("/api/v1/projects/" + project), outsider.token()))
                    .andExpect(status().isNotFound()).andReturn();
            MvcResult absent = mvc.perform(authenticated(get("/api/v1/projects/987654"), asAdmin()))
                    .andExpect(status().isNotFound()).andReturn();
            assertThat(detailOf(none)).isEqualTo("Project not found.").isEqualTo(detailOf(absent));
        }

        @Test
        @DisplayName("a project granted as such is read while it holds nothing, as the tree lists it")
        void grantedEmpty() throws Exception {
            restrict();
            long project = project(solution(unique("empty")), "Empty");
            Reader grantee = reader();
            grant(grantee.id(), "project", project);

            JsonNode read = read(get("/api/v1/projects/" + project), grantee.token());
            assertThat(read.path("repositories").size()).isZero();
            assertThat(read.path("partial").asBoolean()).isFalse();
            mvc.perform(authenticated(get("/api/v1/projects/" + project), reader().token()))
                    .andExpect(status().isNotFound());
        }

        @Test
        @DisplayName("a read key reads it, an export key does not, and one narrowed to another repository reads 404")
        void keys() throws Exception {
            long project = project(solution(unique("keys")), "Keyed");
            long repo = repository("keyed");
            file("repositories", project, repo);
            long other = repository("other");

            mvc.perform(authenticated(get("/api/v1/projects/" + project), key(List.of("read"), null)))
                    .andExpect(status().isOk());
            mvc.perform(authenticated(get("/api/v1/projects/" + project), key(List.of("export"), null)))
                    .andExpect(status().isForbidden());
            mvc.perform(authenticated(get("/api/v1/projects/" + project), key(List.of("read"), other)))
                    .andExpect(status().isNotFound());
            JsonNode narrowed = read(get("/api/v1/projects/" + project), key(List.of("read"), repo));
            assertThat(ids(narrowed, "repositories")).containsExactly(repo);
        }
    }

    // ------------------------------------------------------------------------------ compliance

    @Nested
    @DisplayName("compliance per project and per solution")
    class Compliance {

        @Test
        @DisplayName("a clean project in a dirty estate is compliant and scores clean; the estate is not")
        void cleanProjectInADirtyEstate() throws Exception {
            long solution = solution(unique("clean"));
            long project = project(solution, "Clean");
            long clean = repository("clean");
            file("repositories", project, clean);
            completedScan(clean, null, null);
            long dirty = repository("dirty");
            completedScan(dirty, null, null);
            issue(dirty, null, Severity.CRITICAL, TriageStatus.UNDER_REVIEW);
            issue(dirty, null, Severity.CRITICAL, TriageStatus.UNDER_REVIEW);

            JsonNode scoped = read(get("/api/v1/projects/" + project + "/compliance"), asAdmin());
            JsonNode estate = read(get("/api/v1/compliance/summary"), asAdmin());

            assertThat(scoped.path("kind").asText()).isEqualTo("project");
            assertThat(scoped.path("name").asText()).isEqualTo("Clean");
            assertThat(scoped.path("partial").asBoolean()).isFalse();
            assertThat(scoped.path("targetCount").asInt()).isEqualTo(1);
            assertThat(scoped.at("/compliance/totalMonitoredTargets").asInt()).isEqualTo(1);
            assertThat(targetIds(scoped.path("compliance"))).containsExactly("repo:" + clean);
            assertThat(controlStatus(scoped.path("compliance"), VULNERABILITIES)).isEqualTo("COMPLIANT");
            assertThat(controlStatus(estate, VULNERABILITIES)).as("the estate carries the criticals").isNotEqualTo("COMPLIANT");
            assertThat(scoped.at("/scorecard/criticalCount").asLong()).isZero();
            assertThat(scoped.at("/scorecard/targetKind").asText()).isEqualTo("project");
            assertThat(scoped.at("/scorecard/targetId").asLong()).isEqualTo(project);
            assertThat(scoped.at("/scorecard/score").asInt())
                    .isGreaterThan(read(get("/api/v1/scorecards/global"), asAdmin()).path("score").asInt());

            // The solution holding it is as clean; the unfiled dirty repository is in neither.
            JsonNode ofSolution = read(get("/api/v1/solutions/" + solution + "/compliance"), asAdmin());
            assertThat(ofSolution.path("kind").asText()).isEqualTo("solution");
            assertThat(targetIds(ofSolution.path("compliance"))).containsExactly("repo:" + clean);
            assertThat(controlStatus(ofSolution.path("compliance"), VULNERABILITIES)).isEqualTo("COMPLIANT");
        }

        @Test
        @DisplayName("a project none of whose targets was scanned is no data, however scanned the estate")
        void noData() throws Exception {
            long project = project(solution(unique("unscanned")), "Unscanned");
            file("repositories", project, repository("unscanned"));
            completedScan(repository("scanned-elsewhere"), null, null);

            JsonNode scoped = read(get("/api/v1/projects/" + project + "/compliance"), asAdmin());
            assertThat(texts(scoped.at("/compliance/evaluations"), "overallStatus")).containsOnly("NO_DATA");
            assertThat(scoped.at("/compliance/observedTargets").asInt()).isZero();
            assertThat(texts(read(get("/api/v1/compliance/summary"), asAdmin()).path("evaluations"), "overallStatus"))
                    .as("the estate, scanned, is measured")
                    .doesNotContain("NO_DATA");
        }

        @Test
        @DisplayName("a partial reader's compliance is over the part it sees, partial; none, and absent, read 404 alike")
        void visibility() throws Exception {
            restrict();
            long solution = solution(unique("seen"));
            long project = project(solution, "Mixed");
            long seen = repository("seen");
            long hidden = repository("hidden");
            file("repositories", project, seen);
            file("repositories", project, hidden);
            completedScan(seen, null, null);
            completedScan(hidden, null, null);
            issue(hidden, null, Severity.CRITICAL, TriageStatus.UNDER_REVIEW);
            Reader partial = reader();
            grant(partial.id(), "repository", seen);
            Reader outsider = reader();
            grant(outsider.id(), "repository", repository("outside"));

            JsonNode scoped = read(get("/api/v1/projects/" + project + "/compliance"), partial.token());
            assertThat(scoped.path("partial").asBoolean()).isTrue();
            assertThat(scoped.path("targetCount").asInt()).isEqualTo(1);
            assertThat(targetIds(scoped.path("compliance"))).containsExactly("repo:" + seen);
            assertThat(controlStatus(scoped.path("compliance"), VULNERABILITIES))
                    .as("the hidden repository's critical is not in it")
                    .isEqualTo("COMPLIANT");
            assertThat(scoped.at("/scorecard/criticalCount").asLong()).isZero();
            JsonNode ofSolution = read(get("/api/v1/solutions/" + solution + "/compliance"), partial.token());
            assertThat(ofSolution.path("partial").asBoolean()).isTrue();
            assertThat(targetIds(ofSolution.path("compliance"))).containsExactly("repo:" + seen);

            for (String path : List.of("/api/v1/projects/" + project + "/compliance", "/api/v1/projects/987654/compliance")) {
                MvcResult refused = mvc.perform(authenticated(get(path), path.contains("987654") ? asAdmin() : outsider.token()))
                        .andExpect(status().isNotFound()).andReturn();
                assertThat(detailOf(refused)).isEqualTo("Project not found.");
            }
            for (String path : List.of("/api/v1/solutions/" + solution + "/compliance", "/api/v1/solutions/987654/compliance")) {
                MvcResult refused = mvc.perform(authenticated(get(path), path.contains("987654") ? asAdmin() : outsider.token()))
                        .andExpect(status().isNotFound()).andReturn();
                assertThat(detailOf(refused)).isEqualTo("Solution not found.");
            }
        }

        @Test
        @DisplayName("a read key reads both, an export key neither")
        void keys() throws Exception {
            long solution = solution(unique("keys"));
            long project = project(solution, "Keyed");
            file("repositories", project, repository("keyed"));
            String reading = key(List.of("read"), null);
            String exporting = key(List.of("export"), null);

            for (String path : List.of("/api/v1/projects/" + project + "/compliance", "/api/v1/solutions/" + solution + "/compliance")) {
                mvc.perform(authenticated(get(path), reading)).andExpect(status().isOk());
                mvc.perform(authenticated(get(path), exporting)).andExpect(status().isForbidden());
            }
        }
    }

    // ---------------------------------------------------------------------- consolidated SBOM

    @Nested
    @DisplayName("the consolidated SBOM")
    class Components {

        @Test
        @DisplayName("merges the newest completed scans by purl and version, names who carries each, and says what it could not read")
        void merge() throws Exception {
            long project = project(solution(unique("sbom")), "Bill");
            long api = repository("api");
            long web = repository("web");
            long image = container("bill");
            long never = container("never");
            long empty = repository("empty");
            for (long repo : List.of(api, web, empty)) {
                file("repositories", project, repo);
            }
            file("containers", project, image);
            file("containers", project, never);

            // An older scan's inventory is not the target's any more.
            long stale = completedScan(api, null, "{\"artifacts\":[]}");
            component(stale, "gone", "0.1", "pkg:maven/org.example/gone@0.1");
            long apiScan = completedScan(api, null, "{\"artifacts\":[]}");
            component(apiScan, "log4j-core", "2.17.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1");
            component(apiScan, "jackson-databind", "2.15.0", "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.15.0");
            long webScan = completedScan(web, null, "{\"artifacts\":[]}");
            component(webScan, "log4j-core", "2.17.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1");
            component(webScan, "log4j-core", "2.14.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
            // One package URL written without its version, for two versions: two lines, the version being what
            // an advisory is about.
            component(apiScan, "left-pad", "1.3.0", "pkg:npm/left-pad");
            component(webScan, "left-pad", "1.3.0", "pkg:npm/left-pad");
            component(webScan, "left-pad", "1.2.0", "pkg:npm/left-pad");
            // A newer scan still running does not replace the completed one.
            ScanEntity running = scan(web, null, ScanStatus.SCANNING, null);
            component(running.getId(), "running-only", "1.0", "pkg:npm/running-only@1.0");
            long imageScan = completedScan(null, image, null);
            completedScan(empty, null, "{\"artifacts\":[]}");

            JsonNode merged = read(get("/api/v1/projects/" + project + "/components"), asAdmin());

            assertThat(merged.path("kind").asText()).isEqualTo("project");
            assertThat(merged.path("partial").asBoolean()).isFalse();
            assertThat(merged.path("complete").asBoolean()).as("an image never scanned, another with no SBOM").isFalse();
            assertThat(states(merged)).containsExactlyInAnyOrderEntriesOf(Map.of(
                    "repository:" + api, "listed",
                    "repository:" + web, "listed",
                    "repository:" + empty, "empty",
                    "container:" + image, "absent",
                    "container:" + never, "never_scanned"));
            JsonNode apiRow = targetRow(merged, "repository", api);
            assertThat(apiRow.path("scanId").asLong()).isEqualTo(apiScan);
            assertThat(apiRow.path("componentCount").asInt()).isEqualTo(3);
            assertThat(targetRow(merged, "container", image).path("scanId").asLong()).isEqualTo(imageScan);
            assertThat(targetRow(merged, "container", never).path("scanId").isNull()).isTrue();

            List<String> lines = new ArrayList<>();
            merged.path("components").forEach(line -> lines.add(line.path("name").asText() + "@" + line.path("version").asText()));
            assertThat(lines).containsExactly("jackson-databind@2.15.0", "left-pad@1.2.0", "left-pad@1.3.0",
                    "log4j-core@2.14.1", "log4j-core@2.17.1");
            assertThat(carriers(componentLine(merged, "left-pad", "1.3.0"))).containsExactly("repository:" + api, "repository:" + web);
            assertThat(carriers(componentLine(merged, "left-pad", "1.2.0"))).containsExactly("repository:" + web);
            JsonNode shared = componentLine(merged, "log4j-core", "2.17.1");
            assertThat(carriers(shared)).containsExactly("repository:" + api, "repository:" + web);
            assertThat(shared.path("purl").asText()).isEqualTo("pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1");
            assertThat(carriers(componentLine(merged, "log4j-core", "2.14.1"))).containsExactly("repository:" + web);
        }

        @Test
        @DisplayName("a partial reader's merge holds its targets' components only; none, and absent, read 404 alike")
        void visibility() throws Exception {
            restrict();
            long project = project(solution(unique("sbom-split")), "Split");
            long seen = repository("seen");
            long hidden = repository("hidden");
            file("repositories", project, seen);
            file("repositories", project, hidden);
            component(completedScan(seen, null, "{\"artifacts\":[]}"), "visible-lib", "1.0", "pkg:npm/visible-lib@1.0");
            component(completedScan(hidden, null, "{\"artifacts\":[]}"), "secret-lib", "1.0", "pkg:npm/secret-lib@1.0");
            Reader partial = reader();
            grant(partial.id(), "repository", seen);
            Reader outsider = reader();
            grant(outsider.id(), "repository", repository("outside"));

            JsonNode merged = read(get("/api/v1/projects/" + project + "/components"), partial.token());
            assertThat(merged.path("partial").asBoolean()).isTrue();
            assertThat(merged.path("complete").asBoolean()).as("every visible target was read").isTrue();
            assertThat(states(merged)).containsOnlyKeys("repository:" + seen);
            assertThat(merged.toString()).doesNotContain("secret-lib");

            JsonNode document = read(get("/api/v1/cyclonedx/projects/" + project + "/cyclonedx-vex.json"), partial.token());
            assertThat(document.toString()).doesNotContain("secret-lib");
            assertThat(document.at("/compositions/0/aggregate").asText()).as("the caller sees part of it").isEqualTo("incomplete");
            assertThat(properties(document.at("/metadata/properties"), "vectispire:partial")).containsExactly("true");

            for (String path : List.of("/api/v1/projects/%d/components", "/api/v1/cyclonedx/projects/%d/cyclonedx-vex.json")) {
                MvcResult none = mvc.perform(authenticated(get(path.formatted(project)), outsider.token()))
                        .andExpect(status().isNotFound()).andReturn();
                MvcResult absent = mvc.perform(authenticated(get(path.formatted(987654)), asAdmin()))
                        .andExpect(status().isNotFound()).andReturn();
                assertThat(detailOf(none)).isEqualTo("Project not found.").isEqualTo(detailOf(absent));
            }
        }

        @Test
        @DisplayName("the CycloneDX document lists the merge with its carriers and the project's CVEs, and says when it is whole")
        void document() throws Exception {
            long project = project(solution(unique("cdx")), "Documented");
            long api = repository("api");
            long web = repository("web");
            file("repositories", project, api);
            file("repositories", project, web);
            String purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1";
            component(completedScan(api, null, "{\"artifacts\":[]}"), "org.apache.logging.log4j:log4j-core", "2.14.1", purl);
            component(completedScan(web, null, "{\"artifacts\":[]}"), "org.apache.logging.log4j:log4j-core", "2.14.1", purl);
            IssueEntity cve = issue(api, null, Severity.CRITICAL, TriageStatus.UNDER_REVIEW);
            cve.setPurl(purl);
            cve.setPackageName("org.apache.logging.log4j:log4j-core");
            cve.setPackageVersion("2.14.1");
            issues.save(cve);
            long outsider = repository("outside");
            issue(outsider, null, Severity.CRITICAL, TriageStatus.UNDER_REVIEW);

            MvcResult result = mvc.perform(authenticated(
                            get("/api/v1/cyclonedx/projects/" + project + "/cyclonedx-vex.json"), key(List.of("export"), null)))
                    .andExpect(status().isOk()).andReturn();
            assertThat(result.getResponse().getHeader("Content-Disposition"))
                    .contains("project-" + project + "-cyclonedx-vex.json");
            JsonNode document = json.readTree(result.getResponse().getContentAsString());

            assertThat(document.path("bomFormat").asText()).isEqualTo("CycloneDX");
            assertThat(document.at("/metadata/component/name").asText()).isEqualTo("Documented");
            assertThat(document.path("components").size()).as("one line for the two repositories").isEqualTo(1);
            JsonNode line = document.path("components").get(0);
            assertThat(line.path("bom-ref").asText()).isEqualTo(purl);
            assertThat(properties(line.path("properties"), "vectispire:target"))
                    .containsExactly("repository:" + api, "repository:" + web);
            assertThat(document.path("vulnerabilities").size()).as("the project's CVE, not the outsider's").isEqualTo(1);
            assertThat(document.at("/vulnerabilities/0/id").asText()).isEqualTo(cve.getIdentifier());
            assertThat(document.at("/vulnerabilities/0/affects/0/ref").asText()).isEqualTo(purl);
            assertThat(document.at("/compositions/0/aggregate").asText()).isEqualTo("complete");
            assertThat(properties(document.at("/metadata/properties"), "vectispire:inventory-unknown")).isEmpty();

            // A read key reads the JSON and not the document; the export key the document and not the JSON.
            String reading = key(List.of("read"), null);
            mvc.perform(authenticated(get("/api/v1/cyclonedx/projects/" + project + "/cyclonedx-vex.json"), reading))
                    .andExpect(status().isForbidden());
            mvc.perform(authenticated(get("/api/v1/projects/" + project + "/components"), reading))
                    .andExpect(status().isOk());
            mvc.perform(authenticated(get("/api/v1/projects/" + project + "/components"), key(List.of("export"), null)))
                    .andExpect(status().isForbidden());

            // A target never scanned makes it incomplete, and the document names it.
            long image = container("unread");
            file("containers", project, image);
            JsonNode incomplete = read(get("/api/v1/cyclonedx/projects/" + project + "/cyclonedx-vex.json"), asAdmin());
            assertThat(incomplete.at("/compositions/0/aggregate").asText()).isEqualTo("incomplete");
            assertThat(properties(incomplete.at("/metadata/properties"), "vectispire:inventory-unknown"))
                    .containsExactly("container:" + image);
        }
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

    private JsonNode read(org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder request, String token)
            throws Exception {
        return json.readTree(mvc.perform(authenticated(request, token))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
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

    private void grant(long userId, String kind, long id) throws Exception {
        mvc.perform(authenticated(put("/api/v1/users/" + userId + "/targets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(List.of(Map.of("kind", kind, "id", id)))))
                .andExpect(status().isOk());
    }

    /** An administrator's integration key with these scopes, narrowed to a repository when one is named. */
    private String key(List<String> scopes, Long repository) throws Exception {
        Map<String, Object> body = repository == null
                ? Map.of("name", unique("key"), "scopes", scopes)
                : Map.of("name", unique("key"), "scopes", scopes, "target_kind", "repository", "target_id", repository);
        return json.readTree(mvc.perform(authenticated(post("/api/v1/api-keys"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(body)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString()).path("secret").asText();
    }

    private long repository(String name) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/" + name + "-" + System.nanoTime() + ".git");
        repository.setName(name);
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private long container(String name) {
        ContainerEntity container = new ContainerEntity();
        container.setImageName(name + "-" + System.nanoTime());
        container.setTag("1.0");
        return containers.save(container).getId();
    }

    private ScanEntity scan(Long repoId, Long containerId, ScanStatus status, String sbom) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repoId);
        scan.setContainerId(containerId);
        scan.setStatus(status.wireName());
        scan.setBranch("main");
        scan.setCreatedAt(Instant.now());
        scan.setSbom(sbom);
        return scans.save(scan);
    }

    private long completedScan(Long repoId, Long containerId, String sbom) {
        return scan(repoId, containerId, ScanStatus.COMPLETED, sbom).getId();
    }

    private void component(long scanId, String name, String version, String purl) {
        ComponentEntity component = new ComponentEntity();
        component.setScanId(scanId);
        component.setName(name);
        component.setVersion(version);
        component.setPurl(purl);
        component.setType("library");
        component.setIsDirect(true);
        components.save(component);
    }

    private IssueEntity issue(Long repoId, Long containerId, Severity severity, TriageStatus triage) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setContainerId(containerId);
        issue.setFingerprint("fp-" + System.nanoTime());
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier("CVE-2021-" + System.nanoTime() % 100000);
        issue.setSeverity(severity.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(triage.wireName());
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        return issues.save(issue);
    }

    private static List<Long> ids(JsonNode node, String field) {
        return StreamSupport.stream(node.path(field).spliterator(), false).map(target -> target.path("id").asLong()).toList();
    }

    private static JsonNode projectNode(JsonNode tree, long id) {
        return StreamSupport.stream(tree.path("solutions").spliterator(), false)
                .flatMap(solution -> StreamSupport.stream(solution.path("projects").spliterator(), false))
                .filter(node -> node.path("id").asLong() == id)
                .findFirst()
                .orElseThrow(() -> new AssertionError("project " + id + " is not in the tree"));
    }

    private static List<String> texts(JsonNode array, String field) {
        List<String> values = new ArrayList<>();
        array.forEach(element -> values.add(element.path(field).asText()));
        return values;
    }

    private static List<String> targetIds(JsonNode summary) {
        return texts(summary.path("targets"), "targetId");
    }

    /** The control's status in the ISO 27001 evaluation of a summary. */
    private static String controlStatus(JsonNode summary, String controlId) {
        for (JsonNode evaluation : summary.path("evaluations")) {
            for (JsonNode control : evaluation.path("controls")) {
                if (control.at("/control/id").asText().equals(controlId)) {
                    return control.path("status").asText();
                }
            }
        }
        throw new AssertionError("no control " + controlId);
    }

    private static Map<String, String> states(JsonNode merged) {
        Map<String, String> states = new java.util.HashMap<>();
        merged.path("targets").forEach(target ->
                states.put(target.path("kind").asText() + ":" + target.path("id").asLong(), target.path("inventory").asText()));
        return states;
    }

    private static JsonNode targetRow(JsonNode merged, String kind, long id) {
        return StreamSupport.stream(merged.path("targets").spliterator(), false)
                .filter(target -> target.path("kind").asText().equals(kind) && target.path("id").asLong() == id)
                .findFirst()
                .orElseThrow(() -> new AssertionError(kind + " " + id + " is not listed"));
    }

    private static JsonNode componentLine(JsonNode merged, String name, String version) {
        return StreamSupport.stream(merged.path("components").spliterator(), false)
                .filter(line -> line.path("name").asText().equals(name) && line.path("version").asText().equals(version))
                .findFirst()
                .orElseThrow(() -> new AssertionError(name + "@" + version + " is not listed"));
    }

    private static List<String> carriers(JsonNode line) {
        return StreamSupport.stream(line.path("targets").spliterator(), false)
                .map(target -> target.path("kind").asText() + ":" + target.path("id").asLong())
                .toList();
    }

    private static List<String> properties(JsonNode properties, String name) {
        return StreamSupport.stream(properties.spliterator(), false)
                .filter(property -> property.path("name").asText().equals(name))
                .map(property -> property.path("value").asText())
                .toList();
    }
}
