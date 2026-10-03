package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.dependencies.DependencyGraph;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentEntity;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentRepository;
import com.asmolabs.vectispire.core.inventory.persistence.BuildSbomRepository;
import com.asmolabs.vectispire.core.scanning.ScanIngestor;
import com.asmolabs.vectispire.core.scanning.ScanOrigin;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;

/**
 * A build's CycloneDX SBOM, through the real routes, completing what the scanner listed (G10, decision
 * 0039).
 *
 * <p>The fixtures are the case the capability exists for: a Maven tree whose parent imports Spring's and
 * Jackson's BOMs. The scanner's SBOM ({@code syft-ledger.json}, Syft's shape) lists {@code spring-core}
 * and {@code jackson-databind} at {@code UNKNOWN} and none of their transitive libraries; the build's
 * ({@code cyclonedx-maven-ledger.json}, {@code cyclonedx-maven-plugin}'s {@code makeAggregateBom}) states
 * every version it resolved and the libraries pulled in behind them. The scanner's rows are written by the
 * sink the scan ingestor calls, so the inventory a scan leaves is the one a real scan leaves.
 */
@DisplayName("build SBOM imports, through the routes")
class BuildSbomImportRoutesTest extends ApiTestBase {

    private static final String TEMPLATES = "/api/v1/checklist-templates";

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private ComponentRepository components;

    @Autowired
    private BuildSbomRepository buildSboms;

    @Autowired
    private AuditLogRepository auditLog;

    @Autowired
    private SettingsService settings;

    @Autowired
    private ScanIngestor.InventorySink sink;

    private long project;
    private long ledger;
    private long elsewhere;

    private record Key(String id, String secret) {}

    @BeforeEach
    void estate() throws Exception {
        settings.set(Setting.FOUR_EYES_APPROVAL_REQUIRED, "false");
        settings.set(Setting.CHECKLIST_AUTO_ANSWER, "false");
        long solution = idOf(mvc.perform(authenticated(post("/api/v1/solutions"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", "Ledger " + System.nanoTime()))))
                .andExpect(status().isCreated()));
        project = idOf(mvc.perform(authenticated(post("/api/v1/solutions/" + solution + "/projects"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", "Ledger"))))
                .andExpect(status().isCreated()));
        ledger = repository(true);
        elsewhere = repository(false);
    }

    private long repository(boolean filed) throws Exception {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/ledger-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        long id = repositories.save(repository).getId();
        if (filed) {
            mvc.perform(authenticated(put("/api/v1/projects/" + project + "/repositories/" + id), asAdmin()))
                    .andExpect(status().isNoContent());
        }
        return id;
    }

    // ------------------------------------------------------------------ the declared source

    private Key key(String... scopes) throws Exception {
        JsonNode answer = json.readTree(mvc.perform(authenticated(post("/api/v1/api-keys"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "ci-" + System.nanoTime(), "scopes", List.of(scopes)))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        return new Key(answer.path("key").path("id").asText(), answer.path("secret").asText());
    }

    private ResultActions declare(Key key, List<String> kinds) throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("slug", "ledger-ci-" + System.nanoTime() % 100_000);
        body.put("name", "Ledger CI");
        body.put("api_key_id", key.id());
        body.put("project_id", project);
        body.put("kinds", kinds);
        return mvc.perform(authenticated(post("/api/v1/sarif-sources"), tokenFor("governor-" + System.nanoTime(),
                        com.asmolabs.vectispire.common.domain.users.Role.SUPERUSER, false))
                .contentType(MediaType.APPLICATION_JSON).content(write(body)));
    }

    /** A key holding report_import, declared to deliver SBOMs on the project. */
    private Key sbomKey() throws Exception {
        Key key = key("report_import");
        declare(key, List.of("sbom")).andExpect(status().isCreated())
                .andExpect(jsonPath("$.kinds").value(Matchers.contains("sbom")));
        return key;
    }

    private ResultActions upload(String bearer, long repositoryId, String query, MediaType type, byte[] document)
            throws Exception {
        return mvc.perform(post("/api/v1/repositories/" + repositoryId + "/build-sbom-imports" + query)
                .header("Authorization", "Bearer " + bearer)
                .contentType(type)
                .content(document));
    }

    private ResultActions upload(Key key, long repositoryId, byte[] document) throws Exception {
        return upload(key.secret(), repositoryId, "?commit=4f2a9c1&branch=main",
                MediaType.parseMediaType("application/vnd.cyclonedx+json"), document);
    }

    // ------------------------------------------------------------------ the scans

    private static byte[] fixture(String name) throws IOException {
        try (InputStream in = BuildSbomImportRoutesTest.class.getResourceAsStream("/build-sbom/" + name)) {
            return in.readAllBytes();
        }
    }

    /** A completed scan of {@code branch} whose dependency step produced Syft's SBOM, its inventory written by the sink. */
    private long scan(long repositoryId, String branch, Instant createdAt) throws IOException {
        String syft = new String(fixture("syft-ledger.json"), StandardCharsets.UTF_8);
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositoryId);
        scan.setBranch(branch);
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setCreatedAt(createdAt);
        scan.setAttempts(1);
        scan.setExaminedTypes("vulnerability");
        scan.setSbom(syft);
        ScanEntity saved = scans.save(scan);
        JsonNode sbom = json.readTree(syft);
        sink.components(ScanOrigin.of(saved), sbom, new DependencyGraph(sbom));
        return saved.getId();
    }

    private Map<String, String> inventory(long scanId) {
        return components.findByScanId(scanId).stream().collect(Collectors.toMap(
                row -> row.getName(),
                row -> row.getVersion() + " " + (row.getOrigin() == null ? "scanner" : row.getOrigin())));
    }

    private static Instant hoursAgo(int hours) {
        return Instant.now().minus(Duration.ofHours(hours));
    }

    // ------------------------------------------------------------------ what an import changes

    @Nested
    @DisplayName("an accepted SBOM")
    class Accepted {

        @Test
        @DisplayName("completes the newest scan: the stated versions in place of UNKNOWN, the transitive libraries, "
                + "each row saying who listed it")
        void completesTheNewestScan() throws Exception {
            long older = scan(ledger, "main", hoursAgo(30));
            long newest = scan(ledger, "main", hoursAgo(2));
            assertThat(inventory(newest)).containsEntry("spring-core", "UNKNOWN scanner").doesNotContainKey("snakeyaml");

            JsonNode accepted = json.readTree(upload(sbomKey(), ledger, fixture("cyclonedx-maven-ledger.json"))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.repoId").value(ledger))
                    .andExpect(jsonPath("$.specVersion").value("1.6"))
                    .andExpect(jsonPath("$.tool").value("org.cyclonedx cyclonedx-maven-plugin 2.9.1"))
                    .andExpect(jsonPath("$.componentsCount").value(10))
                    .andExpect(jsonPath("$.commit").value("4f2a9c1"))
                    .andExpect(jsonPath("$.branch").value("main"))
                    .andExpect(jsonPath("$.completedScanId").value(newest))
                    .andExpect(jsonPath("$.documentSha256").value(Matchers.matchesPattern("[0-9a-f]{64}")))
                    .andReturn().getResponse().getContentAsString());

            assertThat(inventory(newest)).containsExactlyInAnyOrderEntriesOf(Map.ofEntries(
                    Map.entry("ledger-model", "1.4.0 both"),
                    Map.entry("spring-core", "6.1.14 both"),
                    Map.entry("jackson-databind", "2.17.2 both"),
                    Map.entry("logback-classic", "1.5.8 both"),
                    Map.entry("left-pad", "1.3.0 scanner"),
                    Map.entry("spring-jcl", "6.1.14 build"),
                    Map.entry("jackson-annotations", "2.17.2 build"),
                    Map.entry("jackson-core", "2.17.2 build"),
                    Map.entry("snakeyaml", "2.2 build"),
                    Map.entry("logback-core", "1.5.8 build"),
                    Map.entry("slf4j-api", "2.0.16 build")));
            // History stays what it was: only the newest scan moves on an import.
            assertThat(inventory(older)).containsEntry("spring-core", "UNKNOWN scanner").hasSize(5);

            // The search shows where each version came from, the scanner's word beside the build's.
            JsonNode found = json.readTree(mvc.perform(authenticated(get("/api/v1/inventory/search")
                                    .param("name", "spring-core"), asAdmin()))
                    .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
            JsonNode onNewest = null;
            for (JsonNode occurrence : found.path("occurrences")) {
                if (occurrence.path("scanId").asLong() == newest) {
                    onNewest = occurrence;
                }
            }
            assertThat(onNewest).isNotNull();
            assertThat(onNewest.path("componentVersion").asText()).isEqualTo("6.1.14");
            assertThat(onNewest.path("source").asText()).isEqualTo("both");
            assertThat(onNewest.path("scannerVersion").asText()).isEqualTo("UNKNOWN");
            assertThat(onNewest.path("purl").asText()).isEqualTo("pkg:maven/org.springframework/spring-core@6.1.14");

            // The project's consolidated inventory reads the same rows, and says who listed each.
            JsonNode consolidated = json.readTree(mvc.perform(authenticated(
                            get("/api/v1/projects/" + project + "/components"), asAdmin()))
                    .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
            Map<String, String> sources = new LinkedHashMap<>();
            consolidated.path("components").forEach(component -> sources.put(component.path("name").asText(),
                    component.path("version").asText() + " " + component.path("sources")));
            assertThat(sources).containsEntry("snakeyaml", "2.2 [\"build\"]")
                    .containsEntry("spring-core", "6.1.14 [\"build\",\"scanner\"]")
                    .containsEntry("left-pad", "1.3.0 [\"scanner\"]");

            mvc.perform(authenticated(get("/api/v1/repositories/" + ledger + "/build-sbom-imports"), asAuditor()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.length()").value(1))
                    .andExpect(jsonPath("$[0].id").value(accepted.path("id").asLong()))
                    .andExpect(jsonPath("$[0].completedScanId").value(newest));
            mvc.perform(authenticated(get("/api/v1/repositories/999999/build-sbom-imports"), asAdmin()))
                    .andExpect(status().isNotFound());

            List<AuditLogEntity> recorded = entries(AuditOperation.BUILD_SBOM_IMPORTED);
            assertThat(recorded).singleElement().satisfies(entry -> {
                assertThat(entry.getResourceId()).isEqualTo(String.valueOf(ledger));
                assertThat(entry.getDescription()).contains("10 component(s)").contains("scan " + newest + " completed")
                        .contains("commit 4f2a9c1").contains("sha256 " + accepted.path("documentSha256").asText().substring(0, 12));
            });
        }

        @Test
        @DisplayName("a component rule reading the newest scan's SBOM passes where the scanner alone failed it")
        void theChecklistLinePasses() throws Exception {
            publishWithRule(Map.of("kind", "component_versions", "maxAgeDays", 7, "components", List.of(
                    Map.of("purlPrefix", "pkg:maven/org.springframework/spring-core", "versions", List.of("6.1.14")),
                    Map.of("purlPrefix", "pkg:maven/org.yaml/snakeyaml", "versions", List.of("2.2")))));
            scan(ledger, "main", hoursAgo(2));
            openChecklist();

            // The false "no": snakeyaml is used, transitively, and the scanner never saw it.
            JsonNode before = measurement();
            assertThat(before.path("outcome").asText()).isEqualTo("fail");
            assertThat(before.toString()).contains("pkg:maven/org.yaml/snakeyaml is not in its SBOM");

            upload(sbomKey(), ledger, fixture("cyclonedx-maven-ledger.json")).andExpect(status().isCreated());

            JsonNode after = measurement();
            assertThat(after.path("outcome").asText()).isEqualTo("pass");
            assertThat(after.toString()).contains("pkg:maven/org.springframework/spring-core at 6.1.14")
                    .contains("pkg:maven/org.yaml/snakeyaml at 2.2");
        }

        @Test
        @DisplayName("a presence rule reads the same completed rows: the transitive library is used")
        void thePresenceLinePasses() throws Exception {
            publishWithRule(Map.of("kind", "component_present", "maxAgeDays", 7, "components",
                    List.of(Map.of("purlPrefix", "pkg:maven/org.yaml/snakeyaml"))));
            scan(ledger, "main", hoursAgo(2));
            openChecklist();
            assertThat(measurement().path("outcome").asText()).isEqualTo("fail");

            upload(sbomKey(), ledger, fixture("cyclonedx-maven-ledger.json")).andExpect(status().isCreated());

            assertThat(measurement().path("outcome").asText()).isEqualTo("pass");
        }

        @Test
        @DisplayName("the licence tallies move when an SBOM arrives, no scan moving: the build's licences and versions count")
        void theLicenceTallyMoves() throws Exception {
            scan(ledger, "main", hoursAgo(2));
            JsonNode before = licenceSummary();
            // Read once so the tally is kept: the next read must notice the import, not count afresh by chance.
            assertThat(licenceSummary()).isEqualTo(before);

            upload(sbomKey(), ledger, fixture("cyclonedx-maven-ledger.json")).andExpect(status().isCreated());

            JsonNode after = licenceSummary();
            // Five scanner rows became eleven: the six libraries only the build lists are counted, and the
            // UNKNOWN entries of spring-core and jackson-databind gave way to the build's versions.
            assertThat(after.path("totalDependencies").asLong()).isEqualTo(before.path("totalDependencies").asLong() + 6);

            JsonNode entries = json.readTree(mvc.perform(authenticated(get("/api/v1/licenses/inventory")
                                    .param("repo_id", String.valueOf(ledger)), asAdmin()))
                    .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
            Map<String, String> licences = new LinkedHashMap<>();
            entries.forEach(entry -> licences.put(entry.path("packageName").asText() + "@" + entry.path("packageVersion").asText(),
                    entry.path("license").asText()));
            assertThat(licences).containsEntry("spring-core@6.1.14", "Apache-2.0")
                    .containsEntry("snakeyaml@2.2", "Apache-2.0")
                    .containsEntry("left-pad@1.3.0", "MIT")
                    .doesNotContainKey("spring-core@UNKNOWN");
        }

        @Test
        @DisplayName("a later scan is completed by the newest SBOM; a branch the SBOM does not state is not; a newer "
                + "SBOM no longer listing a package gives the scanner's row back")
        void laterScansAndNewerSboms() throws Exception {
            Key key = sbomKey();
            scan(ledger, "main", hoursAgo(5));
            upload(key, ledger, fixture("cyclonedx-maven-ledger.json")).andExpect(status().isCreated());

            long nightly = scan(ledger, "main", hoursAgo(1));
            assertThat(inventory(nightly)).containsEntry("spring-core", "6.1.14 both").containsEntry("snakeyaml", "2.2 build");

            long feature = scan(ledger, "feature/reports", Instant.now());
            assertThat(inventory(feature)).containsEntry("spring-core", "UNKNOWN scanner").doesNotContainKey("snakeyaml");

            // The next build dropped jackson: its rows are the scanner's again, its transitive ones gone.
            ObjectNode bom = (ObjectNode) json.readTree(fixture("cyclonedx-maven-ledger.json"));
            ArrayNode kept = json.createArrayNode();
            bom.withArray("components").forEach(component -> {
                if (!component.path("group").asText().startsWith("com.fasterxml")) {
                    kept.add(component);
                }
            });
            bom.set("components", kept);
            long rescanned = scan(ledger, "main", Instant.now().plusSeconds(1));
            upload(key, ledger, json.writeValueAsBytes(bom)).andExpect(status().isCreated())
                    .andExpect(jsonPath("$.completedScanId").value(rescanned));
            assertThat(inventory(rescanned)).containsEntry("jackson-databind", "UNKNOWN scanner")
                    .doesNotContainKeys("jackson-core", "jackson-annotations")
                    .containsEntry("spring-core", "6.1.14 both");
            ComponentEntity restored = components.findByScanId(rescanned).stream()
                    .filter(row -> row.getName().equals("jackson-databind")).findFirst().orElseThrow();
            assertThat(restored.getPurl()).isEqualTo("pkg:maven/com.fasterxml.jackson.core/jackson-databind");
            assertThat(restored.getBuildSbomId()).isNull();
            assertThat(restored.getScannedVersion()).isNull();
        }

        @Test
        @DisplayName("an SBOM with no completed scan to complete is kept, and the first scan is completed by it")
        void beforeAnyScan() throws Exception {
            upload(sbomKey(), ledger, fixture("cyclonedx-maven-ledger.json")).andExpect(status().isCreated())
                    .andExpect(jsonPath("$.completedScanId").value(Matchers.nullValue()));
            assertThat(entries(AuditOperation.BUILD_SBOM_IMPORTED)).singleElement()
                    .satisfies(entry -> assertThat(entry.getDescription()).contains("no scan completed yet"));

            long first = scan(ledger, "main", Instant.now());
            assertThat(inventory(first)).hasSize(11).containsEntry("slf4j-api", "2.0.16 build");
        }
    }

    // ------------------------------------------------------------------ refusals

    @Nested
    @DisplayName("the refusals, in 0017's order")
    class Refusals {

        @Test
        @DisplayName("a session is not a source (403), a key without report_import never reaches the route (403)")
        void callers() throws Exception {
            byte[] bom = fixture("cyclonedx-maven-ledger.json");
            mvc.perform(authenticated(post("/api/v1/repositories/" + ledger + "/build-sbom-imports"), asAdmin())
                            .contentType(MediaType.APPLICATION_JSON).content(bom))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("a session is not a source")));
            upload(key("read"), ledger, bom).andExpect(status().isForbidden());
            assertThat(buildSboms.count()).isZero();
        }

        @Test
        @DisplayName("a key no source is declared for, or a source not declared for sbom (403), audited and signalled")
        void undeclared() throws Exception {
            byte[] bom = fixture("cyclonedx-maven-ledger.json");
            upload(key("report_import"), ledger, bom)
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("not declared as an enabled source")));

            Key coverageOnly = key("report_import");
            declare(coverageOnly, List.of("coverage")).andExpect(status().isCreated());
            upload(coverageOnly, ledger, bom)
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("not declared to deliver sbom")));
            assertThat(entries(AuditOperation.REPORT_IMPORT_REFUSED)).hasSize(2);
            assertThat(buildSboms.count()).isZero();
        }

        @Test
        @DisplayName("a repository outside the source's scope is a 404 in an absence's words, audited; one that does "
                + "not exist reads the same")
        void scope() throws Exception {
            Key key = sbomKey();
            byte[] bom = fixture("cyclonedx-maven-ledger.json");
            String outside = detailOf(upload(key, elsewhere, bom).andExpect(status().isNotFound()).andReturn());
            String absent = detailOf(upload(key, 999_999, bom).andExpect(status().isNotFound()).andReturn());
            assertThat(outside).isEqualTo("No repository " + elsewhere + ".");
            assertThat(absent).isEqualTo("No repository 999999.");
            assertThat(entries(AuditOperation.REPORT_IMPORT_REFUSED)).singleElement()
                    .satisfies(entry -> assertThat(entry.getDescription()).contains("not declared for repository " + elsewhere));
            assertThat(buildSboms.count()).isZero();
        }

        @Test
        @DisplayName("what is not CycloneDX JSON 1.4–1.6, lists nothing or too much is a 400 in words; past the ceiling a 413")
        void documents() throws Exception {
            Key key = sbomKey();
            String syft = detailOf(upload(key, ledger, fixture("syft-ledger.json")).andExpect(status().isBadRequest())
                    .andReturn());
            assertThat(syft).contains("Only CycloneDX JSON is read");

            ObjectNode old = (ObjectNode) json.readTree(fixture("cyclonedx-maven-ledger.json"));
            old.put("specVersion", "1.3");
            assertThat(detailOf(upload(key, ledger, json.writeValueAsBytes(old)).andExpect(status().isBadRequest())
                    .andReturn())).contains("specVersion \"1.3\"");

            ObjectNode nothing = (ObjectNode) json.readTree(fixture("cyclonedx-maven-ledger.json"));
            nothing.remove("components");
            assertThat(detailOf(upload(key, ledger, json.writeValueAsBytes(nothing)).andExpect(status().isBadRequest())
                    .andReturn())).contains("no \"components\"");

            StringBuilder many = new StringBuilder("{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"components\":[");
            for (int i = 0; i <= 50_000; i++) {
                many.append(i == 0 ? "" : ",").append("{\"name\":\"c").append(i).append("\"}");
            }
            assertThat(detailOf(upload(key, ledger, many.append("]}").toString().getBytes(StandardCharsets.UTF_8))
                    .andExpect(status().isBadRequest()).andReturn())).contains("more than 50000 components");

            byte[] huge = new byte[32 * 1024 * 1024 + 1];
            upload(key, ledger, huge).andExpect(status().is(413));
            assertThat(buildSboms.count()).isZero();
            assertThat(entries(AuditOperation.BUILD_SBOM_IMPORTED)).isEmpty();
        }
    }

    // ------------------------------------------------------------------ helpers

    private List<AuditLogEntity> entries(AuditOperation operation) {
        return auditLog.findAll().stream().filter(entry -> operation.wireName().equals(entry.getOperationType())).toList();
    }

    private JsonNode licenceSummary() throws Exception {
        return json.readTree(mvc.perform(authenticated(get("/api/v1/licenses/summary"), asAdmin()))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
    }

    private long idOf(ResultActions result) throws Exception {
        return json.readTree(result.andReturn().getResponse().getContentAsString()).path("id").asLong();
    }

    private void publishWithRule(Map<String, Object> rule) throws Exception {
        List<ChecklistWorkbooks.Line> lines = ChecklistWorkbooks.FIRST;
        mvc.perform(authenticated(post(TEMPLATES + "/release/versions"), asAdmin())
                        .contentType(MediaType.APPLICATION_OCTET_STREAM).content(ChecklistWorkbooks.of(lines)))
                .andExpect(status().isCreated());
        Map<String, Object> layout = new LinkedHashMap<>();
        layout.put("sheet", "Checklist");
        layout.put("columns", Map.of("domain", "A", "objective", "B", "control", "C", "contact", "D", "kpi", "E",
                "answer", "F", "comment", "G"));
        layout.put("firstItemRow", ChecklistWorkbooks.FIRST_ITEM_ROW);
        layout.put("lastItemRow", ChecklistWorkbooks.FIRST_ITEM_ROW + lines.size() - 1);
        layout.put("header", Map.of(
                "date", Map.of("label", "A2", "value", "B2"),
                "product", Map.of("label", "A3", "value", "B3"),
                "author", Map.of("label", "A4", "value", "B4")));
        layout.put("answers", Map.of("yes", "Done", "no", "Not done"));
        JsonNode laid = json.readTree(mvc.perform(authenticated(put(TEMPLATES + "/release/versions/1/layout"), asAdmin())
                        .param("revision", "1").contentType(MediaType.APPLICATION_JSON).content(write(layout)))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        List<Map<String, Object>> bindings = new ArrayList<>();
        Map<String, Object> line = new LinkedHashMap<>();
        line.put("itemKey", laid.at("/items/0/itemKey").asText());
        line.put("rule", rule);
        bindings.add(line);
        JsonNode bound = json.readTree(mvc.perform(authenticated(put(TEMPLATES + "/release/versions/1/rules"), asAdmin())
                        .param("revision", String.valueOf(laid.at("/version/revision").asInt()))
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("items", bindings))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        mvc.perform(authenticated(post(TEMPLATES + "/release/versions/1/publish"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"revision\":" + bound.at("/version/revision").asInt() + "}"))
                .andExpect(status().isOk());
    }

    private void openChecklist() throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("template", "release");
        body.put("version", 1);
        body.put("edition", null);
        mvc.perform(authenticated(post("/api/v1/projects/" + project + "/checklists"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(body)))
                .andExpect(status().isCreated());
    }

    private JsonNode measurement() throws Exception {
        return json.readTree(mvc.perform(authenticated(get("/api/v1/projects/" + project + "/checklists/1/measurements"),
                        asAdmin()))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).at("/lines/0/measurement");
    }
}
