package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.plugins.persistence.SarifImportEntity;
import com.asmolabs.vectispire.core.plugins.persistence.SarifImportRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.ProjectEntity;
import com.asmolabs.vectispire.core.targets.persistence.ProjectRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.targets.persistence.SolutionEntity;
import com.asmolabs.vectispire.core.targets.persistence.SolutionRepository;
import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;

/**
 * SARIF from declared internal sources, through the real routes: who may declare a source, which key
 * may deposit a report, for which repository, from which tool — and what an accepted report does to
 * the backlog, and says about where it came from.
 */
@DisplayName("SARIF imports, through the routes")
class SarifImportRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private SarifImportRepository sarifImports;

    @Autowired
    private SolutionRepository solutions;

    @Autowired
    private ProjectRepository projects;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private AuditLogRepository auditLog;

    private long project;
    private long inScope;
    private long alsoInScope;
    private long outOfScope;

    /** A key and its id, as the API keys route answers when it issues one. */
    private record Key(String id, String secret) {}

    @BeforeEach
    void estate() throws Exception {
        SolutionEntity solution = new SolutionEntity();
        solution.setName("solution-" + System.nanoTime());
        solution.setCreatedAt(Instant.now());
        ProjectEntity entity = new ProjectEntity();
        entity.setSolutionId(solutions.save(solution).getId());
        entity.setName("payments");
        entity.setCreatedAt(Instant.now());
        project = projects.save(entity).getId();
        inScope = repository(project);
        alsoInScope = repository(project);
        outOfScope = repository(null);
    }

    private long repository(Long projectId) throws Exception {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/r-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        long id = repositories.save(repository).getId();
        if (projectId != null) {
            mvc.perform(authenticated(put("/api/v1/projects/" + projectId + "/repositories/" + id), asAdmin()))
                    .andExpect(status().isNoContent());
        }
        return id;
    }

    private Key key(Map<String, Object> body) throws Exception {
        JsonNode answer = json.readTree(mvc.perform(authenticated(post("/api/v1/api-keys"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(body)))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        return new Key(answer.path("key").path("id").asText(), answer.path("secret").asText());
    }

    private Key importKey() throws Exception {
        return key(Map.of("name", "ci-" + System.nanoTime(), "scopes", List.of("sarif_import")));
    }

    private String governor() {
        return tokenFor("governor-" + System.nanoTime(), Role.SUPERUSER, false);
    }

    private ResultActions declare(String token, Map<String, Object> body) throws Exception {
        return mvc.perform(authenticated(post("/api/v1/sarif-sources"), token)
                .contentType(MediaType.APPLICATION_JSON).content(write(body)));
    }

    private Map<String, Object> source(String slug, Key key) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("slug", slug);
        body.put("name", "Team CI");
        body.put("api_key_id", key.id());
        body.put("project_id", project);
        body.put("tools", List.of("Semgrep OSS", "SonarQube"));
        return body;
    }

    private ResultActions upload(Key key, long repositoryId, String document) throws Exception {
        return upload(key.secret(), repositoryId, document.getBytes(StandardCharsets.UTF_8));
    }

    private ResultActions upload(String bearer, long repositoryId, byte[] document) throws Exception {
        return mvc.perform(post("/api/v1/repositories/" + repositoryId + "/sarif-imports")
                .header("Authorization", "Bearer " + bearer)
                .contentType("application/sarif+json")
                .content(document));
    }

    static String sarif(String tool, String version, String... rulesAndPaths) {
        StringBuilder results = new StringBuilder();
        for (int i = 0; i < rulesAndPaths.length; i += 2) {
            if (!results.isEmpty()) {
                results.append(',');
            }
            results.append("{\"ruleId\":\"").append(rulesAndPaths[i]).append("\",\"level\":\"error\",")
                    .append("\"message\":{\"text\":\"found\"},\"locations\":[{\"physicalLocation\":{\"artifactLocation\":")
                    .append("{\"uri\":\"").append(rulesAndPaths[i + 1]).append("\",\"uriBaseId\":\"%SRCROOT%\"},")
                    .append("\"region\":{\"startLine\":7}}}]}");
        }
        return "{\"version\":\"2.1.0\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"" + tool + "\",\"semanticVersion\":\""
                + version + "\"}},\"results\":[" + results + "]}]}";
    }

    private List<IssueEntity> openImported(long repositoryId) {
        return issues.findAll().stream()
                .filter(issue -> Long.valueOf(repositoryId).equals(issue.getRepoId()))
                .filter(issue -> FindingType.IMPORTED.wireName().equals(issue.getType()))
                .filter(issue -> IssueState.OPEN.wireName().equals(issue.getState()))
                .toList();
    }

    private List<String> operations() {
        return auditLog.findAll().stream().map(entry -> entry.getOperationType()).toList();
    }

    @Nested
    @DisplayName("declaring a source")
    class Declaring {

        @Test
        @DisplayName("is the governor's: an administrator may issue the key, not declare it inside the organisation")
        void governorOnly() throws Exception {
            Key key = importKey();

            declare(asAdmin(), source("team-ci", key)).andExpect(status().isForbidden());
            declare(governor(), source("team-ci", key))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.slug").value("team-ci"))
                    .andExpect(jsonPath("$.projectId").value(project))
                    .andExpect(jsonPath("$.tools[0]").value("semgrep oss"));

            assertThat(operations()).containsOnlyOnce(AuditOperation.SARIF_SOURCE_CHANGED.wireName());
            mvc.perform(authenticated(get("/api/v1/sarif-sources"), asAuditor()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[0].slug").value("team-ci"));
        }

        @Test
        @DisplayName("names its key to the governance readers who may not open the key list, and nothing more of it")
        void namesItsKey() throws Exception {
            String name = "team-ci-pipeline-" + System.nanoTime();
            Key key = key(Map.of("name", name, "scopes", List.of("sarif_import")));

            declare(governor(), source("team-ci", key))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.apiKeyName").value(name));
            // An auditor and a CISO may not list the keys; the source list is where they learn which
            // pipeline delivers — by the name the administrator gave it, never its prefix or scopes.
            mvc.perform(authenticated(get("/api/v1/api-keys"), asAuditor())).andExpect(status().isForbidden());
            for (String reader : List.of(asAuditor(), asCiso())) {
                mvc.perform(authenticated(get("/api/v1/sarif-sources"), reader))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$[0].apiKeyId").value(key.id()))
                        .andExpect(jsonPath("$[0].apiKeyName").value(name))
                        .andExpect(jsonPath("$[0].apiKeyPrefix").doesNotExist())
                        .andExpect(jsonPath("$[0].scopes").doesNotExist());
            }

            mvc.perform(authenticated(delete("/api/v1/api-keys/" + key.id()), asAdmin()))
                    .andExpect(status().is2xxSuccessful());
            mvc.perform(authenticated(get("/api/v1/sarif-sources"), asAuditor()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[0].apiKeyId").value(key.id()))
                    .andExpect(jsonPath("$[0].apiKeyName").value(Matchers.nullValue()));
        }

        @Test
        @DisplayName("binds a key that holds the scope, to exactly one scope that exists — never the estate")
        void whatADeclarationNeeds() throws Exception {
            String governor = governor();
            Key reader = key(Map.of("name", "reader-" + System.nanoTime(), "scopes", List.of("read")));
            declare(governor, source("reader", reader))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("sarif_import")));

            Map<String, Object> estate = source("estate", importKey());
            estate.remove("project_id");
            declare(governor, estate)
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("never the whole estate")));

            Map<String, Object> both = source("both", importKey());
            both.put("repository_id", inScope);
            declare(governor, both).andExpect(status().isBadRequest());

            Map<String, Object> nowhere = source("nowhere", importKey());
            nowhere.put("project_id", 999_999);
            declare(governor, nowhere).andExpect(status().isNotFound());

            Key shared = importKey();
            declare(governor, source("first", shared)).andExpect(status().isCreated());
            declare(governor, source("second", shared)).andExpect(status().isConflict());
            declare(governor, source("first", importKey())).andExpect(status().isConflict());
        }
    }

    @Nested
    @DisplayName("importing")
    class Importing {

        private Key key;

        @BeforeEach
        void declared() throws Exception {
            key = importKey();
            declare(governor(), source("team-ci", key)).andExpect(status().isCreated());
        }

        @Test
        @DisplayName("the tools of a report are a list, one per run, and a comma in a version does not split one")
        void toolsAreAList() throws Exception {
            String semgrep = sarif("Semgrep OSS", "1.90.0, build 7", "python.eval", "src/app.py");
            String sonar = sarif("SonarQube", "10.4", "java:S2076", "src/Main.java");
            String twoRuns = semgrep.substring(0, semgrep.lastIndexOf(']')) + ","
                    + sonar.substring(sonar.indexOf("\"runs\":[") + 8, sonar.lastIndexOf(']')) + "]}";

            upload(key, inScope, twoRuns)
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.tools", Matchers.contains("Semgrep OSS 1.90.0; build 7", "SonarQube 10.4")))
                    .andExpect(jsonPath("$.toolKeys", Matchers.contains("import:team-ci/semgrep oss",
                            "import:team-ci/sonarqube")));
            mvc.perform(authenticated(get("/api/v1/repositories/" + inScope + "/sarif-imports"), asAdmin()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[0].tools", Matchers.contains("Semgrep OSS 1.90.0; build 7", "SonarQube 10.4")))
                    .andExpect(jsonPath("$[0].toolKeys", Matchers.contains("import:team-ci/semgrep oss",
                            "import:team-ci/sonarqube")));
        }

        @Test
        @DisplayName("an import from before the tool keys were recorded reads null keys, never an empty list")
        void keysNotRecordedAreNull() throws Exception {
            SarifImportEntity before = new SarifImportEntity();
            before.setSourceId(1L);
            before.setSourceSlug("team-ci");
            before.setRepoId(inScope);
            before.setTools("Semgrep OSS 1.89.0");
            before.setDocumentSha256("a".repeat(64));
            before.setImportedAt(Instant.now());
            before.setImportedBy("pipeline");
            before.setApiKeyId(java.util.UUID.randomUUID());
            sarifImports.save(before);

            // An empty list would say the import accepted no tool; the row says nothing, and the view
            // must not say more than the row.
            mvc.perform(authenticated(get("/api/v1/repositories/" + inScope + "/sarif-imports"), asAdmin()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[0].tools", Matchers.contains("Semgrep OSS 1.89.0")))
                    .andExpect(jsonPath("$[0].toolKeys").value(Matchers.nullValue()));
        }

        @Test
        @DisplayName("a declared source's report opens imported issues that say where they came from")
        void provenance() throws Exception {
            upload(key, inScope, sarif("Semgrep OSS", "1.90.0", "python.eval", "src/app.py", "python.exec", "./src/run.py"))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.sourceSlug").value("team-ci"))
                    .andExpect(jsonPath("$.repoId").value(inScope))
                    .andExpect(jsonPath("$.resultsCount").value(2))
                    .andExpect(jsonPath("$.createdCount").value(2))
                    .andExpect(jsonPath("$.tools", Matchers.contains("Semgrep OSS 1.90.0")))
                    // The tool keys the import accepted, what a checklist reads to know the tool produced.
                    .andExpect(jsonPath("$.toolKeys", Matchers.contains("import:team-ci/semgrep oss")))
                    .andExpect(jsonPath("$.documentSha256").value(Matchers.matchesPattern("[0-9a-f]{64}")));

            assertThat(openImported(inScope)).hasSize(2).allSatisfy(issue -> {
                assertThat(issue.getTool()).isEqualTo("import:team-ci/semgrep oss");
                assertThat(issue.getImportSource()).isEqualTo("team-ci");
                assertThat(issue.getToolName()).isEqualTo("Semgrep OSS");
                assertThat(issue.getToolVersion()).isEqualTo("1.90.0");
                assertThat(issue.getFirstSeenScanId()).as("no scan: the import record is its evidence").isNull();
            });
            assertThat(openImported(inScope)).extracting(IssueEntity::getFilePath)
                    .containsExactlyInAnyOrder("src/app.py", "src/run.py");
            assertThat(operations()).contains(AuditOperation.SARIF_IMPORTED.wireName());

            mvc.perform(authenticated(get("/api/v1/repositories/" + inScope + "/sarif-imports"), asAdmin()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[0].sourceSlug").value("team-ci"));
            mvc.perform(authenticated(get("/api/v1/repositories/999999/sarif-imports"), asAdmin()))
                    .andExpect(status().isNotFound());
        }

        @Test
        @DisplayName("a later report resolves what its tool no longer reports — that tool's issues only")
        void resolvesItsOwnToolOnly() throws Exception {
            upload(key, inScope, sarif("Semgrep OSS", "1.90.0", "python.eval", "src/app.py", "python.exec", "src/run.py"))
                    .andExpect(status().isCreated());
            upload(key, inScope, sarif("SonarQube", "10.6", "S2076", "src/app.py")).andExpect(status().isCreated());

            // Semgrep again, a version later, one finding fixed: the other keeps its identity.
            upload(key, inScope, sarif("semgrep oss", "1.91.0", "python.eval", "src/app.py"))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.resolvedCount").value(1))
                    .andExpect(jsonPath("$.createdCount").value(0));

            assertThat(openImported(inScope)).extracting(IssueEntity::getIdentifier)
                    .containsExactlyInAnyOrder("python.eval", "S2076");
            assertThat(openImported(inScope)).filteredOn(issue -> issue.getIdentifier().equals("python.eval"))
                    .singleElement()
                    .satisfies(issue -> {
                        assertThat(issue.getTimesSeen()).isEqualTo(2);
                        assertThat(issue.getToolVersion()).isEqualTo("1.91.0");
                    });
        }

        @Test
        @DisplayName("a key no source is declared for is refused, and the refusal reaches the SIEM's ledger")
        void undeclaredKey() throws Exception {
            Key stranger = importKey();

            upload(stranger, inScope, sarif("Semgrep OSS", "1", "r", "a.py"))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("not declared")));
            assertThat(operations()).contains(AuditOperation.SARIF_IMPORT_REFUSED.wireName());
            assertThat(openImported(inScope)).isEmpty();
        }

        @Test
        @DisplayName("a session is not a source, and a key without the scope never reaches the route")
        void sessionsAndOtherKeys() throws Exception {
            upload(asAdmin(), inScope, sarif("Semgrep OSS", "1", "r", "a.py").getBytes(StandardCharsets.UTF_8))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("session")));
            Key reader = key(Map.of("name", "reader-" + System.nanoTime(), "scopes", List.of("read")));
            upload(reader, inScope, sarif("Semgrep OSS", "1", "r", "a.py")).andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("a repository outside the source's scope answers as absent")
        void outsideTheScope() throws Exception {
            upload(key, outOfScope, sarif("Semgrep OSS", "1", "r", "a.py")).andExpect(status().isNotFound());
            upload(key, 999_999, sarif("Semgrep OSS", "1", "r", "a.py")).andExpect(status().isNotFound());

            assertThat(openImported(outOfScope)).isEmpty();
            assertThat(operations()).contains(AuditOperation.SARIF_IMPORT_REFUSED.wireName());
        }

        @Test
        @DisplayName("a key restricted to one repository imports into that one, even where its source reaches further")
        void aRestrictedKey() throws Exception {
            Key restricted = key(Map.of("name", "one-repo-" + System.nanoTime(), "scopes", List.of("sarif_import"),
                    "target_kind", "repository", "target_id", inScope));
            declare(governor(), source("one-repo", restricted)).andExpect(status().isCreated());

            upload(restricted, alsoInScope, sarif("Semgrep OSS", "1", "r", "a.py")).andExpect(status().isNotFound());
            upload(restricted, inScope, sarif("Semgrep OSS", "1", "r", "a.py")).andExpect(status().isCreated());
        }

        @Test
        @DisplayName("a tool the source is not declared for is refused, whatever the report contains")
        void undeclaredTool() throws Exception {
            upload(key, inScope, sarif("SonarCloud", "1", "S1", "a.py"))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("SonarCloud")));
            assertThat(openImported(inScope)).isEmpty();
        }

        @Test
        @DisplayName("a report with a link, an absolute path, a failed run or no results is refused, and writes nothing")
        void refusedDocuments() throws Exception {
            upload(key, inScope, sarif("Semgrep OSS", "1", "r", "https://evil.example/a.py"))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("outside the analysed tree")));
            upload(key, inScope, sarif("Semgrep OSS", "1", "r", "/builds/team/app/a.py"))
                    .andExpect(status().isBadRequest());
            upload(key, inScope, "{\"version\":\"2.1.0\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"Semgrep OSS\"}},"
                            + "\"invocations\":[{\"executionSuccessful\":false}],\"results\":[]}]}")
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("did not execute")));
            upload(key, inScope, "{\"version\":\"2.1.0\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"Semgrep OSS\"}}}]}")
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("no results")));
            upload(key, inScope, "{\"version\":\"2.1.0\",\"runs\":[]}").andExpect(status().isBadRequest());
            upload(key, inScope, "not json").andExpect(status().isBadRequest());

            assertThat(openImported(inScope)).isEmpty();
        }

        @Test
        @DisplayName("a report past the ceiling is refused before a byte of it is parsed")
        void oversized() throws Exception {
            byte[] huge = new byte[32 * 1024 * 1024 + 1];
            Arrays.fill(huge, (byte) ' ');

            // Refused by the route's filter on the declared length — its words, not the service's, which
            // holds the same limit once the bytes are read.
            upload(key.secret(), inScope, huge)
                    .andExpect(status().isContentTooLarge())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("this route accepts")));
        }

        @Test
        @DisplayName("a disabled or removed source's key imports nothing")
        void disabledAndRemoved() throws Exception {
            String governor = governor();
            long id = json.readTree(mvc.perform(authenticated(get("/api/v1/sarif-sources"), governor))
                    .andReturn().getResponse().getContentAsString()).path(0).path("id").asLong();

            mvc.perform(authenticated(put("/api/v1/sarif-sources/" + id + "/enabled"), governor)
                            .contentType(MediaType.APPLICATION_JSON).content("{\"enabled\":false}"))
                    .andExpect(status().isOk());
            upload(key, inScope, sarif("Semgrep OSS", "1", "r", "a.py")).andExpect(status().isForbidden());

            mvc.perform(authenticated(delete("/api/v1/sarif-sources/" + id), governor)).andExpect(status().isNoContent());
            upload(key, inScope, sarif("Semgrep OSS", "1", "r", "a.py")).andExpect(status().isForbidden());
        }
    }
}
