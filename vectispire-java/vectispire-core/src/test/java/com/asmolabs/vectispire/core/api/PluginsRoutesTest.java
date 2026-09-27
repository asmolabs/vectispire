package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.ProjectEntity;
import com.asmolabs.vectispire.core.targets.persistence.ProjectRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.targets.persistence.SolutionEntity;
import com.asmolabs.vectispire.core.targets.persistence.SolutionRepository;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

/**
 * The plugin registry and its activations, through the real routes and filter chain: who may register
 * code (the governor alone), who may switch it on for a project, and what a scan's task then carries.
 */
@DisplayName("plugins, through the routes")
class PluginsRoutesTest extends ApiTestBase {

    static final String DIGEST = "sha256:" + "a".repeat(64);
    static final String OTHER_DIGEST = "sha256:" + "b".repeat(64);

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private SolutionRepository solutions;

    @Autowired
    private ProjectRepository projects;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private AuditLogRepository auditLog;

    @Autowired
    private org.springframework.jdbc.core.JdbcTemplate jdbc;

    static Map<String, Object> manifest(String id, String digest) {
        Map<String, Object> manifest = new LinkedHashMap<>();
        manifest.put("id", id);
        manifest.put("name", "ACME house rules");
        manifest.put("image", "registry.acme.internal/sec/" + id + "@" + digest);
        manifest.put("languages", List.of("java", "kotlin"));
        manifest.put("arguments", List.of("--sarif", "{output}", "{source}"));
        manifest.put("output", "results.sarif");
        manifest.put("exit_codes", List.of(0, 1));
        manifest.put("network", false);
        manifest.put("timeout_seconds", 600);
        return manifest;
    }

    private String governor() {
        return tokenFor("governor-" + System.nanoTime(), Role.SUPERUSER, false);
    }

    private ResultActions register(String token, Map<String, Object> manifest) throws Exception {
        return mvc.perform(authenticated(post("/api/v1/plugins"), token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(write(manifest)));
    }

    private long project() {
        SolutionEntity solution = new SolutionEntity();
        solution.setName("solution-" + System.nanoTime());
        solution.setCreatedAt(Instant.now());
        ProjectEntity project = new ProjectEntity();
        project.setSolutionId(solutions.save(solution).getId());
        project.setName("project-" + System.nanoTime());
        project.setCreatedAt(Instant.now());
        return projects.save(project).getId();
    }

    /** A repository, filed through the route that files one — the column is not Hibernate's to write. */
    private long repositoryIn(Long projectId) throws Exception {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/app-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        long id = repositories.save(repository).getId();
        if (projectId != null) {
            mvc.perform(authenticated(put("/api/v1/projects/" + projectId + "/repositories/" + id), asAdmin()))
                    .andExpect(status().isNoContent());
        }
        return id;
    }

    private List<String> operations() {
        return auditLog.findAll().stream().map(entry -> entry.getOperationType()).toList();
    }

    @Nested
    @DisplayName("registering")
    class Registering {

        @Test
        @DisplayName("is the platform governor's alone: an administrator, a CISO and a reader are refused")
        void governorOnly() throws Exception {
            register(asAdmin(), manifest("acme-lint", DIGEST)).andExpect(status().isForbidden());
            register(asCiso(), manifest("acme-lint", DIGEST)).andExpect(status().isForbidden());
            register(asReader(), manifest("acme-lint", DIGEST)).andExpect(status().isForbidden());

            register(governor(), manifest("acme-lint", DIGEST))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.id").value("acme-lint"))
                    .andExpect(jsonPath("$.enabled").value(true))
                    .andExpect(jsonPath("$.manifest.image").value("registry.acme.internal/sec/acme-lint@" + DIGEST))
                    .andExpect(jsonPath("$.manifest.languages[0]").value("java"))
                    .andExpect(jsonPath("$.manifest.exit_codes[1]").value(1))
                    .andExpect(jsonPath("$.manifestDigest").value(Matchers.matchesPattern("[0-9a-f]{64}")));

            assertThat(operations()).containsOnlyOnce(AuditOperation.PLUGIN_REGISTERED.wireName());
        }

        @Test
        @DisplayName("refuses an image pinned by a tag, and a network without a justification")
        void refusesAMovingImage() throws Exception {
            Map<String, Object> tagged = manifest("acme-lint", DIGEST);
            tagged.put("image", "registry.acme.internal/sec/acme-lint:latest");
            register(governor(), tagged)
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("digest")));

            Map<String, Object> networked = manifest("acme-lint", DIGEST);
            networked.put("network", true);
            register(governor(), networked)
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("says why")));

            Map<String, Object> unknownLanguage = manifest("acme-lint", DIGEST);
            unknownLanguage.put("languages", List.of("cobol"));
            // The refusal is thrown inside Jackson, which wraps it; the sentence still has to arrive.
            register(governor(), unknownLanguage)
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.detail").value(Matchers.startsWith("Unknown language \"cobol\"")));
        }

        @Test
        @DisplayName("never reuses an id: a second registration under it is a conflict")
        void idsAreNotReused() throws Exception {
            String governor = governor();
            register(governor, manifest("acme-lint", DIGEST)).andExpect(status().isCreated());

            register(governor, manifest("acme-lint", OTHER_DIGEST)).andExpect(status().isConflict());
        }

        @Test
        @DisplayName("an update keeps the id and moves the digest; the same manifest again records nothing")
        void update() throws Exception {
            String governor = governor();
            String first = json.readTree(register(governor, manifest("acme-lint", DIGEST))
                    .andReturn().getResponse().getContentAsString()).get("manifestDigest").asText();

            mvc.perform(authenticated(put("/api/v1/plugins/acme-lint"), asAdmin())
                            .contentType(MediaType.APPLICATION_JSON).content(write(manifest("acme-lint", OTHER_DIGEST))))
                    .andExpect(status().isForbidden());
            String second = json.readTree(mvc.perform(authenticated(put("/api/v1/plugins/acme-lint"), governor)
                            .contentType(MediaType.APPLICATION_JSON).content(write(manifest("acme-lint", OTHER_DIGEST))))
                    .andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString()).get("manifestDigest").asText();
            mvc.perform(authenticated(put("/api/v1/plugins/acme-lint"), governor)
                            .contentType(MediaType.APPLICATION_JSON).content(write(manifest("acme-lint", OTHER_DIGEST))))
                    .andExpect(status().isOk());

            assertThat(second).isNotEqualTo(first);
            assertThat(operations()).containsOnlyOnce(AuditOperation.PLUGIN_UPDATED.wireName());

            mvc.perform(authenticated(put("/api/v1/plugins/acme-lint"), governor)
                            .contentType(MediaType.APPLICATION_JSON).content(write(manifest("renamed", OTHER_DIGEST))))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("never changed")));
        }

        @Test
        @DisplayName("any signed-in account reads the registry; disabling is the governor's")
        void readAndDisable() throws Exception {
            String governor = governor();
            register(governor, manifest("acme-lint", DIGEST)).andExpect(status().isCreated());

            mvc.perform(authenticated(get("/api/v1/plugins"), asReader()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[0].id").value("acme-lint"));
            mvc.perform(get("/api/v1/plugins")).andExpect(status().isUnauthorized());

            mvc.perform(authenticated(put("/api/v1/plugins/acme-lint/enabled"), asAdmin())
                            .contentType(MediaType.APPLICATION_JSON).content("{\"enabled\":false}"))
                    .andExpect(status().isForbidden());
            mvc.perform(authenticated(put("/api/v1/plugins/acme-lint/enabled"), governor)
                            .contentType(MediaType.APPLICATION_JSON).content("{\"enabled\":false}"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.enabled").value(false));
            assertThat(operations()).containsOnlyOnce(AuditOperation.PLUGIN_ENABLED_CHANGED.wireName());

            mvc.perform(authenticated(get("/api/v1/plugins/absent"), asReader())).andExpect(status().isNotFound());
        }
    }

    @Nested
    @DisplayName("activating per project")
    class Activating {

        @Test
        @DisplayName("is governance work: an administrator or a CISO switches it on, a reader or a champion may not")
        void whoActivates() throws Exception {
            register(governor(), manifest("acme-lint", DIGEST)).andExpect(status().isCreated());
            long project = project();

            mvc.perform(authenticated(put("/api/v1/projects/" + project + "/plugins/acme-lint"), asReader()))
                    .andExpect(status().isForbidden());
            mvc.perform(authenticated(put("/api/v1/projects/" + project + "/plugins/acme-lint"), asSecurityChampion()))
                    .andExpect(status().isForbidden());
            mvc.perform(authenticated(put("/api/v1/projects/" + project + "/plugins/acme-lint"), asCiso()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.pluginId").value("acme-lint"))
                    .andExpect(jsonPath("$.projectId").value(project));
            mvc.perform(authenticated(put("/api/v1/projects/" + project + "/plugins/acme-lint"), asAdmin()))
                    .andExpect(status().isOk());

            assertThat(operations()).containsOnlyOnce(AuditOperation.PLUGIN_ACTIVATED.wireName());
            mvc.perform(authenticated(get("/api/v1/projects/" + project + "/plugins"), asAuditor()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[0].pluginId").value("acme-lint"));
            mvc.perform(authenticated(get("/api/v1/plugins/acme-lint/projects"), asAuditor()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[0].projectId").value(project));
            mvc.perform(authenticated(get("/api/v1/projects/" + project + "/plugins"), asReader()))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("an unknown project or plugin is absent, and switching off what is not on is too")
        void absent() throws Exception {
            register(governor(), manifest("acme-lint", DIGEST)).andExpect(status().isCreated());
            long project = project();

            mvc.perform(authenticated(put("/api/v1/projects/999999/plugins/acme-lint"), asAdmin()))
                    .andExpect(status().isNotFound());
            mvc.perform(authenticated(put("/api/v1/projects/" + project + "/plugins/absent"), asAdmin()))
                    .andExpect(status().isNotFound());
            mvc.perform(authenticated(delete("/api/v1/projects/" + project + "/plugins/acme-lint"), asAdmin()))
                    .andExpect(status().isNotFound());
        }

        @Test
        @DisplayName("deleting the project takes its activations with it")
        void projectDeletion() throws Exception {
            register(governor(), manifest("acme-lint", DIGEST)).andExpect(status().isCreated());
            long project = project();
            mvc.perform(authenticated(put("/api/v1/projects/" + project + "/plugins/acme-lint"), asAdmin()))
                    .andExpect(status().isOk());

            mvc.perform(authenticated(delete("/api/v1/projects/" + project), asAdmin())).andExpect(status().isNoContent());

            mvc.perform(authenticated(get("/api/v1/plugins/acme-lint/projects"), asAdmin()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$").isEmpty());
        }
    }

    @Nested
    @DisplayName("what a scan runs")
    class Scans {

        private record Enrolled(String token) {}

        private Enrolled agent() throws Exception {
            JsonNode answer = json.readTree(mvc.perform(authenticated(post("/api/v1/admin/agents"), asAdmin())
                            .contentType(MediaType.APPLICATION_JSON)
                            // Room for more than one scan: the second claim must not stop at the limit.
                            .content("{\"name\": \"agent-" + System.nanoTime() + "\", \"max_concurrent\": 4}"))
                    .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
            return new Enrolled(answer.get("secret").asText());
        }

        private JsonNode claim(Enrolled agent) throws Exception {
            MvcResult started = mvc.perform(get("/api/v1/agent/jobs?wait=0").header("Authorization", "Bearer " + agent.token()))
                    .andReturn();
            return json.readTree(mvc.perform(asyncDispatch(started)).andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString());
        }

        private void queue(long repositoryId) {
            ScanEntity scan = new ScanEntity();
            scan.setRepoId(repositoryId);
            scan.setBranch("main");
            scan.setStatus(ScanStatus.PENDING.wireName());
            scan.setCreatedAt(Instant.now());
            scan.setFindingsCount(0);
            scan.setNewIssuesCount(0);
            scan.setResolvedIssuesCount(0);
            scan.setAttempts(0);
            scans.save(scan);
        }

        @Test
        @DisplayName("a declared signer is stored, audited, and reaches the agent as it was declared, digest and all")
        void theSignerReachesTheAgent() throws Exception {
            String key = "-----BEGIN PUBLIC KEY-----\n"
                    + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhm3H+258usrgldBUFUFN9WFtNT21\n"
                    + "IV1MQgw1S41uz9HTMzDeHNZ9+PsTOW6xznu1CIrVOSLBcsTdCfoM911hVg==\n"
                    + "-----END PUBLIC KEY-----\n";
            Map<String, Object> halfKeyless = manifest("acme-lint", DIGEST);
            halfKeyless.put("signature", Map.of("identity", "https://github.com/acme/lint/.github/workflows/release.yml@refs/tags/v1"));
            register(governor(), halfKeyless)
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("issuer")));

            Map<String, Object> signed = manifest("acme-lint", DIGEST);
            signed.put("signature", Map.of("public_key", key));
            String digest = json.readTree(register(governor(), signed)
                            .andExpect(status().isCreated())
                            .andExpect(jsonPath("$.manifest.signature.public_key").value(key))
                            .andReturn().getResponse().getContentAsString())
                    .get("manifestDigest").asText();

            String served = mvc.perform(get("/api/v1/agent/plugins/acme-lint/" + digest)
                            .header("Authorization", "Bearer " + agent().token()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.signature.public_key").value(key))
                    .andReturn().getResponse().getContentAsString();
            // What the agent reads is what it checks against the task's digest: read back from the wire, it
            // must hash to the digest the task names, or every signed plugin would be absent on an agent.
            assertThat(json.readValue(served, com.asmolabs.vectispire.common.domain.plugins.PluginManifest.class).digest())
                    .isEqualTo(digest);
            assertThat(auditLog.findAll()).filteredOn(entry -> entry.getOperationType()
                            .equals(AuditOperation.PLUGIN_REGISTERED.wireName()))
                    .singleElement()
                    .satisfies(entry -> assertThat(entry.getDescription()).contains("signed by key sha256:"));
        }

        @Test
        @DisplayName("a repository in a project runs the enabled plugins switched on for it, by id and digest")
        void theTaskCarriesTheProjectsPlugins() throws Exception {
            String governor = governor();
            String digest = json.readTree(register(governor, manifest("acme-lint", DIGEST))
                    .andReturn().getResponse().getContentAsString()).get("manifestDigest").asText();
            register(governor, manifest("dormant", DIGEST)).andExpect(status().isCreated());
            long project = project();
            mvc.perform(authenticated(put("/api/v1/projects/" + project + "/plugins/acme-lint"), asAdmin()))
                    .andExpect(status().isOk());
            queue(repositoryIn(project));
            Enrolled agent = agent();

            JsonNode task = claim(agent).path("task");

            assertThat(task.path("plugins")).hasSize(1);
            assertThat(task.path("plugins").path(0).path("id").asText()).isEqualTo("acme-lint");
            assertThat(task.path("plugins").path(0).path("digest").asText()).isEqualTo(digest);

            // The agent fetches exactly that manifest, by both halves of the reference.
            mvc.perform(get("/api/v1/agent/plugins/acme-lint/" + digest).header("Authorization", "Bearer " + agent.token()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").value("acme-lint"))
                    .andExpect(jsonPath("$.image").value("registry.acme.internal/sec/acme-lint@" + DIGEST));
            mvc.perform(get("/api/v1/agent/plugins/dormant/" + digest).header("Authorization", "Bearer " + agent.token()))
                    .andExpect(status().isNotFound());
            // Not a session's route, whatever its role.
            mvc.perform(authenticated(get("/api/v1/agent/plugins/acme-lint/" + digest), governor))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("an agent's result records each plugin's state on the scan, the not-applicable one included")
        void theScanKeepsEachPluginsOutcome() throws Exception {
            String governor = governor();
            String digest = json.readTree(register(governor, manifest("acme-lint", DIGEST))
                    .andReturn().getResponse().getContentAsString()).get("manifestDigest").asText();
            long project = project();
            mvc.perform(authenticated(put("/api/v1/projects/" + project + "/plugins/acme-lint"), asAdmin()))
                    .andExpect(status().isOk());
            queue(repositoryIn(project));
            Enrolled agent = agent();
            long scanId = claim(agent).path("scanId").asLong();

            String result = """
                    {"plugins":[
                      {"state":"produced","pluginId":"acme-lint","manifestDigest":"%s","toolName":"acme","toolVersion":"4.2",
                       "findings":[{"ruleId":"ACME001","severity":"HIGH","file":"src/App.java","line":3,"message":"m"}]},
                      {"state":"not_applicable","pluginId":"py-only","manifestDigest":"%s","languages":["python"]},
                      {"state":"absent","pluginId":"broken","manifestDigest":"%s","reason":"exited with 2"}],
                     "failures":[{"step":"plugin broken","reason":"exited with 2"}],"duration":"PT3S"}
                    """.formatted(digest, digest, digest);
            mvc.perform(post("/api/v1/agent/jobs/" + scanId + "/result")
                            .header("Authorization", "Bearer " + agent.token())
                            .contentType(MediaType.APPLICATION_JSON).content(result))
                    .andExpect(status().isOk());

            mvc.perform(authenticated(get("/api/v1/scans/" + scanId), asAdmin()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.scan.status").value("completed"))
                    .andExpect(jsonPath("$.plugins[0].pluginId").value("acme-lint"))
                    .andExpect(jsonPath("$.plugins[0].state").value("produced"))
                    .andExpect(jsonPath("$.plugins[0].findings").value(1))
                    .andExpect(jsonPath("$.plugins[1].state").value("not_applicable"))
                    .andExpect(jsonPath("$.plugins[1].languages[0]").value("python"))
                    .andExpect(jsonPath("$.plugins[2].state").value("absent"))
                    .andExpect(jsonPath("$.plugins[2].reason").value("exited with 2"))
                    .andExpect(jsonPath("$.findings[0].tool").value("plugin:acme-lint"))
                    .andExpect(jsonPath("$.findings[0].type").value("plugin"));
        }

        @Test
        @DisplayName("a stored manifest that no longer hashes to its digest is served to nobody")
        void aTamperedManifestIsNotServed() throws Exception {
            String digest = json.readTree(register(governor(), manifest("acme-lint", DIGEST))
                    .andReturn().getResponse().getContentAsString()).get("manifestDigest").asText();
            Enrolled agent = agent();
            mvc.perform(get("/api/v1/agent/plugins/acme-lint/" + digest).header("Authorization", "Bearer " + agent.token()))
                    .andExpect(status().isOk());

            // Somebody with the database edits the arguments in place, under the same key.
            jdbc.update("update t_plugin_manifest set manifest = replace(manifest, '--sarif', '--everything') where digest = ?",
                    digest);

            mvc.perform(get("/api/v1/agent/plugins/acme-lint/" + digest).header("Authorization", "Bearer " + agent.token()))
                    .andExpect(status().isNotFound());
        }

        @Test
        @DisplayName("a repository in no project, or a disabled plugin, runs nothing")
        void nothingGlobal() throws Exception {
            String governor = governor();
            register(governor, manifest("acme-lint", DIGEST)).andExpect(status().isCreated());
            long project = project();
            mvc.perform(authenticated(put("/api/v1/projects/" + project + "/plugins/acme-lint"), asAdmin()))
                    .andExpect(status().isOk());
            queue(repositoryIn(null));
            Enrolled agent = agent();
            JsonNode unfiled = claim(agent);
            assertThat(unfiled.path("task").path("target").path("kind").asText()).isEqualTo("repository");
            assertThat(unfiled.path("task").path("plugins")).isEmpty();

            mvc.perform(authenticated(put("/api/v1/plugins/acme-lint/enabled"), governor)
                            .contentType(MediaType.APPLICATION_JSON).content("{\"enabled\":false}"))
                    .andExpect(status().isOk());
            queue(repositoryIn(project));
            assertThat(claim(agent).path("task").path("plugins")).isEmpty();
        }
    }
}
