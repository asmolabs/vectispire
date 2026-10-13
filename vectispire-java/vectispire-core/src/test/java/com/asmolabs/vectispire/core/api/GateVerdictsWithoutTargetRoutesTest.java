package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.compliance.internal.ProcessEvidenceService;
import com.asmolabs.vectispire.core.gate.persistence.GateVerdictEntity;
import com.asmolabs.vectispire.core.gate.persistence.GateVerdictRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * A gate verdict that names neither a repository nor a container.
 *
 * <p><b>The application records none</b>, and the first two tests pin why: the gate's one writer is
 * {@code POST /gate}, which refuses a request naming no target or both with a 400 before anything is
 * evaluated, and hands the service a {@code ScanTarget} whose identifier is a primitive; deleting a target
 * deletes its verdicts by cascade. No import, agent or CLI path writes the register — the CLI and the CI
 * templates call this same route.
 *
 * <p><b>But the schema allows one</b> — both columns are nullable and no check requires one — so a row
 * written by hand or restored from elsewhere can hold neither. Read as "a repository, else a container",
 * it unboxed a null container id: the register answered 500 to every reader of the whole estate, and
 * section 09 of the evidence bundle failed with it — the defect the exceptions register had (7e7a3fd4).
 * Such a row is now listed with no target to a whole-estate reader and to nobody else.
 */
@DisplayName("a gate verdict that names no target")
class GateVerdictsWithoutTargetRoutesTest extends ApiTestBase {

    @Autowired
    private GateVerdictRepository verdicts;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private SettingsService settings;

    @Autowired
    private ProcessEvidenceService evidence;

    @Test
    @DisplayName("is never recorded by the gate: a request naming no target, or both, is refused and leaves no row")
    void theGateRecordsNone() throws Exception {
        long repository = repository("asked");
        long before = verdicts.count();

        mvc.perform(authenticated(post("/api/v1/gate"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of())))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.detail").value("Give exactly one of \"repository_id\" or \"container_id\"."));
        Map<String, Object> neither = new HashMap<>();
        neither.put("repository_id", null);
        neither.put("container_id", null);
        mvc.perform(authenticated(post("/api/v1/gate"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(neither)))
                .andExpect(status().isBadRequest());
        mvc.perform(authenticated(post("/api/v1/gate"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("repository_id", repository, "container_id", repository))))
                .andExpect(status().isBadRequest());

        assertThat(verdicts.count()).as("no refused question joined the register").isEqualTo(before);
    }

    @Test
    @DisplayName("every verdict the gate records names exactly one target")
    void everyRecordedVerdictNamesOneTarget() throws Exception {
        long repository = repository("recorded");

        mvc.perform(authenticated(post("/api/v1/gate"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("repository_id", repository))))
                .andExpect(status().isOk());

        assertThat(verdicts.findByRepoIdOrderByDecidedAtDesc(repository, org.springframework.data.domain.Limit.of(5)))
                .singleElement()
                .satisfies(row -> {
                    assertThat(row.getRepoId()).isEqualTo(repository);
                    assertThat(row.getContainerId()).isNull();
                });
    }

    @Test
    @DisplayName("is listed with no target to a reader of the whole estate, and the register answers")
    void listedWithNoTarget() throws Exception {
        UUID orphan = verdict(null, Instant.now().plusSeconds(3_600));

        JsonNode row = rowOf(mvc.perform(authenticated(get("/api/v1/gate/verdicts"), asAdmin()))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(), orphan);

        assertThat(row).as("the row is listed").isNotNull();
        assertThat(row.path("target_kind").isNull()).as("not a container with no id").isTrue();
        assertThat(row.path("target_id").isNull()).isTrue();
        assertThat(row.path("passed").asBoolean()).isFalse();
    }

    @Test
    @DisplayName("does not take section 09 of the evidence bundle down with it")
    void theEvidenceStillAnswers() {
        UUID orphan = verdict(null, Instant.now().plusSeconds(3_600));

        ProcessEvidenceService.GateEvidence gate = evidence.gate(Visibility.everything());

        assertThat(gate.refusals())
                .filteredOn(refusal -> refusal.id().equals(orphan.toString()))
                .singleElement()
                .satisfies(refusal -> {
                    assertThat(refusal.targetKind()).isNull();
                    assertThat(refusal.targetId()).isNull();
                });
    }

    @Test
    @DisplayName("is shown to no restricted reader")
    void hiddenFromARestrictedReader() throws Exception {
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        try {
            long mine = repository("mine");
            String reader = assignedReader(mine);
            UUID own = verdict(mine, Instant.now().minusSeconds(60));
            verdict(null, Instant.now().plusSeconds(3_600));

            mvc.perform(authenticated(get("/api/v1/gate/verdicts"), reader))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.verdicts.length()").value(1))
                    .andExpect(jsonPath("$.verdicts[0].id").value(own.toString()));
        } finally {
            settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.EVERYONE.wireName());
        }
    }

    /** The register's row {@code id}, or null when it is not listed. */
    private JsonNode rowOf(String register, UUID id) throws Exception {
        for (JsonNode row : json.readTree(register).path("verdicts")) {
            if (row.path("id").asText().equals(id.toString())) {
                return row;
            }
        }
        return null;
    }

    /** A refusal on {@code repoId} or — null — on no target at all, written as a restore would write it. */
    private UUID verdict(Long repoId, Instant at) {
        GateVerdictEntity row = new GateVerdictEntity();
        row.setId(UUID.randomUUID());
        row.setRepoId(repoId);
        row.setPassed(false);
        row.setEvaluated(3);
        row.setViolations(1);
        row.setCriticalCount(1);
        row.setPolicySource("GLOBAL");
        row.setDecidedAt(at);
        row.setDecidedBy("restored");
        return verdicts.save(row).getId();
    }

    private long repository(String name) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/" + name + "-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    /** A reader with one repository assigned, through the administration route it really uses. */
    private String assignedReader(long repositoryId) throws Exception {
        String reader = asReader();
        long readerId = -1;
        for (JsonNode user : json.readTree(mvc.perform(authenticated(get("/api/v1/users"), asAdmin()))
                        .andReturn().getResponse().getContentAsString())
                .path("users")) {
            if (user.path("username").asText("").startsWith("reader-")) {
                readerId = user.path("id").asLong();
            }
        }
        mvc.perform(authenticated(put("/api/v1/users/" + readerId + "/targets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(List.of(Map.of("kind", "repository", "id", repositoryId)))))
                .andExpect(status().isOk());
        return reader;
    }
}
