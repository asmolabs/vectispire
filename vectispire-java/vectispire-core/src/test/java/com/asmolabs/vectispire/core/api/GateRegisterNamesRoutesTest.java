package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.gate.persistence.GateVerdictEntity;
import com.asmolabs.vectispire.core.gate.persistence.GateVerdictRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * The verdict register names its targets.
 *
 * <p>It showed "Repository 5": an identifier an assessor reading the register can do nothing with. The
 * name comes from the server, as every other screen's does, and only for a target the reader may see —
 * a restricted reader is shown no row of anybody else's target, and so no name either.
 */
@DisplayName("the verdict register's target names")
class GateRegisterNamesRoutesTest extends ApiTestBase {

    @Autowired
    private GateVerdictRepository verdicts;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ContainerRepository containers;

    @Autowired
    private SettingsService settings;

    @Test
    @DisplayName("a repository and an image are listed under their names")
    void named() throws Exception {
        String repositoryName = "Payments API " + System.nanoTime();
        long repository = repository(repositoryName);
        String image = "team/ledger-" + System.nanoTime();
        long container = container(image);
        UUID onRepository = verdict(repository, null);
        UUID onImage = verdict(null, container);

        String register = mvc.perform(authenticated(get("/api/v1/gate/verdicts"), asAdmin()))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        assertThat(rowOf(register, onRepository).path("target_name").asText()).isEqualTo(repositoryName);
        assertThat(rowOf(register, onImage).path("target_name").asText()).contains(image);
    }

    @Test
    @DisplayName("a restricted reader is told the name of its own target and of no other")
    void withheldFromARestrictedReader() throws Exception {
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        try {
            String mineName = "mine-" + System.nanoTime();
            String theirsName = "theirs-" + System.nanoTime();
            long mine = repository(mineName);
            long theirs = repository(theirsName);
            String reader = assignedReader(mine);
            UUID own = verdict(mine, null);
            UUID hidden = verdict(theirs, null);

            String seen = mvc.perform(authenticated(get("/api/v1/gate/verdicts"), reader))
                    .andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString();

            assertThat(rowOf(seen, own).path("target_name").asText()).isEqualTo(mineName);
            assertThat(rowOf(seen, hidden)).as("their verdict is not listed").isNull();
            assertThat(seen).as("nor is their target's name, anywhere").doesNotContain(theirsName);

            // The administrator, who sees the whole estate, is told both.
            String whole = mvc.perform(authenticated(get("/api/v1/gate/verdicts"), asAdmin()))
                    .andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString();
            assertThat(rowOf(whole, hidden).path("target_name").asText()).isEqualTo(theirsName);
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

    private UUID verdict(Long repoId, Long containerId) {
        GateVerdictEntity row = new GateVerdictEntity();
        row.setId(UUID.randomUUID());
        row.setRepoId(repoId);
        row.setContainerId(containerId);
        row.setPassed(true);
        row.setEvaluated(5);
        row.setPolicySource("GLOBAL");
        // Newer than anything another test of this JVM wrote, so the first page holds it.
        row.setDecidedAt(Instant.now().plusSeconds(7_200));
        row.setDecidedBy("ci");
        return verdicts.save(row).getId();
    }

    private long repository(String name) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/" + System.nanoTime() + ".git");
        repository.setName(name);
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private long container(String imageName) {
        ContainerEntity image = new ContainerEntity();
        image.setImageName(imageName);
        image.setTag("1.0");
        return containers.save(image).getId();
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
