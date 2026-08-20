package com.asmolabs.zanshin.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.zanshin.core.persistence.RepositoryEntity;
import com.asmolabs.zanshin.core.repositories.GitRepositories;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * Changing a monitored repository.
 *
 * <p>There was no way to: create, scan and delete were the whole surface, so correcting a branch
 * or a sub-path meant deleting the row — and its scan history and its triaged backlog with it.
 */
@DisplayName("updating a repository")
class RepositoryUpdateTest extends ApiTestBase {

    @Autowired
    private GitRepositories repositories;

    @Test
    @DisplayName("leaves out what the request left out, instead of clearing it")
    void absentMeansUnchanged() throws Exception {
        long id = seed();

        // The trap this pins: a screen that edits two fields sends two fields. With the opposite
        // convention it would silently erase the SSH key, the schedule and the agent label — and
        // nothing would say so until a scan waited for an agent nobody requires any more.
        mvc.perform(authenticated(patch("/api/v1/repositories/" + id), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("branch", "develop"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.branch").value("develop"))
                .andExpect(jsonPath("$.subPath").value("services/billing"))
                .andExpect(jsonPath("$.requiredAgentLabel").value("linux-x64"));
    }

    @Test
    @DisplayName("clears a field when the request says empty, which is a different thing")
    void emptyMeansCleared() throws Exception {
        long id = seed();

        mvc.perform(authenticated(patch("/api/v1/repositories/" + id), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("required_agent_label", "", "subPath", ""))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.requiredAgentLabel").doesNotExist())
                .andExpect(jsonPath("$.subPath").doesNotExist());
    }

    @Test
    @DisplayName("validates the URL on update exactly as on create")
    void theUrlIsValidatedAgain() throws Exception {
        long id = seed();

        // An unvalidated URL reaching a git clone is arbitrary code execution, not a typo. A row
        // edited later is no safer than a row added.
        mvc.perform(authenticated(patch("/api/v1/repositories/" + id), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("url", "ext::sh -c whoami"))))
                .andExpect(status().isBadRequest());

        mvc.perform(authenticated(get("/api/v1/repositories"), asAdmin()))
                .andExpect(jsonPath("$[0].url").value("https://example.invalid/billing.git"));
    }

    @Test
    @DisplayName("switching to SSH is a change of URL, and keeps the row")
    void theUrlCanMoveToSsh() throws Exception {
        long id = seed();

        // The point of having an update at all: the backlog and the scan history stay attached.
        mvc.perform(authenticated(patch("/api/v1/repositories/" + id), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("url", "git@example.invalid:team/billing.git"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value((int) id))
                .andExpect(jsonPath("$.url").value("git@example.invalid:team/billing.git"));
    }

    private long seed() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/billing.git");
        repository.setBranch("main");
        repository.setSubPath("services/billing");
        repository.setRequiredAgentLabel("linux-x64");
        return repositories.save(repository).getId();
    }
}
