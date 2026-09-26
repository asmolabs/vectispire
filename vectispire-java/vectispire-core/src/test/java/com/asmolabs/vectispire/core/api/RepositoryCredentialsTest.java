package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.core.audit.persistence.AuditLog;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * A repository URL that carries a credential: accepted, used for the clone, and shown nowhere.
 *
 * <p>A token in the URL is the only way to clone a private repository over HTTPS today, so it is
 * not refused. It was, however, returned verbatim by the list to every account that sees the
 * repository, and written into the audit log — chained, so never rewritten.
 */
@DisplayName("a repository URL carrying a credential")
class RepositoryCredentialsTest extends ApiTestBase {

    private static final String WITH_TOKEN = "https://alice:ghp_secret@github.com/org/private.git";
    private static final String MASKED = "https://***@github.com/org/private.git";

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private AuditLog auditLogs;

    /**
     * A row from before decision 0022, when a token in the URL was the only way to clone a private
     * repository over HTTPS. New ones are refused on entry; these keep working and stay masked.
     */
    private long legacyRow() {
        RepositoryEntity legacy = new RepositoryEntity();
        legacy.setUrl(WITH_TOKEN);
        legacy.setBranch("main");
        return repositories.save(legacy).getId();
    }

    @Test
    @DisplayName("a new URL carrying a credential is refused on entry")
    void aNewCredentialInTheUrlIsRefused() throws Exception {
        mvc.perform(authenticated(post("/api/v1/repositories"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("url", WITH_TOKEN, "branch", "main"))))
                .andExpect(status().isBadRequest());
        assertThat(repositories.findAll()).isEmpty();
    }

    @Test
    @DisplayName("an existing one is kept whole, and neither the list nor the audit log shows it")
    void theCredentialIsNeverShown() throws Exception {
        long id = legacyRow();
        String updated = mvc.perform(authenticated(patch("/api/v1/repositories/" + id), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("branch", "develop"))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String listed = mvc.perform(authenticated(get("/api/v1/repositories"), asAdmin()))
                .andReturn().getResponse().getContentAsString();

        assertThat(updated).doesNotContain("ghp_secret").contains(MASKED);
        assertThat(listed).doesNotContain("ghp_secret").contains(MASKED);
        assertThat(auditLogs.findAll()).allSatisfy(entry -> assertThat(entry.getDescription()).doesNotContain("ghp_secret"));
        // The clone still needs it.
        assertThat(repositories.findById(id).orElseThrow().getUrl()).isEqualTo(WITH_TOKEN);
    }

    @Test
    @DisplayName("a form saved with the masked URL untouched keeps the stored one")
    void theMaskSentBackChangesNothing() throws Exception {
        // The edit form shows what the list sent — the mask. Saving it without touching the URL
        // must not replace a working credential with three asterisks.
        long id = legacyRow();

        mvc.perform(authenticated(patch("/api/v1/repositories/" + id), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("url", MASKED, "branch", "develop"))))
                .andExpect(status().isOk());

        assertThat(repositories.findById(id).orElseThrow().getUrl()).isEqualTo(WITH_TOKEN);
        assertThat(repositories.findById(id).orElseThrow().getBranch()).isEqualTo("develop");
    }
}
