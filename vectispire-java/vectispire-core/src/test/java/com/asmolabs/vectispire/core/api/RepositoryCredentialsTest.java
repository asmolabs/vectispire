package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.core.repositories.AuditLog;
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

    @Test
    @DisplayName("is stored whole, and neither the list nor the audit log shows the credential")
    void theCredentialIsNeverShown() throws Exception {
        String created = mvc.perform(authenticated(post("/api/v1/repositories"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("url", WITH_TOKEN, "branch", "main"))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String listed = mvc.perform(authenticated(get("/api/v1/repositories"), asAdmin()))
                .andReturn().getResponse().getContentAsString();

        assertThat(created).doesNotContain("ghp_secret").contains(MASKED);
        assertThat(listed).doesNotContain("ghp_secret").contains(MASKED);
        assertThat(auditLogs.findAll()).allSatisfy(entry -> assertThat(entry.getDescription()).doesNotContain("ghp_secret"));
        // The clone still needs it.
        assertThat(repositories.findAll()).singleElement().satisfies(r -> assertThat(r.getUrl()).isEqualTo(WITH_TOKEN));
    }

    @Test
    @DisplayName("a form saved with the masked URL untouched keeps the stored one")
    void theMaskSentBackChangesNothing() throws Exception {
        // The edit form shows what the list sent — the mask. Saving it without touching the URL
        // must not replace a working credential with three asterisks.
        String admin = asAdmin();
        mvc.perform(authenticated(post("/api/v1/repositories"), admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("url", WITH_TOKEN, "branch", "main"))))
                .andExpect(status().isOk());
        long id = repositories.findAll().getFirst().getId();

        mvc.perform(authenticated(patch("/api/v1/repositories/" + id), admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("url", MASKED, "branch", "develop"))))
                .andExpect(status().isOk());

        assertThat(repositories.findById(id).orElseThrow().getUrl()).isEqualTo(WITH_TOKEN);
        assertThat(repositories.findById(id).orElseThrow().getBranch()).isEqualTo("develop");
    }
}
