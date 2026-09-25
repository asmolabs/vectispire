package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.GitTokens;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * HTTPS clone tokens over HTTP (decision 0022): stored encrypted, bound to a host, never returned,
 * and attachable only where they will be presented to that host.
 */
@DisplayName("HTTPS clone tokens")
class GitTokensRoutesTest extends ApiTestBase {

    @Autowired
    private GitTokens tokens;

    @Autowired
    private GitRepositories repositories;

    private String createToken(String host) throws Exception {
        String body = mvc.perform(authenticated(post("/api/v1/git-tokens"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "forge", "host", host, "token", "glpat-secret-token"))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return json.readTree(body).get("id").asText();
    }

    @Test
    @DisplayName("is stored encrypted, normalizes its host, and never comes back out")
    void theTokenNeverLeaves() throws Exception {
        String id = createToken(" GitLab.Example.com. ");

        String listed = mvc.perform(authenticated(get("/api/v1/git-tokens"), asAdmin()))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        assertThat(listed).contains("gitlab.example.com").doesNotContain("glpat-secret-token");
        assertThat(tokens.findById(java.util.UUID.fromString(id)).orElseThrow().getToken())
                .startsWith("v2:")
                .doesNotContain("glpat-secret-token");
    }

    @Test
    @DisplayName("is an administrator's to manage")
    void onlyAnAdministratorManagesThem() throws Exception {
        mvc.perform(authenticated(get("/api/v1/git-tokens"), asCiso())).andExpect(status().isForbidden());
        mvc.perform(authenticated(post("/api/v1/git-tokens"), asAuditor())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "x", "host", "h.example", "token", "t"))))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("attaches only to an https URL on its own host")
    void theTokenGoesToItsHostOnly() throws Exception {
        // Without the binding, pointing a repository's URL at another server would send that server
        // the forge's token.
        String id = createToken("gitlab.example.com");

        for (String url : new String[] {"https://evil.example.net/team/repo.git", "git@gitlab.example.com:team/repo.git"}) {
            mvc.perform(authenticated(post("/api/v1/repositories"), asAdmin())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(write(Map.of("url", url, "https_token_id", id))))
                    .andExpect(status().isBadRequest());
        }

        mvc.perform(authenticated(post("/api/v1/repositories"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("url", "https://gitlab.example.com/team/repo.git", "https_token_id", id))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.httpsTokenId").value(id));

        // Moving that repository to another host later is refused too, token still attached.
        long repoId = repositories.findAll().stream()
                .filter(r -> "https://gitlab.example.com/team/repo.git".equals(r.getUrl()))
                .findFirst().orElseThrow().getId();
        mvc.perform(authenticated(patch("/api/v1/repositories/" + repoId), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("url", "https://evil.example.net/team/repo.git"))))
                .andExpect(status().isBadRequest());

        // And a token in use cannot be deleted from under the repository.
        mvc.perform(authenticated(delete("/api/v1/git-tokens/" + id), asAdmin())).andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("a new URL carrying a credential is refused; an old one keeps working")
    void aCredentialInTheUrlIsRefusedForNewUrls() throws Exception {
        // It was the only way to clone a private repository over HTTPS, and it stored the token in
        // the clear in the repository row.
        mvc.perform(authenticated(post("/api/v1/repositories"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("url", "https://oauth2:glpat-x@gitlab.example.com/team/repo.git"))))
                .andExpect(status().isBadRequest());

        RepositoryEntity legacy = new RepositoryEntity();
        legacy.setUrl("https://oauth2:glpat-x@gitlab.example.com/team/legacy.git");
        legacy.setBranch("main");
        long legacyId = repositories.save(legacy).getId();
        mvc.perform(authenticated(patch("/api/v1/repositories/" + legacyId), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("branch", "develop"))))
                .andExpect(status().isOk());
    }
}
