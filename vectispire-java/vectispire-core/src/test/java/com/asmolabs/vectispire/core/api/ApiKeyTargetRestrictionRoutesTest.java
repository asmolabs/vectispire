package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.ApiKeysRepository;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import java.util.Map;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * A key restricted to one target, which nothing would have enforced.
 *
 * <p>The only keys that authenticate are agents' own, issued unrestricted when the agent is
 * declared, and the agent protocol reads no visibility. A restriction chosen on the API keys screen
 * was stored, listed with its target's name — and restricted nothing, because no key issued there
 * ever reaches a route that reads one. It is refused now, and nothing is stored.
 */
@DisplayName("an API key cannot be restricted to a target nobody would enforce")
class ApiKeyTargetRestrictionRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private ApiKeysRepository keys;

    @Test
    @DisplayName("a restricted key is refused with 400, and no key is issued")
    void aRestrictedKeyIsRefused() throws Exception {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/restricted.git");
        repository.setBranch("main");
        long id = repositories.save(repository).getId();
        long before = keys.count();

        mvc.perform(authenticated(post("/api/v1/api-keys"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "ci", "target_kind", "repository", "target_id", id))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.detail").value(Matchers.containsString("cannot be restricted to a target")));

        assertThat(keys.count()).isEqualTo(before);
    }

    @Test
    @DisplayName("an unrestricted key is still issued")
    void anUnrestrictedKeyIsIssued() throws Exception {
        mvc.perform(authenticated(post("/api/v1/api-keys"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "ci"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.key.targetKind").doesNotExist());
    }
}
