package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The public security badge.
 *
 * <p>The route this replaces took the repository's sequential id and carried
 * {@code @OpenToAnonymous} with no visibility check: walking 1..N returned the security grade of
 * every repository in the installation to a caller with no account, and answered {@code unknown}
 * for an id that did not exist — an existence oracle on top of a cross-tenant read. These tests
 * exist so that neither half can come back.
 */
@DisplayName("the public security badge")
class BadgeRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositories repositories;

    private Long repositoryId() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setName("corp/order-service");
        repository.setUrl("https://github.com/corp/order-service.git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    @Test
    @DisplayName("nothing is published until somebody publishes it")
    void closedByDefault() throws Exception {
        Long id = repositoryId();

        mvc.perform(authenticated(get("/api/v1/scorecards/repositories/" + id + "/badge"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.published").value(false))
                .andExpect(jsonPath("$.url").doesNotExist());
    }

    /**
     * The regression this whole change exists for.
     *
     * <p>Two assertions and they are not the same one. Anonymously the path is now refused by the
     * filter chain before any handler is consulted — 401, which is what every other unlisted path
     * gets. Signed in, it reaches routing and finds nothing: 404 proves there is no handler left,
     * which is stronger than proving a handler checks something.
     */
    @Test
    @DisplayName("the id-addressed badge route no longer exists, and is no longer anonymous")
    void theEnumerableRouteIsGone() throws Exception {
        Long id = repositoryId();

        mvc.perform(get("/api/v1/scorecards/repositories/" + id + "/badge.svg"))
                .andExpect(status().isUnauthorized());
        mvc.perform(authenticated(get("/api/v1/scorecards/repositories/" + id + "/badge.svg"), asAdmin()))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("a published badge is served to an anonymous caller, which is the point of it")
    void publishedBadgeIsAnonymous() throws Exception {
        Long id = repositoryId();

        String body = mvc.perform(authenticated(post("/api/v1/scorecards/repositories/" + id + "/badge"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.published").value(true))
                .andReturn()
                .getResponse()
                .getContentAsString();

        String url = json.readTree(body).path("url").asText();
        assertThat(url).startsWith("/api/v1/scorecards/badges/");

        mvc.perform(get(url))
                .andExpect(status().isOk())
                .andExpect(result -> assertThat(result.getResponse().getContentAsString()).contains("<svg"));
    }

    @Test
    @DisplayName("the token is not the id, and is long enough not to be walked")
    void tokenIsOpaque() throws Exception {
        Long id = repositoryId();

        String body = mvc.perform(authenticated(post("/api/v1/scorecards/repositories/" + id + "/badge"), asAdmin()))
                .andReturn()
                .getResponse()
                .getContentAsString();

        JsonNode answer = json.readTree(body);
        String token = answer.path("token").asText();

        // 32 random bytes, base64url, unpadded — 43 characters. The property is that the token is
        // not derived from the id in any way a caller could reverse or walk.
        assertThat(token).isNotEqualTo(String.valueOf(id));
        assertThat(token).hasSize(43);
        assertThat(token).matches("[A-Za-z0-9_-]+");
    }

    @Test
    @DisplayName("an unknown token is a 404, and so is a revoked one")
    void unknownAndRevokedLookAlike() throws Exception {
        Long id = repositoryId();

        String body = mvc.perform(authenticated(post("/api/v1/scorecards/repositories/" + id + "/badge"), asAdmin()))
                .andReturn()
                .getResponse()
                .getContentAsString();
        String url = json.readTree(body).path("url").asText();

        mvc.perform(get(url)).andExpect(status().isOk());

        mvc.perform(authenticated(delete("/api/v1/scorecards/repositories/" + id + "/badge"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.published").value(false));

        mvc.perform(get(url)).andExpect(status().isNotFound());
        mvc.perform(get("/api/v1/scorecards/badges/aTokenNobodyEverIssued.svg")).andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("publishing twice keeps the URL, so a README already carrying it keeps working")
    void publishIsIdempotent() throws Exception {
        Long id = repositoryId();

        String first = mvc.perform(authenticated(post("/api/v1/scorecards/repositories/" + id + "/badge"), asAdmin()))
                .andReturn().getResponse().getContentAsString();
        String second = mvc.perform(authenticated(post("/api/v1/scorecards/repositories/" + id + "/badge"), asAdmin()))
                .andReturn().getResponse().getContentAsString();

        assertThat(json.readTree(first).path("token").asText())
                .isEqualTo(json.readTree(second).path("token").asText());
    }

    @Test
    @DisplayName("publishing needs a session — the anonymous half is reading, never deciding")
    void publishingIsNotAnonymous() throws Exception {
        Long id = repositoryId();

        mvc.perform(post("/api/v1/scorecards/repositories/" + id + "/badge"))
                .andExpect(status().isUnauthorized());
        mvc.perform(delete("/api/v1/scorecards/repositories/" + id + "/badge"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("a repository that does not exist is a 404 to the state route, not an empty answer")
    void unknownRepository() throws Exception {
        mvc.perform(authenticated(get("/api/v1/scorecards/repositories/999999/badge"), asAdmin()))
                .andExpect(status().isNotFound());
    }
}
