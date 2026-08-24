package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * What a refusal looks like from outside.
 *
 * <p><b>A wrong status is not cosmetic here.</b> 401 tells a client to sign in, so a client that
 * receives it for anything else signs in, retries, and is refused again — a loop in which the
 * real reason is never shown to anybody. That is what the application did for every unmapped
 * failure until the error dispatch was let through the security chain, and it took starting the
 * server to see it: through MockMvc the same call answered correctly.
 */
@DisplayName("what a refusal looks like from outside")
class ErrorResponsesTest extends ApiTestBase {

    @Autowired
    private GitRepositories repositories;

    @Test
    @DisplayName("a second scan of a queued target is 409, and says why")
    void aDuplicateScanIsAConflict() throws Exception {
        long id = repository();

        mvc.perform(authenticated(post("/api/v1/repositories/" + id + "/scan"), asAdmin()))
                .andExpect(status().isOk());

        mvc.perform(authenticated(post("/api/v1/repositories/" + id + "/scan"), asAdmin()))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.detail").value("A scan of this target is already queued."));
    }

    @Test
    @DisplayName("a target that is not there is 404, with a body")
    void anAbsentTargetIsNotFound() throws Exception {
        mvc.perform(authenticated(post("/api/v1/repositories/9999/scan"), asAdmin()))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.detail").isNotEmpty());
    }

    @Test
    @DisplayName("a malformed value is 400, with the message the operator has to read")
    void aMalformedValueIsABadRequest() throws Exception {
        mvc.perform(authenticated(post("/api/v1/repositories"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("url", "ext::sh -c whoami"))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.detail").isNotEmpty());
    }

    @Test
    @DisplayName("no refusal of a signed-in caller is ever a 401")
    void nothingAnsweredToASignedInCallerSaysSignInAgain() throws Exception {
        String admin = asAdmin();

        // 401 is reserved for "we do not know who you are". Every other refusal has to be
        // distinguishable from it, or a client cannot tell "log in" from "you cannot do that".
        mvc.perform(authenticated(get("/api/v1/scans/9999"), admin)).andExpect(status().isNotFound());
        mvc.perform(authenticated(get("/api/v1/targets/nonsense/1/issues.csv"), admin))
                .andExpect(status().isBadRequest());
        mvc.perform(authenticated(post("/api/v1/gate"), admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of())))
                .andExpect(status().isBadRequest());
    }

    private long repository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/queued.git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }
}
