package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;

/** With an allowlist configured, a repository on another host is refused when it is entered. */
@DisplayName("the git host allowlist, on the repository form")
@TestPropertySource(properties = "vectispire.git.allowed-hosts=gitlab.corp.example,*.forge.example")
class GitHostAllowlistRoutesTest extends ApiTestBase {

    @Test
    @DisplayName("refuses a host the list does not name, accepts one it does")
    void onlyListedHosts() throws Exception {
        mvc.perform(authenticated(post("/api/v1/repositories"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("url", "https://github.com/someone/else.git"))))
                .andExpect(status().isBadRequest());

        mvc.perform(authenticated(post("/api/v1/repositories"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("url", "git@eu.forge.example:team/service.git"))))
                .andExpect(status().isOk());
    }
}
