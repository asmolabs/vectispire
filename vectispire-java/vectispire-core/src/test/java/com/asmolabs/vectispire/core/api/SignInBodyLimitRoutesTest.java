package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

/**
 * The sign-in routes, through the real filter chain, refuse a body no sign-in needs.
 *
 * <p>Three of them are open to anyone, and their JSON was read with no ceiling but the container's.
 */
@DisplayName("the size of what the sign-in routes accept")
class SignInBodyLimitRoutesTest extends ApiTestBase {

    @Test
    @DisplayName("a login, a one-time code or a session exchange past 16 KB is answered 413")
    void oversizedSignInBodiesAreRefused() throws Exception {
        String padding = " ".repeat(16 * 1024);
        for (String path : new String[] {"/api/v1/auth/login", "/api/v1/auth/mfa/verify", "/api/v1/auth/session/exchange"}) {
            int status = mvc.perform(post(path)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"username\":\"nobody\"," + padding + "\"password\":\"x\"}"))
                    .andReturn().getResponse().getStatus();

            assertThat(status).as(path).isEqualTo(413);
        }
    }

    @Test
    @DisplayName("an ordinary login is still read, and refused on its credentials")
    void anOrdinaryLoginIsRead() throws Exception {
        int status = mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"nobody\",\"password\":\"not-the-password\"}"))
                .andReturn().getResponse().getStatus();

        assertThat(status).isEqualTo(401);
    }
}
