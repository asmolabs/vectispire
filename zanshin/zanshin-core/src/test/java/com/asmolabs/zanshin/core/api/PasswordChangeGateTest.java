package com.asmolabs.zanshin.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

/**
 * The forced password change, enforced on the server.
 *
 * <p>This is the control that used to exist only in the Angular client: the flag was set in
 * three places and read by nobody on the server, so a direct API call ignored it and the
 * bootstrap password stayed a valid SUPERUSER credential with no expiry.
 *
 * <p><b>403 and not 401.</b> The caller is authenticated — its token is good and the server
 * knows exactly who it is. 401 says "sign in", which the client has already done and would do
 * again, in a loop. 403 with the reason is what sends it to the password screen instead. The
 * first run of the real application answered 401, which is how this test came to exist.
 */
@DisplayName("an account that must change its password")
class PasswordChangeGateTest extends ApiTestBase {

    @Test
    @DisplayName("is refused on an ordinary route, with 403")
    void ordinaryRoutesAreRefused() throws Exception {
        String token = asPendingPasswordChange();

        mvc.perform(authenticated(get("/api/v1/issues"), token)).andExpect(status().isForbidden());
        mvc.perform(authenticated(get("/api/v1/dashboard"), token)).andExpect(status().isForbidden());
        mvc.perform(authenticated(get("/api/v1/users"), token)).andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("can still read its own profile and sign out")
    void theWayOutStaysOpen() throws Exception {
        String token = asPendingPasswordChange();

        // The allow-list holds exactly what it takes to leave the state, and nothing else.
        mvc.perform(authenticated(get("/api/v1/auth/me"), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mustChangePassword").value(true));
        mvc.perform(authenticated(delete("/api/v1/auth/session"), token)).andExpect(status().isNoContent());
    }

    @Test
    @DisplayName("changing the password lifts the refusal")
    void changingThePasswordOpensTheRest() throws Exception {
        String token = asPendingPasswordChange();

        mvc.perform(authenticated(post("/api/v1/auth/change-password"), token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of(
                                "currentPassword", "correct horse battery staple",
                                "newPassword", "a different long passphrase"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mustChangePassword").value(false));

        mvc.perform(authenticated(get("/api/v1/issues"), token)).andExpect(status().isOk());
    }

    @Test
    @DisplayName("the current password is required, even here")
    void theCurrentPasswordIsStillRequired() throws Exception {
        String token = asPendingPasswordChange();

        // No "first login" exemption: the person has just typed that password to get here, and
        // without the check a workstation left unlocked for a minute is enough to take the
        // account.
        mvc.perform(authenticated(post("/api/v1/auth/change-password"), token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("currentPassword", "wrong", "newPassword", "a long new passphrase"))))
                .andExpect(status().isUnauthorized());
    }
}
