package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.repositories.Users;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * Deprovisioning an account by PATCH, through the routes.
 *
 * <p><b>The gesture a directory makes when somebody leaves</b> — {@code active: false} — and the
 * one this route could not perform: the operation's {@code value} was a Jackson 2 node, which the
 * Jackson 3 HTTP layer cannot build, so the request answered 500 before reaching the service. The
 * unit test beside the controller built the node by hand and passed throughout.
 */
@DisplayName("the SCIM user routes")
class ScimUsersRoutesTest extends ApiTestBase {

    @Autowired
    private Users users;

    @Test
    @DisplayName("a PATCH setting active to false deactivates the account and closes its sessions")
    void patchDeactivates() throws Exception {
        String session = tokenFor("scim-leaver", Role.USER, false);
        long id = users.findByUsername("scim-leaver").orElseThrow().getId();

        mvc.perform(authenticated(get("/api/v1/auth/me"), session))
                .andExpect(status().isOk());

        mvc.perform(authenticated(patch("/scim/v2/Users/" + id), asAdmin())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of(
                                "schemas", List.of("urn:ietf:params:scim:api:messages:2.0:PatchOp"),
                                "Operations", List.of(Map.of("op", "replace", "path", "active", "value", false))))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false));

        assertThat(users.findById(id).orElseThrow().getIsActive()).isFalse();
        // Out when the directory says so, not when the session happens to expire.
        mvc.perform(authenticated(get("/api/v1/auth/me"), session))
                .andExpect(status().isUnauthorized());
    }
}
