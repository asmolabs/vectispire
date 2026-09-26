package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.Users;
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

    // --- What the directory may not do -------------------------------------------------------
    //
    // The SCIM token lives in the identity provider's configuration. With it, a PUT rebound the
    // bootstrap governor to an attacker's IdP subject, granted SUPERUSER, or demoted anyone to USER
    // by omitting roles; the last administrator could be deleted. Each test below is one of those.

    @Test
    @DisplayName("an administrative account cannot be replaced, patched or deleted through SCIM")
    void administrativeAccountsAreProtected() throws Exception {
        tokenFor("scim-admin", Role.ADMIN, false);
        long id = users.findByUsername("scim-admin").orElseThrow().getId();

        mvc.perform(authenticated(put("/scim/v2/Users/" + id), asAdmin())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-admin", "externalId", "attacker-subject"))))
                .andExpect(status().isForbidden());
        mvc.perform(authenticated(patch("/scim/v2/Users/" + id), asAdmin())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of(
                                "schemas", List.of("urn:ietf:params:scim:api:messages:2.0:PatchOp"),
                                "Operations", List.of(Map.of("op", "replace", "path", "active", "value", false))))))
                .andExpect(status().isForbidden());
        mvc.perform(authenticated(delete("/scim/v2/Users/" + id), asAdmin()))
                .andExpect(status().isForbidden());

        var after = users.findById(id).orElseThrow();
        assertThat(after.getKeycloakId()).isNull();
        assertThat(after.getIsActive()).isTrue();
        assertThat(after.getRole()).isEqualTo(Role.ADMIN.name());
    }

    @Test
    @DisplayName("SCIM grants no administrative role, on creation or replacement")
    void noAdministrativeGrant() throws Exception {
        tokenFor("scim-plain", Role.USER, false);
        long id = users.findByUsername("scim-plain").orElseThrow().getId();

        mvc.perform(authenticated(put("/scim/v2/Users/" + id), asAdmin())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-plain", "roles", List.of(Map.of("value", "SUPERUSER"))))))
                .andExpect(status().isBadRequest());
        mvc.perform(authenticated(post("/scim/v2/Users"), asAdmin())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-new-admin", "roles", List.of(Map.of("value", "admin"))))))
                .andExpect(status().isBadRequest());

        assertThat(users.findById(id).orElseThrow().getRole()).isEqualTo(Role.USER.name());
        assertThat(users.findByUsername("scim-new-admin")).isEmpty();
    }

    @Test
    @DisplayName("a replacement that names no role leaves the role as it is")
    void anAbsentRoleIsNoDemotion() throws Exception {
        tokenFor("scim-ciso", Role.CISO, false);
        long id = users.findByUsername("scim-ciso").orElseThrow().getId();

        mvc.perform(authenticated(put("/scim/v2/Users/" + id), asAdmin())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-ciso", "displayName", "Renamed"))))
                .andExpect(status().isOk());

        assertThat(users.findById(id).orElseThrow().getRole()).isEqualTo(Role.CISO.name());
    }

    @Test
    @DisplayName("externalId is bound once and never rebound")
    void externalIdIsImmutable() throws Exception {
        tokenFor("scim-bound", Role.USER, false);
        long id = users.findByUsername("scim-bound").orElseThrow().getId();

        mvc.perform(authenticated(put("/scim/v2/Users/" + id), asAdmin())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-bound", "externalId", "subject-1"))))
                .andExpect(status().isOk());
        mvc.perform(authenticated(put("/scim/v2/Users/" + id), asAdmin())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-bound", "externalId", "attacker-subject"))))
                .andExpect(status().isBadRequest());

        assertThat(users.findById(id).orElseThrow().getKeycloakId()).isEqualTo("subject-1");
    }

    @Test
    @DisplayName("a role change from the directory closes the account's sessions")
    void aRoleChangeRevokes() throws Exception {
        String session = tokenFor("scim-promoted", Role.USER, false);
        long id = users.findByUsername("scim-promoted").orElseThrow().getId();

        mvc.perform(authenticated(put("/scim/v2/Users/" + id), asAdmin())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-promoted", "roles", List.of(Map.of("value", "SECURITY_CHAMPION"))))))
                .andExpect(status().isOk());

        assertThat(users.findById(id).orElseThrow().getRole()).isEqualTo(Role.SECURITY_CHAMPION.name());
        mvc.perform(authenticated(get("/api/v1/auth/me"), session))
                .andExpect(status().isUnauthorized());
    }
}
