package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.AuthenticationFlowService;
import com.asmolabs.vectispire.core.access.ExternalIdentityService;
import com.asmolabs.vectispire.core.access.ScimProvisioningService;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.access.web.security.chain.OidcConfiguration;
import jakarta.servlet.http.Cookie;
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
    private UserRepository users;

    @Autowired
    private com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository auditLogs;

    @Autowired
    private AuthenticationFlowService flows;

    @Test
    @DisplayName("/scim takes the SCIM token and nothing else: an administrator's session is refused there")
    void scimTakesOnlyTheToken() throws Exception {
        // The controllers carried the administrator marker and nothing more: an administrator's
        // session provisioned through /scim, outside the account screens' rules, SCIM enabled or
        // not. The converse of ScimTokenScopeTest, which keeps the token on /scim.
        String admin = asAdmin();
        long before = users.count();
        mvc.perform(authenticated(get("/scim/v2/Users"), admin)).andExpect(status().isForbidden());
        mvc.perform(authenticated(post("/scim/v2/Users"), admin)
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-via-session"))))
                .andExpect(status().isForbidden());
        mvc.perform(authenticated(get("/scim/v2/Groups"), admin)).andExpect(status().isForbidden());
        mvc.perform(get("/scim/v2/Users")).andExpect(status().isUnauthorized());
        assertThat(users.count()).isEqualTo(before);
        assertThat(users.findByUsername("scim-via-session")).isEmpty();
    }

    @Test
    @DisplayName("the audit names the directory as the actor and the account as what was changed")
    void theDirectoryIsTheActor() throws Exception {
        mvc.perform(authenticated(post("/scim/v2/Users"), asScim())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-audited"))))
                .andExpect(status().isCreated());
        long id = users.findByUsername("scim-audited").orElseThrow().getId();

        assertThat(auditLogs.findAll())
                .filteredOn(entry -> "SCIM provisioned account: scim-audited".equals(entry.getDescription()))
                .singleElement()
                .satisfies(entry -> {
                    assertThat(entry.getUserId()).isEqualTo(ScimProvisioningService.ACTOR);
                    assertThat(entry.getResourceId()).isEqualTo(String.valueOf(id));
                });
    }

    @Test
    @DisplayName("a PATCH setting active to false deactivates the account and closes its sessions")
    void patchDeactivates() throws Exception {
        String session = tokenFor("scim-leaver", Role.USER, false);
        long id = users.findByUsername("scim-leaver").orElseThrow().getId();

        mvc.perform(authenticated(get("/api/v1/auth/me"), session))
                .andExpect(status().isOk());

        mvc.perform(authenticated(patch("/scim/v2/Users/" + id), asScim())
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

        mvc.perform(authenticated(put("/scim/v2/Users/" + id), asScim())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-admin", "externalId", "attacker-subject"))))
                .andExpect(status().isForbidden());
        mvc.perform(authenticated(patch("/scim/v2/Users/" + id), asScim())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of(
                                "schemas", List.of("urn:ietf:params:scim:api:messages:2.0:PatchOp"),
                                "Operations", List.of(Map.of("op", "replace", "path", "active", "value", false))))))
                .andExpect(status().isForbidden());
        mvc.perform(authenticated(delete("/scim/v2/Users/" + id), asScim()))
                .andExpect(status().isForbidden());

        var after = users.findById(id).orElseThrow();
        assertThat(after.getKeycloakId()).isNull();
        assertThat(after.getIsActive()).isTrue();
        assertThat(after.getRole()).isEqualTo(Role.ADMIN.name());
    }

    @Test
    @DisplayName("the 403 on an administrative account and the 400 of a PATCH past a column are SCIM's error schema")
    void refusalsAreScimErrors() throws Exception {
        // Both are declared in the OpenAPI document with ScimErrorResponse (OpenApiRoutesTest): this is
        // the body behind each declaration, a PATCH's 400 included, which no other case sends.
        tokenFor("scim-protected", Role.ADMIN, false);
        long admin = users.findByUsername("scim-protected").orElseThrow().getId();
        mvc.perform(authenticated(delete("/scim/v2/Users/" + admin), asScim()))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.schemas[0]").value("urn:ietf:params:scim:api:messages:2.0:Error"))
                .andExpect(jsonPath("$.status").value("403"));

        tokenFor("scim-patched", Role.USER, false);
        long id = users.findByUsername("scim-patched").orElseThrow().getId();
        mvc.perform(authenticated(patch("/scim/v2/Users/" + id), asScim())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of(
                                "schemas", List.of("urn:ietf:params:scim:api:messages:2.0:PatchOp"),
                                "Operations", List.of(Map.of(
                                        "op", "replace", "value", Map.of("displayName", "d".repeat(256))))))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.schemas[0]").value("urn:ietf:params:scim:api:messages:2.0:Error"))
                .andExpect(jsonPath("$.status").value("400"))
                .andExpect(jsonPath("$.detail").value("The SCIM attribute displayName is longer than 255 characters."));
        assertThat(users.findById(id).orElseThrow().getDisplayName()).isNotEqualTo("d".repeat(256));
    }

    @Test
    @DisplayName("SCIM grants no administrative role, on creation or replacement")
    void noAdministrativeGrant() throws Exception {
        tokenFor("scim-plain", Role.USER, false);
        long id = users.findByUsername("scim-plain").orElseThrow().getId();

        mvc.perform(authenticated(put("/scim/v2/Users/" + id), asScim())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-plain", "roles", List.of(Map.of("value", "SUPERUSER"))))))
                .andExpect(status().isBadRequest());
        mvc.perform(authenticated(post("/scim/v2/Users"), asScim())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-new-admin", "roles", List.of(Map.of("value", "admin"))))))
                .andExpect(status().isBadRequest());

        assertThat(users.findById(id).orElseThrow().getRole()).isEqualTo(Role.USER.name());
        assertThat(users.findByUsername("scim-new-admin")).isEmpty();
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.EnumSource(Role.class)
    @DisplayName("SCIM grants only the scoped roles; one that administers or sees the whole estate is Vectispire's")
    void onlyScopedRolesAreGranted(Role role) throws Exception {
        // Only ADMIN and SUPERUSER were refused: the directory's token could make an account a CISO
        // or an auditor.
        String name = "scim-" + role.name().toLowerCase(java.util.Locale.ROOT) + "-" + System.nanoTime();
        int status = mvc.perform(authenticated(post("/scim/v2/Users"), asScim())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", name, "roles", List.of(Map.of("value", role.name()))))))
                .andReturn().getResponse().getStatus();

        boolean scoped = !role.isAdministrative() && !role.hasGlobalSecurityScope();
        assertThat(status).as("SCIM creating a %s", role).isEqualTo(scoped ? 201 : 400);
        assertThat(users.findByUsername(name).map(user -> user.getRole()))
                .isEqualTo(scoped ? java.util.Optional.of(role.name()) : java.util.Optional.empty());
    }

    @Test
    @DisplayName("naming the role an account already holds is not a grant, and is accepted")
    void theSameRoleIsNoGrant() throws Exception {
        tokenFor("scim-auditor", Role.AUDITOR, false);
        long id = users.findByUsername("scim-auditor").orElseThrow().getId();

        mvc.perform(authenticated(put("/scim/v2/Users/" + id), asScim())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-auditor", "roles", List.of(Map.of("value", "AUDITOR"))))))
                .andExpect(status().isOk());
        mvc.perform(authenticated(put("/scim/v2/Users/" + id), asScim())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-auditor", "roles", List.of(Map.of("value", "CISO"))))))
                .andExpect(status().isBadRequest());
        assertThat(users.findById(id).orElseThrow().getRole()).isEqualTo(Role.AUDITOR.name());
    }

    @Test
    @DisplayName("a replacement that names no role leaves the role as it is")
    void anAbsentRoleIsNoDemotion() throws Exception {
        tokenFor("scim-ciso", Role.CISO, false);
        long id = users.findByUsername("scim-ciso").orElseThrow().getId();

        mvc.perform(authenticated(put("/scim/v2/Users/" + id), asScim())
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

        mvc.perform(authenticated(put("/scim/v2/Users/" + id), asScim())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-bound", "externalId", "subject-1"))))
                .andExpect(status().isOk());
        mvc.perform(authenticated(put("/scim/v2/Users/" + id), asScim())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-bound", "externalId", "attacker-subject"))))
                .andExpect(status().isBadRequest());

        assertThat(users.findById(id).orElseThrow().getKeycloakId()).isEqualTo("subject-1");
    }

    /**
     * The subject is unique in {@code t_user}: a directory binding one another account holds reached
     * the constraint and read a 500, where {@code uniqueness} is what tells it to link instead.
     */
    @Test
    @DisplayName("an externalId another account is bound to is a 409 uniqueness, on creation and on a first binding")
    void aTakenExternalIdIsUniqueness() throws Exception {
        mvc.perform(authenticated(post("/scim/v2/Users"), asScim())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-subject-holder", "externalId", "subject-held"))))
                .andExpect(status().isCreated());

        mvc.perform(authenticated(post("/scim/v2/Users"), asScim())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-subject-second", "externalId", "subject-held"))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.scimType").value("uniqueness"))
                .andExpect(jsonPath("$.detail").value("An account with this externalId already exists."));
        assertThat(users.findByUsername("scim-subject-second")).isEmpty();

        tokenFor("scim-subject-unbound", Role.USER, false);
        long id = users.findByUsername("scim-subject-unbound").orElseThrow().getId();
        mvc.perform(authenticated(put("/scim/v2/Users/" + id), asScim())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-subject-unbound", "externalId", "subject-held",
                                "displayName", "Not Written"))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.scimType").value("uniqueness"))
                .andExpect(jsonPath("$.detail").value("An account with this externalId already exists."));
        var unbound = users.findById(id).orElseThrow();
        assertThat(unbound.getKeycloakId()).isNull();
        assertThat(unbound.getDisplayName()).isNotEqualTo("Not Written");

        // The holder's own subject, sent again, is no conflict.
        long holder = users.findByUsername("scim-subject-holder").orElseThrow().getId();
        mvc.perform(authenticated(put("/scim/v2/Users/" + holder), asScim())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-subject-holder", "externalId", "subject-held"))))
                .andExpect(status().isOk());
    }

    /**
     * The audit of 10 October 2026: the token could not grant a CISO, but it could bind an existing,
     * unbound one to a subject of its choosing, and the next sign-in landed on that account with
     * neither its password nor its second factor.
     */
    @Test
    @DisplayName("an existing privileged account is not bound to a subject by the directory")
    void aPrivilegedAccountIsNotBound() throws Exception {
        tokenFor("scim-ciso-unbound", Role.CISO, false);
        long id = users.findByUsername("scim-ciso-unbound").orElseThrow().getId();

        mvc.perform(authenticated(put("/scim/v2/Users/" + id), asScim())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-ciso-unbound", "externalId", "attacker-subject"))))
                .andExpect(status().isBadRequest())
                // It used to send the directory to "an administrator, in Vectispire", where no route binds a
                // subject: the refusal names what does work.
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Provision a new account")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("link-privileged-accounts")));

        assertThat(users.findById(id).orElseThrow().getKeycloakId()).isNull();
    }

    /**
     * The role was read at the binding, and the directory may lower one: a first request lowered the
     * CISO to User, and the next bound it, now that it held nothing. Lowering stays allowed — taking a
     * privilege away must not wait — and the binding remembers what the account held.
     */
    @Test
    @DisplayName("an account the directory lowered out of a privileged role is not bound until an administrator sets its role")
    void aLoweredAccountIsNotBound() throws Exception {
        tokenFor("scim-ciso-lowered", Role.CISO, false);
        long id = users.findByUsername("scim-ciso-lowered").orElseThrow().getId();

        mvc.perform(authenticated(put("/scim/v2/Users/" + id), asScim())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-ciso-lowered", "roles", List.of(Map.of("value", "USER"))))))
                .andExpect(status().isOk());
        assertThat(users.findById(id).orElseThrow().getRole()).isEqualTo(Role.USER.name());

        mvc.perform(authenticated(put("/scim/v2/Users/" + id), asScim())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-ciso-lowered", "externalId", "attacker-subject"))))
                .andExpect(status().isBadRequest());
        assertThat(users.findById(id).orElseThrow().getKeycloakId()).isNull();

        // An administrator who sets the role has decided about the account; the directory binds it then.
        mvc.perform(authenticated(patch("/api/v1/users/" + id), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("role", "USER"))))
                .andExpect(status().isOk());
        mvc.perform(authenticated(put("/scim/v2/Users/" + id), asScim())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-ciso-lowered", "externalId", "directory-subject"))))
                .andExpect(status().isOk());
        assertThat(users.findById(id).orElseThrow().getKeycloakId()).isEqualTo("directory-subject");
    }

    @Test
    @DisplayName("an existing account with a local second factor is not bound to a subject by the directory")
    void aSecondFactorAccountIsNotBound() throws Exception {
        tokenFor("scim-totp-unbound", Role.USER, false);
        var account = users.findByUsername("scim-totp-unbound").orElseThrow();
        account.setMfaEnabled(true);
        users.save(account);

        mvc.perform(authenticated(put("/scim/v2/Users/" + account.getId()), asScim())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-totp-unbound", "externalId", "attacker-subject"))))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("turns the second factor off")));

        assertThat(users.findById(account.getId()).orElseThrow().getKeycloakId()).isNull();
    }

    /** Provisioned accounts sign in through the provider, with a password nobody holds. */
    @Test
    @DisplayName("an account the directory creates is not held on the change-password screen")
    void aProvisionedAccountNeedsNoPasswordChange() throws Exception {
        mvc.perform(authenticated(post("/scim/v2/Users"), asScim())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-provisioned", "externalId", "subject-provisioned"))))
                .andExpect(status().isCreated());

        assertThat(users.findByUsername("scim-provisioned").orElseThrow().getMustChangePassword()).isFalse();
    }

    /**
     * The same, from the directory's request to an ordinary route: the flag was only the first link.
     * A provisioned account signed in through the provider was answered 403 "change your password" on
     * every route, by a screen asking for a password nobody held — and the check above, on the row,
     * could not say whether anything else on the way still held it there.
     */
    @Test
    @DisplayName("a provisioned account's federated session reaches an ordinary route")
    void aProvisionedAccountsFederatedSessionIsServed() throws Exception {
        String name = "scim-federated-" + System.nanoTime();
        String subject = "subject-" + name;
        mvc.perform(authenticated(post("/scim/v2/Users"), asScim())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", name, "externalId", subject))))
                .andExpect(status().isCreated());

        var signedIn = flows.completeFederatedSignIn(new AuthenticationFlowService.FederatedIdentity(
                        subject, "https://idp.example.invalid/realms/vectispire",
                        new ExternalIdentityService.Claimed(name, null, false), List.of("otp"), null, List.of()),
                "browser", "198.51.100.7");
        assertThat(signedIn).isInstanceOf(AuthenticationFlowService.FederatedSignIn.SignedIn.class);
        String handoff = ((AuthenticationFlowService.FederatedSignIn.SignedIn) signedIn).issued().token();

        String body = mvc.perform(post("/api/v1/auth/session/exchange")
                        .cookie(new Cookie(OidcConfiguration.HANDOFF_COOKIE, handoff)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user.mustChangePassword").value(false))
                .andReturn().getResponse().getContentAsString();
        String session = json.readTree(body).get("token").asText();

        // The route `PasswordChangeGateTest` shows refused to an account that owes a change.
        mvc.perform(authenticated(get("/api/v1/issues"), session)).andExpect(status().isOk());
    }

    @Test
    @DisplayName("a role change from the directory closes the account's sessions")
    void aRoleChangeRevokes() throws Exception {
        String session = tokenFor("scim-promoted", Role.USER, false);
        long id = users.findByUsername("scim-promoted").orElseThrow().getId();

        mvc.perform(authenticated(put("/scim/v2/Users/" + id), asScim())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-promoted", "roles", List.of(Map.of("value", "SECURITY_CHAMPION"))))))
                .andExpect(status().isOk());

        assertThat(users.findById(id).orElseThrow().getRole()).isEqualTo(Role.SECURITY_CHAMPION.name());
        mvc.perform(authenticated(get("/api/v1/auth/me"), session))
                .andExpect(status().isUnauthorized());
    }

    // --- Filters (RFC 7644 §3.4.2.2) ----------------------------------------------------------
    //
    // A filter the endpoint did not evaluate fell back to every account: a directory looking an account up
    // by e-mail before creating one read the first account of the list as its match.

    @Test
    @DisplayName("an absent account and a taken userName answer SCIM's error schema, never an empty body")
    void absentAndTakenAreScimErrors() throws Exception {
        long absent = 9_000_000L;
        for (var request : List.of(
                get("/scim/v2/Users/" + absent),
                put("/scim/v2/Users/" + absent)
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-nobody"))),
                patch("/scim/v2/Users/" + absent)
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of(
                                "schemas", List.of("urn:ietf:params:scim:api:messages:2.0:PatchOp"),
                                "Operations", List.of(Map.of("op", "replace", "path", "active", "value", false))))))) {
            mvc.perform(authenticated(request, asScim()))
                    .andExpect(status().isNotFound())
                    .andExpect(jsonPath("$.schemas[0]").value("urn:ietf:params:scim:api:messages:2.0:Error"))
                    .andExpect(jsonPath("$.status").value("404"))
                    .andExpect(jsonPath("$.detail").value("User " + absent + " not found."));
        }

        tokenFor("scim-taken", Role.USER, false);
        mvc.perform(authenticated(post("/scim/v2/Users"), asScim())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-taken"))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.schemas[0]").value("urn:ietf:params:scim:api:messages:2.0:Error"))
                .andExpect(jsonPath("$.status").value("409"))
                // RFC 7644 §3.3: what a directory reads to link the existing account instead of failing.
                .andExpect(jsonPath("$.scimType").value("uniqueness"))
                .andExpect(jsonPath("$.detail").value("An account with this userName already exists."));
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {
        "displayName eq \"Filter Person\"",
        "userName eq \"scim-filtered\" and active eq true",
        "emails[value eq \"filtered@example.org\"]",
        "userName co \"scim\"",
        "userName eq scim-filtered",
        "userName eq \"scim-filtered\" or userName eq \"scim-other\"",
        "(userName eq \"scim-filtered\")",
    })
    @DisplayName("an unsupported filter is 400 invalidFilter in SCIM's error schema, never the whole list")
    void anUnsupportedFilterIsRefused(String filter) throws Exception {
        tokenFor("scim-filtered", Role.USER, false);

        mvc.perform(authenticated(get("/scim/v2/Users").param("filter", filter), asScim()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.schemas[0]").value("urn:ietf:params:scim:api:messages:2.0:Error"))
                .andExpect(jsonPath("$.status").value("400"))
                .andExpect(jsonPath("$.scimType").value("invalidFilter"))
                .andExpect(jsonPath("$.Resources").doesNotExist());
    }

    @Test
    @DisplayName("userName eq and externalId eq still find their account — any case of attribute and operator — and an absent one finds none")
    void theSupportedFiltersStillAnswer() throws Exception {
        tokenFor("scim-filtered", Role.USER, false);
        tokenFor("scim-other", Role.USER, false);
        mvc.perform(authenticated(post("/scim/v2/Users"), asScim())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "scim-bound-filter", "externalId", "subject \"quoted\""))))
                .andExpect(status().isCreated());

        for (String filter : List.of("userName eq \"scim-filtered\"", "USERNAME EQ \"Scim-Filtered\"")) {
            mvc.perform(authenticated(get("/scim/v2/Users").param("filter", filter), asScim()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.totalResults").value(1))
                    .andExpect(jsonPath("$.Resources[0].userName").value("scim-filtered"));
        }
        mvc.perform(authenticated(get("/scim/v2/Users").param("filter", "externalId eq \"subject \\\"quoted\\\"\""), asScim()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalResults").value(1))
                .andExpect(jsonPath("$.Resources[0].userName").value("scim-bound-filter"));
        mvc.perform(authenticated(get("/scim/v2/Users").param("filter", "userName eq \"nobody-here\""), asScim()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalResults").value(0));
    }

    @Test
    @DisplayName("no filter, or a blank one, lists every account as before")
    void noFilterListsEveryAccount() throws Exception {
        tokenFor("scim-filtered", Role.USER, false);
        tokenFor("scim-other", Role.USER, false);
        String admin = asScim();
        long accounts = users.count();

        mvc.perform(authenticated(get("/scim/v2/Users"), admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalResults").value(accounts));
        mvc.perform(authenticated(get("/scim/v2/Users").param("filter", "  "), admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalResults").value(accounts));
    }
}
