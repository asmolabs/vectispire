package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.AccountAdministrationService;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.outbox.persistence.OutboxMessageRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.siem.SiemEvents;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.test.web.servlet.MvcResult;

/**
 * Lifting another account's password-change requirement, {@code DELETE /api/v1/users/{id}/password-change-requirement}.
 *
 * <p>The accounts the directory created on 0.10.0 and {@code v0.11.0-rc.1} carry the flag, and every
 * federated session of theirs was held on a change-password screen asking for a password nobody had: the
 * 0.11.0 release notes could only offer an SQL statement. What the route must not become is the way to keep
 * a password somebody else chose valid on an account that signs in with it — which is the control the flag
 * is — so most of these cases are refusals.
 */
@DisplayName("lifting an account's password-change requirement")
class PasswordChangeRequirementRoutesTest extends ApiTestBase {

    private static final String PATH = "/api/v1/users/%d/password-change-requirement";

    @Autowired
    private UserRepository users;

    @Autowired
    private AuditLogRepository auditEntries;

    @Autowired
    private OutboxMessageRepository outbox;

    @Autowired
    private SettingsService settings;

    @Autowired
    private AccountAdministrationService administration;

    @Test
    @DisplayName("an administrator lifts it for a federated account, which is then served, and the entry names both")
    void anAdministratorLiftsItForAFederatedAccount() throws Exception {
        exportTo("127.0.0.1:9");
        String admin = tokenFor("lifting-admin", Role.ADMIN, false);
        String held = tokenFor("provisioned-held", Role.USER, true);
        UserEntity account = federate("provisioned-held");

        // Held on the change-password screen, as the provisioned accounts were.
        mvc.perform(authenticated(get("/api/v1/issues"), held)).andExpect(status().isForbidden());

        mvc.perform(authenticated(delete(PATH.formatted(account.getId())), admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(account.getId()))
                .andExpect(jsonPath("$.mustChangePassword").value(false))
                .andExpect(jsonPath("$.federated").value(true));

        assertThat(users.findById(account.getId()).orElseThrow().getMustChangePassword()).isFalse();
        // The session the flag held reaches an ordinary route now, without signing in again.
        mvc.perform(authenticated(get("/api/v1/issues"), held)).andExpect(status().isOk());

        assertThat(entriesFor(account)).singleElement().satisfies(entry -> {
            assertThat(entry.getOperationType()).isEqualTo(AuditOperation.USER_UPDATED.wireName());
            assertThat(entry.getUserId()).as("who lifted it").isEqualTo("lifting-admin");
            assertThat(entry.getDescription()).as("whose").contains("provisioned-held")
                    .contains("password-change requirement lifted");
        });
        // USER_UPDATED is an account change for the SOC, whoever writes it.
        assertThat(queuedSiemTypes()).containsExactly("ACCOUNT_CHANGED");
    }

    @Test
    @DisplayName("every role that does not administer accounts is refused 403, and the flag stays")
    void nonAdministratorsAreRefused() throws Exception {
        UserEntity account = flaggedFederated("refused-target");

        for (String token : List.of(asReader(), asAuditor(), asCiso(), asSecurityChampion())) {
            mvc.perform(authenticated(delete(PATH.formatted(account.getId())), token))
                    .andExpect(status().isForbidden());
        }

        assertThat(users.findById(account.getId()).orElseThrow().getMustChangePassword()).isTrue();
        assertThat(entriesFor(account)).isEmpty();
    }

    /**
     * The marker is not the only gate: the service reads the caller's role again, as it does for the
     * governor rule, so a route that lost its marker — or another caller of the method — still refuses.
     */
    @Test
    @DisplayName("the service refuses a caller whose role does not administer, whatever the route admitted")
    void theServiceReadsTheCallersRole() {
        UserEntity account = flaggedFederated("service-target");
        tokenFor("service-champion", Role.SECURITY_CHAMPION, false);
        long champion = users.findByUsername("service-champion").orElseThrow().getId();
        RequestActor actor = new RequestActor("service-champion", "192.0.2.1", "test");

        assertThatThrownBy(() -> administration.clearPasswordChangeRequirement(account.getId(), champion, actor))
                .isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> administration.clearPasswordChangeRequirement(account.getId(), null, actor))
                .as("a caller that is not an account")
                .isInstanceOf(AccessDeniedException.class);
        assertThat(users.findById(account.getId()).orElseThrow().getMustChangePassword()).isTrue();
    }

    /**
     * The control the flag is: a password an administrator typed, or the bootstrap one, stops being a
     * credential once its owner changes it. Lifted, it would stay valid for good.
     */
    @Test
    @DisplayName("an account that signs in with its own password is refused 400, and the flag stays")
    void anAccountSigningInWithItsPasswordIsRefused() throws Exception {
        tokenFor("local-held", Role.USER, true);
        UserEntity account = users.findByUsername("local-held").orElseThrow();

        MvcResult refused = mvc.perform(authenticated(delete(PATH.formatted(account.getId())), asAdmin()))
                .andExpect(status().isBadRequest())
                .andReturn();

        assertThat(detailOf(refused)).contains("signs in with its password").contains("changing it");
        assertThat(users.findById(account.getId()).orElseThrow().getMustChangePassword()).isTrue();
        assertThat(entriesFor(account)).isEmpty();
    }

    @Test
    @DisplayName("an administrator cannot lift their own, even when it is already clear")
    void notOnOnesOwnAccount() throws Exception {
        String admin = tokenFor("self-admin", Role.ADMIN, false);
        UserEntity me = users.findByUsername("self-admin").orElseThrow();
        me.setKeycloakId("subject-self-admin");
        users.save(me);

        MvcResult refused = mvc.perform(authenticated(delete(PATH.formatted(me.getId())), admin))
                .andExpect(status().isBadRequest())
                .andReturn();

        assertThat(detailOf(refused)).contains("your own password-change requirement");
        assertThat(entriesFor(me)).isEmpty();
    }

    @Test
    @DisplayName("an account that owes nothing is answered as it is, with no write and no entry")
    void anAccountOwingNothingIsLeftAlone() throws Exception {
        tokenFor("owes-nothing", Role.USER, false);
        UserEntity account = federate("owes-nothing");
        java.time.Instant before = users.findById(account.getId()).orElseThrow().getUpdatedAt();

        mvc.perform(authenticated(delete(PATH.formatted(account.getId())), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mustChangePassword").value(false));

        assertThat(users.findById(account.getId()).orElseThrow().getUpdatedAt())
                .as("nothing was written").isEqualTo(before);
        assertThat(entriesFor(account)).isEmpty();
    }

    @Test
    @DisplayName("a platform governor's is lifted by a governor only")
    void aGovernorsIsAGovernorsToLift() throws Exception {
        tokenFor("held-governor", Role.SUPERUSER, true);
        UserEntity governor = federate("held-governor");

        MvcResult refused = mvc.perform(authenticated(delete(PATH.formatted(governor.getId())), asAdmin()))
                .andExpect(status().isBadRequest())
                .andReturn();
        assertThat(detailOf(refused)).contains("Only a platform governor");
        assertThat(users.findById(governor.getId()).orElseThrow().getMustChangePassword()).isTrue();

        String otherGovernor = tokenFor("lifting-governor", Role.SUPERUSER, false);
        mvc.perform(authenticated(delete(PATH.formatted(governor.getId())), otherGovernor))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mustChangePassword").value(false));
    }

    @Test
    @DisplayName("an account that does not exist is a 404")
    void anUnknownAccountIsAbsent() throws Exception {
        MvcResult absent = mvc.perform(authenticated(delete(PATH.formatted(Long.MAX_VALUE)), asAdmin()))
                .andExpect(status().isNotFound())
                .andReturn();
        assertThat(detailOf(absent)).isEqualTo("Account not found.");
    }

    @Test
    @DisplayName("the account list says which accounts are federated")
    void theListSaysWhichAccountsAreFederated() throws Exception {
        flaggedFederated("listed-federated");
        tokenFor("listed-local", Role.USER, true);

        String body = mvc.perform(authenticated(get("/api/v1/users"), asAdmin()))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Map<String, Boolean> federated = new java.util.HashMap<>();
        json.readTree(body).get("users").forEach(user ->
                federated.put(user.get("username").asText(), user.get("federated").asBoolean()));
        assertThat(federated).containsEntry("listed-federated", true).containsEntry("listed-local", false);
    }

    private UserEntity flaggedFederated(String username) {
        tokenFor(username, Role.USER, true);
        return federate(username);
    }

    /** Bound to a provider subject, as the directory or a first single sign-on binds an account. */
    private UserEntity federate(String username) {
        UserEntity account = users.findByUsername(username).orElseThrow();
        account.setKeycloakId("subject-" + username);
        return users.save(account);
    }

    private List<AuditLogEntity> entriesFor(UserEntity account) {
        return auditEntries.findAll().stream()
                .filter(entry -> String.valueOf(account.getId()).equals(entry.getResourceId()))
                .filter(entry -> AuditOperation.USER_UPDATED.wireName().equals(entry.getOperationType()))
                .toList();
    }

    /** Turns the SIEM export on, then forgets what the save queued, so the test counts its own. */
    private void exportTo(String endpoint) throws Exception {
        settings.set(Setting.SIEM_ALLOW_PRIVATE_DESTINATION, "true");
        mvc.perform(authenticated(put("/api/v1/siem/config"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"enabled": true, "protocol": "SYSLOG_UDP", "endpoint": "%s", "minSeverity": "LOW"}"""
                                .formatted(endpoint)))
                .andExpect(status().isOk());
        outbox.deleteAll();
    }

    private List<String> queuedSiemTypes() {
        return outbox.findAll().stream()
                .filter(row -> SiemEvents.TYPE.equals(row.getMessageType()))
                .map(row -> {
                    try {
                        return json.readTree(row.getPayload()).get("eventType").asText();
                    } catch (Exception unreadable) {
                        throw new IllegalStateException(unreadable);
                    }
                })
                .toList();
    }
}
