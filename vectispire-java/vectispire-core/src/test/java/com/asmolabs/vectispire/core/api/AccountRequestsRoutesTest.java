package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.AccountRequestRepository;
import com.asmolabs.vectispire.core.access.persistence.SessionRepository;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;

/**
 * Under four-eyes, an account change that makes an approver waits for a second administrator (#126,
 * option 2).
 *
 * <p>Before it, one administrator could create an account with a role that approves, or reset the password
 * of one that holds it, sign in with the password just typed and act under that name. Each case below is
 * one of the three gestures held back, one of the refusals an approval meets, or one of the gestures left
 * alone on purpose — four-eyes off, a role that approves nothing, an installation with nobody else to ask.
 */
@DisplayName("account changes waiting for a second administrator")
class AccountRequestsRoutesTest extends ApiTestBase {

    private static final String PASSWORD = "a-temporary-password-of-length";

    @Autowired
    private UserRepository users;

    @Autowired
    private SessionRepository sessions;

    @Autowired
    private AccountRequestRepository requests;

    @Autowired
    private AuditLogRepository audit;

    @Autowired
    private SettingsService settings;

    private String alice;
    private String bob;

    @BeforeEach
    void twoAdministrators() {
        settings.set(Setting.FOUR_EYES_APPROVAL_REQUIRED, "true");
        alice = tokenFor("alice", Role.ADMIN, false);
        bob = tokenFor("bob", Role.ADMIN, false);
    }

    @Test
    @DisplayName("creating an administrator is filed, listed, and applied once another administrator approves")
    void creationWaitsForASecondAdministrator() throws Exception {
        long id = filedId(create(alice, "carol", Role.ADMIN)
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.kind").value("create"))
                .andExpect(jsonPath("$.username").value("carol"))
                .andExpect(jsonPath("$.requestedRole").value("ADMIN"))
                .andExpect(jsonPath("$.passwordReset").value(true))
                .andExpect(jsonPath("$.requestedBy").value("alice"))
                .andExpect(jsonPath("$.passwordHash").doesNotExist()));
        assertThat(users.findByUsername("carol")).isEmpty();

        mvc.perform(authenticated(get("/api/v1/account-requests"), bob))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(1))
                .andExpect(jsonPath("$.requests[0].id").value(id));

        approve(id, bob)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("carol"))
                .andExpect(jsonPath("$.role").value("ADMIN"))
                .andExpect(jsonPath("$.mustChangePassword").value(true));

        UserEntity carol = users.findByUsername("carol").orElseThrow();
        assertThat(PasswordHasher.verify(PASSWORD, carol.getPassword())).isTrue();
        assertThat(requests.findById(id).orElseThrow().getPasswordHash())
                .as("an applied request keeps no copy of the password").isNull();
        mvc.perform(authenticated(get("/api/v1/account-requests"), bob))
                .andExpect(jsonPath("$.total").value(0));
        assertThat(operations()).contains(
                AuditOperation.ACCOUNT_REQUEST_FILED.name(), AuditOperation.ACCOUNT_REQUEST_APPROVED.name());
        assertThat(audit.findAllByOrderByTimestampAscIdAsc())
                .filteredOn(entry -> entry.getOperationType().equals(AuditOperation.USER_UPDATED.name()))
                .singleElement()
                .satisfies(entry -> {
                    assertThat(entry.getDescription()).contains("Account created: carol (ADMIN)")
                            .contains("requested by alice and approved by bob");
                    assertThat(entry.getUserId()).isEqualTo("bob");
                });
    }

    @Test
    @DisplayName("the requester cannot approve their own request")
    void notByItsRequester() throws Exception {
        long id = filedId(create(alice, "dave", Role.CISO).andExpect(status().isAccepted()));

        approve(id, alice)
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("own-account-request"))
                .andExpect(jsonPath("$.type").value("urn:vectispire:problem:own-account-request"));
        assertThat(users.findByUsername("dave")).isEmpty();
        assertThat(requests.findById(id).orElseThrow().getStatus()).isEqualTo("pending");
    }

    @Test
    @DisplayName("raising a role to one that approves is filed, and the role does not move until approved")
    void aRaisedRoleWaits() throws Exception {
        long account = existing("erin", Role.USER);

        long id = filedId(change(alice, account, Map.of("role", Role.SECURITY_CHAMPION.name()))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.kind").value("change"))
                .andExpect(jsonPath("$.heldRole").value("USER"))
                .andExpect(jsonPath("$.requestedRole").value("SECURITY_CHAMPION"))
                .andExpect(jsonPath("$.passwordReset").value(false)));
        assertThat(users.findById(account).orElseThrow().getRole()).isEqualTo(Role.USER.name());

        approve(id, bob).andExpect(status().isOk()).andExpect(jsonPath("$.role").value("SECURITY_CHAMPION"));
        assertThat(users.findById(account).orElseThrow().getRole()).isEqualTo(Role.SECURITY_CHAMPION.name());
    }

    @Test
    @DisplayName("resetting the password of an account that approves is filed, and applied with its sessions closed")
    void aResetOfAnApproverWaits() throws Exception {
        String ciso = tokenFor("frank", Role.CISO, false);
        UserEntity frank = users.findByUsername("frank").orElseThrow();
        String before = frank.getPassword();

        long id = filedId(change(alice, frank.getId(), Map.of("password", PASSWORD))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.passwordReset").value(true)));
        assertThat(users.findById(frank.getId()).orElseThrow().getPassword()).isEqualTo(before);
        assertThat(sessions.findAll()).anyMatch(session -> session.getUserId().equals(frank.getId()));

        approve(id, bob).andExpect(status().isOk());
        UserEntity after = users.findById(frank.getId()).orElseThrow();
        assertThat(PasswordHasher.verify(PASSWORD, after.getPassword())).isTrue();
        assertThat(after.getMustChangePassword()).isTrue();
        mvc.perform(authenticated(get("/api/v1/auth/me"), ciso)).andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("a rejection applies nothing, and a decided request cannot be decided again")
    void aRejectionAppliesNothing() throws Exception {
        long id = filedId(create(alice, "grace", Role.ADMIN).andExpect(status().isAccepted()));

        mvc.perform(authenticated(post("/api/v1/account-requests/" + id + "/reject"), bob))
                .andExpect(status().isNoContent());
        assertThat(users.findByUsername("grace")).isEmpty();
        assertThat(operations()).contains(AuditOperation.ACCOUNT_REQUEST_REJECTED.name());

        approve(id, bob).andExpect(status().isConflict());
        mvc.perform(authenticated(post("/api/v1/account-requests/" + id + "/reject"), bob))
                .andExpect(status().isConflict());
        approve(999_999, bob).andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("is refused to an approver the requester created recently, and admitted from somebody else")
    void notByAnApproverTheRequesterMade() throws Exception {
        // Bob made alone, before anybody else could approve: the bootstrap case, applied at once.
        remove(bob, "alice");
        create(bob, "heidi", Role.ADMIN).andExpect(status().isOk());
        UserEntity made = users.findByUsername("heidi").orElseThrow();
        made.setMustChangePassword(false);
        users.save(made);
        String heidi = sessionFor(made.getId());

        long id = filedId(create(bob, "ivan", Role.CISO).andExpect(status().isAccepted()));
        approve(id, heidi)
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("approver-not-independent"))
                .andExpect(jsonPath("$.gesture").value("created"));
        assertThat(users.findByUsername("ivan")).isEmpty();

        approve(id, tokenFor("judy", Role.ADMIN, false)).andExpect(status().isOk());
        assertThat(users.findByUsername("ivan")).isPresent();
    }

    @Test
    @DisplayName("an administrator alone applies it at once, and the audit entry says no second one was there")
    void aLoneAdministratorIsNotLockedOut() throws Exception {
        remove(alice, "bob");

        create(alice, "kim", Role.ADMIN).andExpect(status().isOk()).andExpect(jsonPath("$.role").value("ADMIN"));
        assertThat(audit.findAllByOrderByTimestampAscIdAsc())
                .extracting(AuditLogEntity::getDescription)
                .anySatisfy(description -> assertThat(description).contains("Account created: kim")
                        .contains("without a second administrator"));
    }

    @Test
    @DisplayName("a deactivated administrator still counts: deactivating the others does not make one alone")
    void deactivatingTheOthersIsNotBeingAlone() throws Exception {
        change(alice, users.findByUsername("bob").orElseThrow().getId(), Map.of("is_active", "false"))
                .andExpect(status().isOk());

        create(alice, "kurt", Role.CISO).andExpect(status().isAccepted());
        assertThat(users.findByUsername("kurt")).isEmpty();
    }

    @Test
    @DisplayName("lowering the other administrators does not make one alone either")
    void loweringTheOthersIsNotBeingAlone() throws Exception {
        change(alice, users.findByUsername("bob").orElseThrow().getId(), Map.of("role", Role.AUDITOR.name()))
                .andExpect(status().isOk());

        create(alice, "lowered-witness", Role.CISO).andExpect(status().isAccepted());
        assertThat(users.findByUsername("lowered-witness")).isEmpty();
    }

    @Test
    @DisplayName("a reset waits while a change to the same account is pending")
    void noResetBesideAPendingRaise() throws Exception {
        long account = existing("pending-raise", Role.USER);
        change(alice, account, Map.of("role", Role.CISO.name())).andExpect(status().isAccepted());
        String before = users.findById(account).orElseThrow().getPassword();

        change(bob, account, Map.of("password", PASSWORD)).andExpect(status().isConflict());
        assertThat(users.findById(account).orElseThrow().getPassword()).isEqualTo(before);
    }

    @Test
    @DisplayName("lower, reset, raise: a raise is refused to the administrator who set the account's password")
    void lowerResetRaiseIsRefused() throws Exception {
        long carol = existing("carol-ciso", Role.CISO);
        change(alice, carol, Map.of("role", Role.USER.name())).andExpect(status().isOk());
        change(alice, carol, Map.of("password", PASSWORD)).andExpect(status().isOk());

        change(alice, carol, Map.of("role", Role.CISO.name()))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("password-known-to-administrator"))
                .andExpect(jsonPath("$.gesture").value("password_reset"));
        assertThat(requests.findAll()).isEmpty();
        assertThat(users.findById(carol).orElseThrow().getRole()).isEqualTo(Role.USER.name());
    }

    @Test
    @DisplayName("and to an approver who set it: somebody else approves the raise")
    void aRaiseIsNotApprovedByWhoeverSetThePassword() throws Exception {
        long sock = existing("sock", Role.USER);
        change(bob, sock, Map.of("password", PASSWORD)).andExpect(status().isOk());
        long id = filedId(change(alice, sock, Map.of("role", Role.SECURITY_CHAMPION.name()))
                .andExpect(status().isAccepted()));

        approve(id, bob)
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("password-known-to-administrator"));
        assertThat(users.findById(sock).orElseThrow().getRole()).isEqualTo(Role.USER.name());

        approve(id, tokenFor("victor", Role.ADMIN, false)).andExpect(status().isOk());
        assertThat(users.findById(sock).orElseThrow().getRole()).isEqualTo(Role.SECURITY_CHAMPION.name());
    }

    @Test
    @DisplayName("is refused to an approver who administered the requester: an administrator it made is not a second person")
    void notByTheMakerOfTheRequester() throws Exception {
        long id = filedId(create(alice, "zed", Role.ADMIN).andExpect(status().isAccepted()));
        approve(id, bob).andExpect(status().isOk());
        UserEntity zed = users.findByUsername("zed").orElseThrow();
        zed.setMustChangePassword(false);
        users.save(zed);

        long next = filedId(create(sessionFor(zed.getId()), "yves", Role.CISO).andExpect(status().isAccepted()));
        approve(next, alice)
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("approver-not-independent"))
                .andExpect(jsonPath("$.gesture").value("created"));
        assertThat(users.findByUsername("yves")).isEmpty();
    }

    @Test
    @DisplayName("is refused once its requester is no longer an active administrator")
    void notOnceTheRequesterIsGone() throws Exception {
        long id = filedId(create(alice, "wendy", Role.ADMIN).andExpect(status().isAccepted()));
        change(bob, users.findByUsername("alice").orElseThrow().getId(), Map.of("is_active", "false"))
                .andExpect(status().isOk());

        approve(id, bob).andExpect(status().isConflict());
        assertThat(users.findByUsername("wendy")).isEmpty();
    }

    @Test
    @DisplayName("nobody approves a change to their own account")
    void notAChangeToOnesOwnAccount() throws Exception {
        long bobId = users.findByUsername("bob").orElseThrow().getId();
        long id = filedId(change(alice, bobId, Map.of("password", PASSWORD)).andExpect(status().isAccepted()));

        approve(id, bob).andExpect(status().isBadRequest());
        assertThat(requests.findById(id).orElseThrow().getStatus()).isEqualTo("pending");
    }

    @Test
    @DisplayName("is checked again as the approver: an administrator cannot approve the creation of a governor")
    void theApproverIsHeldToTheRules() throws Exception {
        String governor = tokenFor("governor", Role.SUPERUSER, false);
        long id = filedId(create(governor, "second-governor", Role.SUPERUSER).andExpect(status().isAccepted()));

        approve(id, bob).andExpect(status().isBadRequest());
        assertThat(users.findByUsername("second-governor")).isEmpty();
    }

    @Test
    @DisplayName("a request whose account changed since it was filed is stale")
    void aStaleRequestIsRefused() throws Exception {
        long account = existing("lena", Role.USER);
        long id = filedId(change(alice, account, Map.of("role", Role.CISO.name())).andExpect(status().isAccepted()));
        change(bob, account, Map.of("role", Role.AUDITOR.name())).andExpect(status().isOk());

        approve(id, bob).andExpect(status().isConflict());
        assertThat(users.findById(account).orElseThrow().getRole()).isEqualTo(Role.AUDITOR.name());
    }

    @Test
    @DisplayName("a second request for the same account waits for the first to be decided")
    void oneRequestPerAccount() throws Exception {
        long account = existing("mallory", Role.USER);
        change(alice, account, Map.of("role", Role.CISO.name())).andExpect(status().isAccepted());
        change(bob, account, Map.of("role", Role.ADMIN.name())).andExpect(status().isConflict());
        create(alice, "nina", Role.CISO).andExpect(status().isAccepted());
        create(bob, "nina", Role.ADMIN).andExpect(status().isConflict());
    }

    @Test
    @DisplayName("a deactivation sent with a filed change is applied at once")
    void deactivationIsNeverHeldBack() throws Exception {
        long account = existing("oscar", Role.USER);
        change(alice, account, Map.of("role", "CISO", "is_active", "false")).andExpect(status().isAccepted());

        UserEntity oscar = users.findById(account).orElseThrow();
        assertThat(oscar.getIsActive()).isFalse();
        assertThat(oscar.getRole()).isEqualTo(Role.USER.name());
    }

    @Test
    @DisplayName("nothing waits for a role that approves nothing, nor for a reset of an account that approves nothing")
    void onlyApproversWait() throws Exception {
        create(alice, "peggy", Role.AUDITOR).andExpect(status().isOk());
        long account = existing("quentin", Role.USER);
        change(alice, account, Map.of("password", PASSWORD)).andExpect(status().isOk());
        change(alice, account, Map.of("role", Role.AUDITOR.name())).andExpect(status().isOk());
        assertThat(requests.findAll()).isEmpty();
    }

    @Test
    @DisplayName("with four-eyes off, nothing changes: every gesture applies at once")
    void nothingChangesWithFourEyesOff() throws Exception {
        settings.set(Setting.FOUR_EYES_APPROVAL_REQUIRED, "false");
        long account = existing("rupert", Role.USER);

        create(alice, "sybil", Role.ADMIN).andExpect(status().isOk());
        change(alice, account, Map.of("role", Role.CISO.name())).andExpect(status().isOk());
        change(alice, account, Map.of("password", PASSWORD)).andExpect(status().isOk());
        assertThat(requests.findAll()).isEmpty();
        assertThat(users.findById(account).orElseThrow().getRole()).isEqualTo(Role.CISO.name());
    }

    @Test
    @DisplayName("the routes are an administrator's")
    void administratorsOnly() throws Exception {
        long id = filedId(create(alice, "trent", Role.ADMIN).andExpect(status().isAccepted()));
        String ciso = asCiso();

        mvc.perform(authenticated(get("/api/v1/account-requests"), ciso)).andExpect(status().isForbidden());
        approve(id, ciso).andExpect(status().isForbidden());
        mvc.perform(authenticated(post("/api/v1/account-requests/" + id + "/reject"), ciso))
                .andExpect(status().isForbidden());
    }

    private ResultActions create(String token, String username, Role role) throws Exception {
        return mvc.perform(authenticated(post("/api/v1/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(write(Map.of("username", username, "password", PASSWORD, "role", role.name()))), token));
    }

    private ResultActions change(String token, long account, Map<String, String> change) throws Exception {
        Map<String, Object> body = new java.util.HashMap<>(change);
        if (change.containsKey("is_active")) {
            body.put("is_active", Boolean.parseBoolean(change.get("is_active")));
        }
        return mvc.perform(authenticated(patch("/api/v1/users/" + account)
                .contentType(MediaType.APPLICATION_JSON)
                .content(write(body)), token));
    }

    private ResultActions approve(long id, String token) throws Exception {
        return mvc.perform(authenticated(post("/api/v1/account-requests/" + id + "/approve"), token));
    }

    private long filedId(ResultActions filed) throws Exception {
        return json.readTree(filed.andReturn().getResponse().getContentAsString()).get("id").asLong();
    }

    private long existing(String username, Role role) {
        tokenFor(username, role, false);
        return users.findByUsername(username).orElseThrow().getId();
    }

    private void remove(String token, String username) throws Exception {
        mvc.perform(authenticated(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .delete("/api/v1/users/" + users.findByUsername(username).orElseThrow().getId()), token))
                .andExpect(status().isNoContent());
    }

    private List<String> operations() {
        return audit.findAllByOrderByTimestampAscIdAsc().stream().map(AuditLogEntity::getOperationType).toList();
    }
}
