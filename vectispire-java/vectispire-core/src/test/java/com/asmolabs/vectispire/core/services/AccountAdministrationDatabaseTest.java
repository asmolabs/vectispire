package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.persistence.SessionEntity;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.repositories.AuditLog;
import com.asmolabs.vectispire.core.repositories.UserSessions;
import com.asmolabs.vectispire.core.repositories.Users;
import java.time.Clock;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The account administration rules as the service applies them, against the database.
 *
 * <p>{@code AccountRules} is tested on its own, with the facts handed to it. What had no test is
 * the part that gathers those facts — whether the change is to one's own account, how many
 * <em>other active</em> administrators remain — and the decision taken after the rules pass:
 * which changes close the account's sessions. Get the first wrong and the last administrator
 * locks everybody out; get the second wrong and a reset password leaves the stolen session open.
 */
@DisplayName("administering accounts")
class AccountAdministrationDatabaseTest extends VectispireContextTest {

    private static final RequestActor ACTOR = new RequestActor("root", "192.0.2.1", "test");

    @Autowired
    private AccountAdministrationService accounts;

    @Autowired
    private Users users;

    @Autowired
    private UserSessions sessions;

    @Autowired
    private AuditLog audit;

    @Autowired
    private Clock clock;

    @Test
    @DisplayName("an administrator cannot deactivate or demote their own account")
    void noSelfLockout() {
        UserEntity me = account("me", Role.ADMIN, true);
        account("colleague", Role.ADMIN, true);

        assertThatThrownBy(() -> accounts.update(me.getId(), change(null, false, null), me.getId(), ACTOR))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("deactivate your own account");
        assertThatThrownBy(() -> accounts.update(me.getId(), change("USER", null, null), me.getId(), ACTOR))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("your own administrator role");
        assertThat(users.findById(me.getId()).orElseThrow().getRole()).isEqualTo(Role.ADMIN.name());
    }

    @Test
    @DisplayName("the last active administrator cannot be demoted by someone else — a deactivated one does not count")
    void theLastActiveAdministratorStays() {
        UserEntity last = account("last", Role.ADMIN, true);
        account("dormant", Role.ADMIN, false);
        // The caller is not an account at all — an API key, say — so the self rules cannot be
        // what refuses: only the count can.
        assertThatThrownBy(() -> accounts.update(last.getId(), change("USER", null, null), null, ACTOR))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("last active administrator");
        assertThatThrownBy(() -> accounts.delete(last.getId(), null, ACTOR))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("last active administrator");
        assertThat(users.findById(last.getId())).isPresent();
    }

    @Test
    @DisplayName("with another active administrator, one may be demoted and deleted")
    void anotherAdministratorIsEnough() {
        UserEntity leaving = account("leaving", Role.ADMIN, true);
        account("staying", Role.ADMIN, true);

        accounts.update(leaving.getId(), change("user", null, null), null, ACTOR);
        assertThat(users.findById(leaving.getId()).orElseThrow().getRole()).isEqualTo(Role.USER.name());

        accounts.delete(leaving.getId(), null, ACTOR);
        assertThat(users.findById(leaving.getId())).isEmpty();
    }

    @Test
    @DisplayName("nobody deletes their own account, administrator or not")
    void noSelfDeletion() {
        UserEntity me = account("me", Role.USER, true);

        assertThatThrownBy(() -> accounts.delete(me.getId(), me.getId(), ACTOR))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("delete your own account");
    }

    @Test
    @DisplayName("a password reset, a role change and a deactivation each close the account's sessions")
    void theThreeGesturesRevoke() {
        account("root", Role.ADMIN, true);
        UserEntity reset = account("reset", Role.USER, true);
        UserEntity promoted = account("promoted", Role.USER, true);
        UserEntity disabled = account("disabled", Role.USER, true);
        SessionEntity a = openSession(reset);
        SessionEntity b = openSession(promoted);
        SessionEntity c = openSession(disabled);

        var view = accounts.update(reset.getId(), change(null, null, "a-new-password-of-length"), null, ACTOR);
        accounts.update(promoted.getId(), change("AUDITOR", null, null), null, ACTOR);
        accounts.update(disabled.getId(), change(null, false, null), null, ACTOR);

        assertThat(sessions.findById(a.getTokenHash())).isEmpty();
        assertThat(sessions.findById(b.getTokenHash())).isEmpty();
        assertThat(sessions.findById(c.getTokenHash())).isEmpty();
        assertThat(view.activeSessions()).isZero();

        UserEntity afterReset = users.findById(reset.getId()).orElseThrow();
        assertThat(PasswordHasher.verify("a-new-password-of-length", afterReset.getPassword())).isTrue();
        // The administrator typed it, so it is a pass rather than the account's secret.
        assertThat(afterReset.getMustChangePassword()).isTrue();
    }

    @Test
    @DisplayName("a change that alters nothing leaves the sessions open and writes no audit entry")
    void aNoOpChangeKeepsTheSessions() {
        UserEntity user = account("steady", Role.USER, true);
        SessionEntity open = openSession(user);

        var view = accounts.update(user.getId(), change("user", true, null), null, ACTOR);

        assertThat(sessions.findById(open.getTokenHash())).isPresent();
        assertThat(view.activeSessions()).isEqualTo(1);
        assertThat(audit.findAllByOrderByTimestampAscIdAsc()).isEmpty();
    }

    @Test
    @DisplayName("each change is audited in one entry naming what changed and who did it")
    void changesAreAudited() {
        account("root", Role.ADMIN, true);
        UserEntity user = account("audited", Role.USER, true);

        accounts.update(user.getId(), change("AUDITOR", false, null), null, ACTOR);

        assertThat(audit.findAllByOrderByTimestampAscIdAsc())
                .singleElement()
                .satisfies(entry -> {
                    assertThat(entry.getResourceId()).isEqualTo(String.valueOf(user.getId()));
                    assertThat(entry.getDescription()).contains("USER → AUDITOR").contains("deactivated");
                    assertThat(entry.getUserId()).isEqualTo("root");
                    assertThat(entry.getIpAddress()).isEqualTo("192.0.2.1");
                });
    }

    @Test
    @DisplayName("creating an account refuses an unknown role and a taken username, and marks the password as a pass")
    void creation() {
        account("taken", Role.USER, true);

        assertThatThrownBy(() -> accounts.create(newAccount("fresh", "OVERLORD"), null, ACTOR))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unknown role");
        assertThatThrownBy(() -> accounts.create(newAccount(" taken ", null), null, ACTOR))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("already taken");

        UserEntity created = accounts.create(newAccount("fresh", null), null, ACTOR).user();
        assertThat(created.getRole()).isEqualTo(Role.USER.name());
        assertThat(created.getMustChangePassword()).isTrue();
        assertThat(audit.findAllByOrderByTimestampAscIdAsc())
                .extracting(AuditLogEntity::getDescription)
                .containsExactly("Account created: fresh (USER)");
    }

    @Test
    @DisplayName("an administrator cannot make itself platform governor, nor create one")
    void anAdministratorCannotBecomeGovernor() {
        // Become governor, lift four-eyes, come back and settle issues alone: one request each.
        UserEntity admin = account("admin", Role.ADMIN, true);
        account("other-admin", Role.ADMIN, true);

        assertThatThrownBy(() -> accounts.update(admin.getId(), change("SUPERUSER", null, null), admin.getId(), ACTOR))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Only a platform governor");
        assertThatThrownBy(() -> accounts.create(newAccount("shadow", "SUPERUSER"), admin.getId(), ACTOR))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Only a platform governor");
        assertThat(users.findById(admin.getId()).orElseThrow().getRole()).isEqualTo(Role.ADMIN.name());
        assertThat(users.findByUsername("shadow")).isEmpty();
    }

    @Test
    @DisplayName("an administrator cannot reset, deactivate or delete a governor's account")
    void anAdministratorCannotAdministerAGovernor() {
        UserEntity admin = account("admin", Role.ADMIN, true);
        UserEntity governor = account("governor", Role.SUPERUSER, true);
        String before = governor.getPassword();

        assertThatThrownBy(() -> accounts.update(governor.getId(), change(null, null, "a-password-long-enough"), admin.getId(), ACTOR))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> accounts.update(governor.getId(), change(null, false, null), admin.getId(), ACTOR))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> accounts.delete(governor.getId(), admin.getId(), ACTOR))
                .isInstanceOf(IllegalArgumentException.class);

        UserEntity after = users.findById(governor.getId()).orElseThrow();
        assertThat(after.getPassword()).isEqualTo(before);
        assertThat(after.getIsActive()).isTrue();
    }

    @Test
    @DisplayName("a governor can grant the role to someone else, and nobody changes their own")
    void aGovernorGrantsItButNotToItself() {
        UserEntity governor = account("governor", Role.SUPERUSER, true);
        UserEntity admin = account("admin", Role.ADMIN, true);
        account("other-admin", Role.ADMIN, true);

        accounts.update(admin.getId(), change("SUPERUSER", null, null), governor.getId(), ACTOR);
        assertThat(users.findById(admin.getId()).orElseThrow().getRole()).isEqualTo(Role.SUPERUSER.name());

        UserEntity champion = account("champion", Role.SECURITY_CHAMPION, true);
        assertThatThrownBy(() -> accounts.update(champion.getId(), change("CISO", null, null), champion.getId(), ACTOR))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("your own role");
    }

    private static AccountAdministrationService.AccountChange change(String role, Boolean isActive, String password) {
        return new AccountAdministrationService.AccountChange(role, isActive, password);
    }

    private static AccountAdministrationService.NewAccount newAccount(String username, String role) {
        return new AccountAdministrationService.NewAccount(username, "an-initial-password-long", role, null, null);
    }

    private UserEntity account(String username, Role role, boolean active) {
        UserEntity user = new UserEntity();
        user.setUsername(username);
        user.setPassword(PasswordHasher.hash("irrelevant-password"));
        user.setRole(role.name());
        user.setIsActive(active);
        user.setMustChangePassword(false);
        user.setCreatedAt(clock.instant());
        user.setUpdatedAt(clock.instant());
        return users.save(user);
    }

    private SessionEntity openSession(UserEntity user) {
        SessionEntity session = new SessionEntity();
        session.setTokenHash("hash-" + user.getUsername());
        session.setUserId(user.getId());
        session.setCreatedAt(clock.instant());
        session.setLastSeenAt(clock.instant());
        session.setExpiresAt(clock.instant().plusSeconds(3600));
        return sessions.save(session);
    }
}
