package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;

import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.SessionEntity;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.UserSessions;
import com.asmolabs.vectispire.core.access.persistence.Users;
import java.time.Clock;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

/**
 * Resetting a password and closing the sessions are one gesture or neither.
 *
 * <p><b>Why this exists.</b> {@code UsersController} explains at length that a password reset
 * must close the account's sessions, because the administrator doing it has just been told a
 * token was stolen. The explanation was true and the boundary was not: the save and the
 * revocation were separate repository calls, each with its own transaction, so a failure between
 * them left the password changed, the screen confirming, and the stolen session alive for the
 * rest of its lifetime.
 *
 * <p>Nothing could notice. Every existing assertion checks the happy path, where two
 * transactions and one look identical. So the test has to <em>make</em> the second write fail —
 * which is what the spy below is for — and then ask the only question that separates the two
 * designs: did the first one survive?
 *
 * <p>The failure injected is a query timeout rather than a contrived exception: a lock held a
 * moment too long on {@code t_session} is the realistic way this happens in production, and it
 * is not one anybody would call an outage.
 */
@DisplayName("a failed session revocation")
class AccountRevocationAtomicityTest extends ApiTestBase {

    private static final String OLD_PASSWORD = "old-password-that-must-survive";
    private static final String NEW_PASSWORD = "new-password-nobody-should-get";

    @MockitoSpyBean
    private UserSessions sessions;

    @Autowired
    private Users users;

    @Autowired
    private Clock clock;

    @Test
    @DisplayName("rolls the password reset back with it")
    void rolls_the_password_reset_back_with_it() throws Exception {
        UserEntity target = anAccount();
        String admin = asAdmin();

        // Only this account's revocation fails. The harness mints its own sessions through the
        // same bean, and a blanket stub would take the administrator's token down with it.
        doThrow(new QueryTimeoutException("lock wait timeout on t_session"))
                .when(sessions)
                .deleteByUserId(eq(target.getId()));

        assertThatThrownBy(() -> mvc.perform(authenticated(
                        patch("/api/v1/users/" + target.getId())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"password\":\"" + NEW_PASSWORD + "\"}"),
                        admin)))
                .rootCause()
                .isInstanceOf(QueryTimeoutException.class);

        UserEntity after = users.findById(target.getId()).orElseThrow();

        // The point of the whole test. With two transactions this line fails: the new password
        // is stored, and the session the reset existed to close is still open.
        assertThat(PasswordHasher.verify(NEW_PASSWORD, after.getPassword()))
                .as("the new password must not be stored when the sessions could not be closed")
                .isFalse();
        assertThat(PasswordHasher.verify(OLD_PASSWORD, after.getPassword()))
                .as("the account is left exactly as it was")
                .isTrue();
        assertThat(after.getMustChangePassword())
                .as("the flag the reset sets must roll back too")
                .isFalse();
    }

    @Test
    @DisplayName("does not happen on the ordinary path")
    void does_not_happen_on_the_ordinary_path() throws Exception {
        UserEntity target = anAccount();
        SessionEntity open = anOpenSessionFor(target);
        String admin = asAdmin();

        mvc.perform(authenticated(
                        patch("/api/v1/users/" + target.getId())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"password\":\"" + NEW_PASSWORD + "\"}"),
                        admin))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk());

        UserEntity after = users.findById(target.getId()).orElseThrow();
        assertThat(PasswordHasher.verify(NEW_PASSWORD, after.getPassword())).isTrue();
        assertThat(sessions.findById(open.getTokenHash()))
                .as("the reset closes the sessions it was meant to close")
                .isEmpty();
    }

    private UserEntity anAccount() {
        UserEntity user = new UserEntity();
        user.setUsername("target-" + System.nanoTime());
        user.setPassword(PasswordHasher.hash(OLD_PASSWORD));
        user.setRole(Role.USER.name());
        user.setIsActive(true);
        user.setMustChangePassword(false);
        user.setCreatedAt(clock.instant());
        user.setUpdatedAt(clock.instant());
        return users.save(user);
    }

    private SessionEntity anOpenSessionFor(UserEntity user) {
        SessionEntity session = new SessionEntity();
        session.setTokenHash("hash-" + System.nanoTime());
        session.setUserId(user.getId());
        session.setCreatedAt(clock.instant());
        session.setLastSeenAt(clock.instant());
        session.setExpiresAt(clock.instant().plusSeconds(3600));
        return sessions.save(session);
    }
}
