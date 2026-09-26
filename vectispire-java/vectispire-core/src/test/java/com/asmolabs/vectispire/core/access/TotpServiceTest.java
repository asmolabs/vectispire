package com.asmolabs.vectispire.core.access;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.auth.Totp;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.Users;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The second factor against the database: what one code, or one backup code, may open.
 *
 * <p>Each check used to be a read, a comparison in Java and nothing recorded — so a code stayed
 * good for its whole window and a backup code could be spent by two sign-ins at once. Both are
 * now decided by an update, and the tests below hold two copies of the account where a race
 * would.
 */
@DisplayName("TOTP verification")
class TotpServiceTest extends VectispireContextTest {

    @Autowired
    private TotpService totp;

    @Autowired
    private Users users;

    @Autowired
    private Clock clock;

    private record Enrolled(UserEntity user, String secret, List<String> backupCodes) {}

    private Enrolled enrolled() {
        Instant now = clock.instant();
        UserEntity user = new UserEntity();
        user.setUsername("totp-" + System.nanoTime());
        user.setPassword(PasswordHasher.hash("correct horse battery staple"));
        user.setRole(Role.USER.name());
        user.setIsActive(true);
        user.setMustChangePassword(false);
        user.setCreatedAt(now);
        user.setUpdatedAt(now);
        user = users.save(user);

        String secret = totp.setup(UserView.of(user)).secret();
        List<String> codes = totp.enable(UserView.of(user), secret, Totp.generateCode(secret, now)).backupCodes();
        return new Enrolled(users.findById(user.getId()).orElseThrow(), secret, codes);
    }

    @Test
    @DisplayName("a code opens once: presented again inside its window, it is refused")
    void aCodeIsNotReplayed() {
        Enrolled account = enrolled();
        String next = Totp.generateCode(account.secret(), clock.instant().plusSeconds(30));

        assertThat(totp.verify(account.user(), next)).isTrue();
        assertThat(totp.verify(users.findById(account.user().getId()).orElseThrow(), next)).isFalse();
    }

    @Test
    @DisplayName("the code that proved the enrolment opens no sign-in afterwards")
    void theEnrolmentCodeIsSpent() {
        Enrolled account = enrolled();

        assertThat(totp.verify(account.user(), Totp.generateCode(account.secret(), clock.instant()))).isFalse();
    }

    @Test
    @DisplayName("a backup code spent through one copy of the account is refused through another")
    void aBackupCodeIsSpentOnce() {
        Enrolled account = enrolled();
        // Two sign-ins racing each hold the account as it was read: the same ciphertext, the
        // same code inside it.
        UserEntity first = users.findById(account.user().getId()).orElseThrow();
        UserEntity second = users.findById(account.user().getId()).orElseThrow();
        String code = account.backupCodes().getFirst();

        assertThat(totp.verify(first, code)).isTrue();
        assertThat(totp.verify(second, code)).isFalse();
        // And the others are still there: the refusal spent nothing.
        assertThat(totp.verify(users.findById(account.user().getId()).orElseThrow(), account.backupCodes().get(1)))
                .isTrue();
    }

    @Test
    @DisplayName("enrolling over an active factor is refused: replacing it goes through disabling it")
    void anActiveFactorIsNotOverwritten() {
        Enrolled account = enrolled();
        String attacker = totp.setup(UserView.of(account.user())).secret();

        assertThatThrownBy(() -> totp.enable(UserView.of(account.user()), attacker, Totp.generateCode(attacker, clock.instant())))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("already enabled");
        assertThat(totp.verify(account.user(), Totp.generateCode(account.secret(), clock.instant().plusSeconds(30))))
                .isTrue();
    }
}
